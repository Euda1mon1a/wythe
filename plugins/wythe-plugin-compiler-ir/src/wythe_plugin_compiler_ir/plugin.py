"""Wythe Zoom-2 Compiler IR (`USR` / `SIL` / `LLVM IR`) & Metal `AIR` plugin (`#77`)."""

from __future__ import annotations

from collections.abc import Iterator, Sequence
from contextlib import contextmanager
from contextvars import ContextVar
from pathlib import Path
from typing import Any, Literal

from app.adapters import plugin_registry
from app.adapters.base import ManipulatorExtractionResult, RawCandidateFinding
from app.adapters.plugin_registry import PluginRuleSpec, WythePluginSpec
from app.schemas.atlas import (
    AtlasEdge,
    AtlasNode,
    StratumExpansionResult,
    StratumMicroEdge,
    StratumMicroNode,
    StratumSummaryBadge,
    TruthAtlasReport,
    VerificationState,
)
from wythe_plugin_compiler_ir.ir_parsers import (
    CompilerIrBundle,
    IrFunctionNode,
    parse_llvm_ir_file,
    parse_sil_file,
)
from wythe_plugin_compiler_ir.metal_air import (
    METAL_AIR_EPISTEMIC_NOTE,
    MetalSeamAnalysis,
    verify_metal_compute_seams,
)
from wythe_plugin_compiler_ir.usr_index import (
    UsrSymbolRecord,
    parse_usr_index,
)

PLUGIN_VERSION = "0.1.0"

COMPILER_IR_RULES: tuple[PluginRuleSpec, ...] = (
    PluginRuleSpec(
        rule_code="METAL-001",
        tier="manipulate",
        title="Static host Metal compute kernel name is absent from target .metal sources and .metallib AIR exports",
        severity="blocking",
        blocks_gate=True,
        enabled=True,
        confidence="confirmed",
        evidence_strength="ast_exact",
    ),
    PluginRuleSpec(
        rule_code="METAL-002",
        tier="manipulate",
        title="Host Metal setBuffer/setBytes indices omit a declared kernel [[buffer(N)]] binding or collide on duplicate indices",
        severity="blocking",
        blocks_gate=True,
        enabled=True,
        confidence="confirmed",
        evidence_strength="ast_exact",
    ),
    PluginRuleSpec(
        rule_code="METAL-003",
        tier="manipulate",
        title="Statically shared host vs .metal struct layout disagrees on size, stride, alignment, or field offsets",
        severity="blocking",
        blocks_gate=True,
        enabled=True,
        confidence="confirmed",
        evidence_strength="ast_exact",
    ),
)

_LOCAL_ARTIFACTS_VAR: ContextVar[dict[str, tuple[str, ...]] | None] = ContextVar(
    "wythe_compiler_ir_artifacts",
    default=None,
)


def _norm_paths(val: str | Path | Sequence[str | Path] | None) -> tuple[str, ...]:
    if val is None:
        return ()
    if isinstance(val, (str, Path)):
        s = str(val).strip()
        return (s,) if s else ()
    out: list[str] = []
    for item in val:
        s = str(item).strip()
        if s and s not in out:
            out.append(s)
    return tuple(out)


@contextmanager
def compiler_ir_artifacts_scope(
    *,
    index_store: str | Path | Sequence[str | Path] | None = None,
    sil: str | Path | Sequence[str | Path] | None = None,
    llvm_ir: str | Path | Sequence[str | Path] | None = None,
    metallib: str | Path | Sequence[str | Path] | None = None,
) -> Iterator[None]:
    """Bind read-only compiler IR / metallib artifact paths for the active execution scope."""
    scoped: dict[str, tuple[str, ...]] = {}
    for key, raw_val in (
        ("index_store", index_store),
        ("sil", sil),
        ("llvm_ir", llvm_ir),
        ("metallib", metallib),
    ):
        norm = _norm_paths(raw_val)
        if norm:
            scoped[key] = norm

    prev = dict(_LOCAL_ARTIFACTS_VAR.get() or {})
    merged = {**prev, **scoped}
    tok = _LOCAL_ARTIFACTS_VAR.set(merged)
    core_scope = getattr(plugin_registry, "stratum_artifacts_scope", None)
    try:
        if callable(core_scope):
            with core_scope(**scoped):
                yield
        else:
            yield
    finally:
        _LOCAL_ARTIFACTS_VAR.reset(tok)


def _resolve_active_artifacts(
    explicit: dict[str, tuple[str, ...]],
    overrides: dict[str, str | Path | Sequence[str | Path] | None],
) -> dict[str, tuple[str, ...]]:
    core_getter = getattr(plugin_registry, "get_active_stratum_artifacts", None)
    core_map = core_getter() if callable(core_getter) else {}
    local_map = _LOCAL_ARTIFACTS_VAR.get() or {}
    resolved: dict[str, tuple[str, ...]] = {}
    for key in ("index_store", "sil", "llvm_ir", "metallib"):
        acc: list[str] = []
        for src in (
            core_map.get(key) if isinstance(core_map, dict) else (),
            local_map.get(key, ()),
            explicit.get(key, ()),
            _norm_paths(overrides.get(key)),
        ):
            for p in _norm_paths(src):  # type: ignore[arg-type]
                if p not in acc:
                    acc.append(p)
        resolved[key] = tuple(acc)
    return resolved


def load_combined_ir_bundle(
    repo_root: Path,
    *,
    index_store: Sequence[str | Path] = (),
    sil: Sequence[str | Path] = (),
    llvm_ir: Sequence[str | Path] = (),
) -> CompilerIrBundle:
    """Load and cross-link read-only USR index, `.sil`, and `.ll` artifacts."""
    bundle = CompilerIrBundle()
    for idx_p in index_store:
        bundle.usr_index.merge(parse_usr_index(idx_p, repo_root=repo_root, allow_external=True))
    for sil_p in sil:
        bundle.merge(parse_sil_file(sil_p, repo_root=repo_root, allow_external=True))
    for ll_p in llvm_ir:
        bundle.merge(parse_llvm_ir_file(ll_p, repo_root=repo_root, allow_external=True))

    # Enrich IR functions missing debug locations using exact USR or symbol name matches
    usr_by_name: dict[str, UsrSymbolRecord] = {}
    for u_rec in bundle.usr_index.symbols_by_usr.values():
        usr_by_name.setdefault(u_rec.name, u_rec)
        short_nm = u_rec.name.split("(")[0].split(".")[-1].split("::")[-1]
        if short_nm:
            usr_by_name.setdefault(short_nm, u_rec)

    for sym_key, fn in list(bundle.functions.items()):
        matched_u = bundle.usr_index.symbols_by_usr.get(fn.usr) or usr_by_name.get(fn.symbol) or usr_by_name.get(fn.label.split("(")[0])
        if matched_u is not None:
            bundle.functions[sym_key] = IrFunctionNode(
                symbol=fn.symbol,
                label=fn.label if fn.is_thunk_or_arc else (matched_u.name or fn.label),
                usr=matched_u.usr,
                language=matched_u.language or fn.language,
                ir_format=fn.ir_format,
                source_file=fn.source_file or matched_u.source_file,
                line=fn.line if fn.source_file else matched_u.line,
                is_defined=fn.is_defined or bool(matched_u.source_file),
                is_thunk_or_arc=fn.is_thunk_or_arc,
            )
    return bundle


def _file_matches_node(file_path: str, node: AtlasNode) -> bool:
    if not file_path or not node.source_file:
        return False
    nf = node.source_file.strip("/")
    fp = file_path.strip("/")
    if fp == nf:
        return True
    if nf.endswith("Package.swift"):
        return False
    nf_dir = nf.rsplit("/", 1)[0] if "/" in nf else ""
    fp_dir = fp.rsplit("/", 1)[0] if "/" in fp else ""
    return Path(fp).stem == Path(nf).stem and (
        nf_dir == fp_dir or fp_dir.startswith(f"{nf_dir}/") or nf_dir.startswith(f"{fp_dir}/")
    )


def upgrade_edges_with_compiler_ir(
    edges: Sequence[AtlasEdge],
    nodes: Sequence[AtlasNode],
    ir_bundle: CompilerIrBundle,
) -> int:
    """Upgrade matching Zoom-1 `AtlasEdge.symbol_links` with compiler-exact USR/SIL/LLVM links."""
    node_by_id = {n.id: n for n in nodes}
    unscoped_out_targets = {
        n.id
        for n in nodes
        if any(e.source_id == n.id for e in edges)
        and not any(e.symbol_links for e in edges if e.source_id == n.id)
    }

    cross_pairs: list[tuple[str, str, str, str, str, str]] = []
    for xref in ir_bundle.usr_index.cross_refs:
        if (
            xref.caller_file
            and xref.callee_file
            and xref.verification == "verified"
            and xref.kind in ("calls_usr", "ffi_call", "witness_dispatch")
        ):
            cross_pairs.append(
                (xref.caller_file, xref.callee_file, xref.caller_name, xref.callee_name, xref.caller_usr, xref.callee_usr)
            )

    calls_by_caller: dict[str, list[Any]] = {}
    for c in ir_bundle.calls:
        if not c.is_dynamic and c.kind != "indirect_call":
            calls_by_caller.setdefault(c.caller_symbol, []).append(c)

    for c in ir_bundle.calls:
        if c.is_dynamic or c.kind == "indirect_call":
            continue
        src_fn = ir_bundle.functions.get(c.caller_symbol)
        dst_fn = ir_bundle.functions.get(c.callee_symbol)
        src_f = (src_fn.source_file if src_fn else "") or c.source_file
        if not src_f or dst_fn is None:
            continue
        if dst_fn.source_file:
            cross_pairs.append((src_f, dst_fn.source_file, c.caller_label, dst_fn.label, c.caller_usr, dst_fn.usr))
        if dst_fn.is_thunk_or_arc:
            for hop2 in calls_by_caller.get(dst_fn.symbol, ()):
                if hop2.is_dynamic or hop2.kind == "indirect_call":
                    continue
                end_fn = ir_bundle.functions.get(hop2.callee_symbol)
                if end_fn is not None and end_fn.source_file:
                    cross_pairs.append((src_f, end_fn.source_file, c.caller_label, end_fn.label, c.caller_usr, end_fn.usr))

    upgraded = 0
    for edge in edges:
        s_node = node_by_id.get(edge.source_id)
        t_node = node_by_id.get(edge.target_id)
        if s_node is None or t_node is None:
            continue
        added: list[str] = []
        for sf, tf, caller_nm, callee_nm, caller_u, callee_u in cross_pairs:
            if _file_matches_node(sf, s_node) and _file_matches_node(tf, t_node):
                if t_node.id in unscoped_out_targets:
                    added.append(f"{caller_nm}->*")
                added.append(f"{caller_nm}->{callee_nm}")
                if caller_u and callee_u:
                    added.append(f"{caller_u}->{callee_u}")
        if added:
            merged = list(dict.fromkeys([*edge.symbol_links, *added]))
            if merged != edge.symbol_links:
                edge.symbol_links = merged
                upgraded += 1
    return upgraded


def _badges_for_node(
    node: AtlasNode,
    ir_bundle: CompilerIrBundle,
    metal: MetalSeamAnalysis,
) -> list[StratumSummaryBadge]:
    ir_syms = {
        u.usr for u in ir_bundle.usr_index.symbols_by_usr.values() if _file_matches_node(u.source_file, node)
    } | {
        fn.usr for fn in ir_bundle.functions.values() if _file_matches_node(fn.source_file, node)
    }
    ir_calls = sum(
        1 for x in ir_bundle.usr_index.cross_refs if _file_matches_node(x.caller_file, node)
    ) + sum(
        1
        for c in ir_bundle.calls
        if _file_matches_node(c.source_file, node)
        or (c.caller_symbol in ir_bundle.functions and _file_matches_node(ir_bundle.functions[c.caller_symbol].source_file, node))
    )
    m_disps = [d for d in metal.host_dispatches if _file_matches_node(d.source_file, node)]
    m_kerns = [k for k in metal.metal_kernels.values() if _file_matches_node(k.source_file, node)]

    badges: list[StratumSummaryBadge] = []
    if ir_syms:
        badges.append(StratumSummaryBadge(key="ir_symbols", label="IR/USR Symbols", count=len(ir_syms)))
    if ir_calls:
        badges.append(StratumSummaryBadge(key="ir_calls", label="Compiler IR Calls", count=ir_calls))
    if m_disps:
        badges.append(StratumSummaryBadge(key="metal_dispatches", label="Metal Dispatches", count=len(m_disps)))
    if m_kerns:
        badges.append(StratumSummaryBadge(key="metal_kernels", label="Metal AIR Kernels", count=len(m_kerns)))
    return badges


def _expand_node_zoom2(
    parent: AtlasNode,
    ir_bundle: CompilerIrBundle,
    metal: MetalSeamAnalysis,
) -> StratumExpansionResult:
    nodes_map: dict[str, StratumMicroNode] = {}
    edges_map: dict[str, StratumMicroEdge] = {}
    notes: list[str] = list(dict.fromkeys([*ir_bundle.notes, *ir_bundle.usr_index.notes]))

    def _put_node(n: StratumMicroNode) -> None:
        nodes_map.setdefault(n.id, n)

    def _put_edge(e: StratumMicroEdge) -> None:
        edges_map.setdefault(e.id, e)

    # 1. USR symbols & cross-references
    for u_rec in ir_bundle.usr_index.symbols_by_usr.values():
        if _file_matches_node(u_rec.source_file, parent):
            nid = f"z2:{parent.id}:usr:{u_rec.usr}"
            _put_node(
                StratumMicroNode(
                    id=nid,
                    label=u_rec.name,
                    kind=f"usr_{u_rec.kind}",
                    zoom=2,
                    source_file=u_rec.source_file or None,
                    line=u_rec.line,
                    verification="verified",
                    summary=f"{u_rec.language} symbol [{u_rec.usr}]",
                )
            )

    for xref in ir_bundle.usr_index.cross_refs:
        if not _file_matches_node(xref.caller_file, parent):
            continue
        src_id = f"z2:{parent.id}:usr:{xref.caller_usr}"
        dst_id = f"z2:{parent.id}:usr:{xref.callee_usr}"
        is_exact_caller = xref.provenance in (
            "compiler_called_by",
            "compiler_override_of",
            "compiler_base_of",
            "compiler_containment",
        )
        src_verif: VerificationState = (
            "verified"
            if is_exact_caller and not xref.caller_usr.startswith("file:")
            else "unverified"
        )
        _put_node(
            StratumMicroNode(
                id=src_id,
                label=xref.caller_name,
                kind="usr_function",
                zoom=2,
                source_file=xref.caller_file or None,
                line=xref.caller_line,
                verification=src_verif,
                summary=(
                    f"Caller [{xref.caller_usr}]"
                    if is_exact_caller
                    else f"Unverified heuristic enclosing caller [{xref.caller_usr}] ({xref.provenance})"
                ),
            )
        )
        dst_node_verif: VerificationState = (
            "unverified" if xref.is_dynamic else ("verified" if xref.callee_file else "declared")
        )
        _put_node(
            StratumMicroNode(
                id=dst_id,
                label=xref.callee_name,
                kind="usr_function",
                zoom=2,
                source_file=xref.callee_file or None,
                line=xref.callee_line,
                verification=dst_node_verif,
                summary=f"Callee [{xref.callee_usr}]",
            )
        )
        edge_verif: VerificationState = xref.verification
        ev_note = (
            f"USR {xref.caller_usr} -> {xref.callee_usr}"
            if is_exact_caller
            else (
                f"Heuristic caller ({xref.provenance}, no compiler calledBy relation): "
                f"USR {xref.caller_usr} -> {xref.callee_usr}"
            )
        )
        eid = f"e:{src_id}->{dst_id}:{xref.kind}"
        _put_edge(
            StratumMicroEdge(
                id=eid,
                source_id=src_id,
                target_id=dst_id,
                label=f"{xref.caller_name}->{xref.callee_name}",
                kind=xref.kind,
                verification=edge_verif,
                evidence_note=ev_note,
            )
        )

    # 2. SIL & LLVM IR functions and transitive witness/vtable/ARC hops
    seed_syms = {
        fn.symbol
        for fn in ir_bundle.functions.values()
        if _file_matches_node(fn.source_file, parent)
        or (not fn.source_file and parent.label and parent.label in fn.label)
    }
    calls_from: dict[str, list[Any]] = {}
    for c in ir_bundle.calls:
        calls_from.setdefault(c.caller_symbol, []).append(c)
        if _file_matches_node(c.source_file, parent):
            seed_syms.add(c.caller_symbol)

    frontier = sorted(seed_syms)
    visited_syms = set(seed_syms)
    active_calls: list[Any] = []
    while frontier:
        cur_sym = frontier.pop(0)
        for c in calls_from.get(cur_sym, ()):
            active_calls.append(c)
            tgt_fn = ir_bundle.functions.get(c.callee_symbol)
            if c.callee_symbol not in visited_syms:
                visited_syms.add(c.callee_symbol)
                if tgt_fn is not None and tgt_fn.is_thunk_or_arc:
                    frontier.append(c.callee_symbol)

    for sym in sorted(visited_syms):
        fn = ir_bundle.functions.get(sym)
        if fn is None:
            continue
        verif: VerificationState = (
            "unverified"
            if sym.startswith("indirect:")
            else ("verified" if fn.is_defined or fn.is_thunk_or_arc else "declared")
        )
        _put_node(
            StratumMicroNode(
                id=f"z2:{parent.id}:ir:{fn.symbol}",
                label=fn.label,
                kind=f"{fn.ir_format}_thunk" if fn.is_thunk_or_arc else f"{fn.ir_format}_fn",
                zoom=2,
                source_file=fn.source_file or None,
                line=fn.line,
                verification=verif,
                summary=f"{fn.ir_format.upper()} ({fn.language}) [{fn.usr}]",
            )
        )

    for c in active_calls:
        s_id = f"z2:{parent.id}:ir:{c.caller_symbol}"
        t_id = f"z2:{parent.id}:ir:{c.callee_symbol}"
        e_verif: VerificationState = "unverified" if c.is_dynamic else "verified"
        _put_edge(
            StratumMicroEdge(
                id=f"e:{s_id}->{t_id}:{c.kind}:{c.line}",
                source_id=s_id,
                target_id=t_id,
                label=f"{c.caller_label}->{c.callee_label}",
                kind=c.kind,
                verification=e_verif,
                evidence_note=f"{c.ir_format.upper()} {c.caller_usr} -> {c.callee_usr}",
            )
        )

    # 3. Host <-> Metal AIR compute dispatches
    available_air = set(metal.metal_kernels) | set(metal.metallib_exports)
    node_disps = [d for d in metal.host_dispatches if _file_matches_node(d.source_file, parent)]
    if (
        node_disps
        or any(_file_matches_node(k.source_file, parent) for k in metal.metal_kernels.values())
    ) and METAL_AIR_EPISTEMIC_NOTE not in notes:
        notes.append(METAL_AIR_EPISTEMIC_NOTE)

    for idx, disp in enumerate(node_disps, start=1):
        d_id = f"z2:{parent.id}:metal_disp:{idx}:{disp.enclosing_symbol}"
        d_verif: VerificationState = (
            "unverified" if disp.binding_verification == "unverified" else "verified"
        )
        _put_node(
            StratumMicroNode(
                id=d_id,
                label=f"{disp.enclosing_symbol}:{disp.lookup_api}",
                kind="metal_dispatch",
                zoom=2,
                source_file=disp.source_file,
                line=disp.line,
                verification=d_verif,
                summary=f"Host {disp.language} Metal compute dispatch ({len(disp.buffer_args)} buffer binding(s))",
            )
        )
        if disp.is_dynamic_kernel or not disp.kernel_name:
            k_id = f"z2:{parent.id}:metal_dyn:{idx}"
            _put_node(
                StratumMicroNode(
                    id=k_id,
                    label=f"dynamic:{disp.kernel_expr}",
                    kind="metal_dynamic_kernel",
                    zoom=2,
                    source_file=disp.source_file,
                    line=disp.line,
                    verification="unverified",
                    summary="Runtime/JIT-specialized Metal kernel expression (unresolved statically)",
                )
            )
            _put_edge(
                StratumMicroEdge(
                    id=f"e:{d_id}->{k_id}:dispatches_kernel",
                    source_id=d_id,
                    target_id=k_id,
                    label="dispatches_dynamic_kernel",
                    kind="dispatches_kernel",
                    verification="unverified",
                    evidence_note=f"Dynamic/JIT kernel specialization `{disp.kernel_expr}`",
                )
            )
        else:
            kspec = metal.metal_kernels.get(disp.kernel_name)
            in_air = disp.kernel_name in available_air
            k_verif: VerificationState = "verified" if in_air else "broken"
            edge_k_verif: VerificationState = (
                "broken" if not in_air else ("unverified" if d_verif == "unverified" else "verified")
            )
            k_id = f"z2:{parent.id}:metal_air:{disp.kernel_name}"
            _put_node(
                StratumMicroNode(
                    id=k_id,
                    label=disp.kernel_name,
                    kind="metal_air_kernel",
                    zoom=2,
                    source_file=kspec.source_file if kspec else None,
                    line=kspec.line if kspec else None,
                    verification=k_verif,
                    summary=(
                        f"Metal AIR kernel `{disp.kernel_name}` (buffers={sorted(kspec.buffers) if kspec else []})"
                        if in_air
                        else f"Missing Metal kernel `{disp.kernel_name}`"
                    ),
                )
            )
            _put_edge(
                StratumMicroEdge(
                    id=f"e:{d_id}->{k_id}:dispatches_kernel",
                    source_id=d_id,
                    target_id=k_id,
                    label=f"{disp.enclosing_symbol}->{disp.kernel_name}",
                    kind="dispatches_kernel",
                    verification=edge_k_verif,
                    evidence_note=f"Host `{disp.lookup_api}` -> Metal AIR `{disp.kernel_name}`",
                )
            )

    return StratumExpansionResult(
        summary_badges=_badges_for_node(parent, ir_bundle, metal),
        nodes=list(nodes_map.values()),
        edges=list(edges_map.values()),
        notes=notes,
    )


class CompilerIrPlugin:
    """Multi-capability Zoom-2 Compiler IR (`USR`/`SIL`/`LLVM`) & Metal `AIR` plugin."""

    name = "compiler-ir"
    kind = "stratum_inspector"
    version = PLUGIN_VERSION
    description = (
        "Read-only Zoom-2 compiler IR (IndexStoreDB USR, Swift SIL, LLVM IR) and "
        "CPU-to-Metal AIR compute seam verifier (METAL-001..003)."
    )
    supported_zooms: tuple[int, ...] = (2,)
    enabled_by_default: bool = True
    rules: tuple[PluginRuleSpec, ...] = COMPILER_IR_RULES
    plugin_rules: tuple[PluginRuleSpec, ...] = COMPILER_IR_RULES

    def __init__(
        self,
        *,
        index_store: str | Path | Sequence[str | Path] | None = None,
        sil: str | Path | Sequence[str | Path] | None = None,
        llvm_ir: str | Path | Sequence[str | Path] | None = None,
        metallib: str | Path | Sequence[str | Path] | None = None,
        extra_metal_files: str | Path | Sequence[str | Path] | None = None,
    ) -> None:
        self._explicit_artifacts: dict[str, tuple[str, ...]] = {
            "index_store": _norm_paths(index_store),
            "sil": _norm_paths(sil),
            "llvm_ir": _norm_paths(llvm_ir),
            "metallib": _norm_paths(metallib),
        }
        self._extra_metal_files: tuple[str, ...] = _norm_paths(extra_metal_files)

    def _collect_artifacts(
        self,
        *,
        index_store: str | Path | Sequence[str | Path] | None = None,
        sil: str | Path | Sequence[str | Path] | None = None,
        llvm_ir: str | Path | Sequence[str | Path] | None = None,
        metallib: str | Path | Sequence[str | Path] | None = None,
    ) -> dict[str, tuple[str, ...]]:
        return _resolve_active_artifacts(
            self._explicit_artifacts,
            {
                "index_store": index_store,
                "sil": sil,
                "llvm_ir": llvm_ir,
                "metallib": metallib,
            },
        )

    def augment_manipulator(
        self,
        repo_root: Path,
        backend_subdir: str,
        result: ManipulatorExtractionResult,
        *,
        index_store: str | Path | Sequence[str | Path] | None = None,
        sil: str | Path | Sequence[str | Path] | None = None,
        llvm_ir: str | Path | Sequence[str | Path] | None = None,
    ) -> None:
        _ = backend_subdir
        arts = self._collect_artifacts(index_store=index_store, sil=sil, llvm_ir=llvm_ir)
        if not (arts["index_store"] or arts["sil"] or arts["llvm_ir"]):
            return
        ir_bundle = load_combined_ir_bundle(
            repo_root,
            index_store=arts["index_store"],
            sil=arts["sil"],
            llvm_ir=arts["llvm_ir"],
        )
        upgraded = upgrade_edges_with_compiler_ir(result.edges, result.nodes, ir_bundle)
        if upgraded:
            result.notes.append(
                f"compiler-ir: upgraded {upgraded} Zoom-1 edge(s) with exact USR/SIL/LLVM symbol_links."
            )

    def check_report(
        self,
        repo_root: Path,
        report: TruthAtlasReport,
        *,
        metallib: str | Path | Sequence[str | Path] | None = None,
        extra_metal_files: str | Path | Sequence[str | Path] | None = None,
    ) -> dict[str, object]:
        arts = self._collect_artifacts(metallib=metallib)
        extra_metals = [*self._extra_metal_files, *_norm_paths(extra_metal_files)]
        nid_by_file = {n.source_file: n.id for n in report.nodes}
        seam = verify_metal_compute_seams(
            repo_root,
            metallib_paths=arts["metallib"],
            extra_metal_files=extra_metals,
            node_id_by_file=nid_by_file,
        )
        if not seam.has_metal_surface:
            return {"has_metal_surface": False, "findings": [], "notes": []}

        existing_keys = {(f.rule_code, f.source_file, f.line) for f in report.findings}
        out_findings: list[RawCandidateFinding] = []
        for fdict in seam.findings:
            fkey = (str(fdict["rule_code"]), str(fdict["source_file"]), int(fdict["line"]))  # type: ignore[arg-type]
            if fkey in existing_keys:
                continue
            existing_keys.add(fkey)
            out_findings.append(
                RawCandidateFinding(
                    rule_code=str(fdict["rule_code"]),
                    node_id=fdict.get("node_id"),  # type: ignore[arg-type]
                    source_file=str(fdict["source_file"]),
                    line=int(fdict["line"]),  # type: ignore[arg-type]
                    title=str(fdict["title"]),
                    detail=str(fdict["detail"]),
                    remediation=str(fdict["remediation"]),
                    confidence=str(fdict.get("confidence", "confirmed")),
                    evidence_strength=str(fdict.get("evidence_strength", "ast_exact")),
                )
            )
        return {
            "has_metal_surface": True,
            "findings": out_findings,
            "notes": list(seam.notes),
            "unresolved_dynamic_kernels": [
                {"source_file": d.source_file, "line": d.line, "expr": d.kernel_expr}
                for d in seam.unresolved_dispatches
            ],
        }

    def summarize_zoom1_badges(
        self,
        repo_root: Path,
        report: TruthAtlasReport,
        *,
        index_store: str | Path | Sequence[str | Path] | None = None,
        sil: str | Path | Sequence[str | Path] | None = None,
        llvm_ir: str | Path | Sequence[str | Path] | None = None,
        metallib: str | Path | Sequence[str | Path] | None = None,
    ) -> dict[str, list[StratumSummaryBadge]]:
        arts = self._collect_artifacts(
            index_store=index_store,
            sil=sil,
            llvm_ir=llvm_ir,
            metallib=metallib,
        )
        try:
            ir_bundle = (
                load_combined_ir_bundle(
                    repo_root,
                    index_store=arts["index_store"],
                    sil=arts["sil"],
                    llvm_ir=arts["llvm_ir"],
                )
                if (arts["index_store"] or arts["sil"] or arts["llvm_ir"])
                else CompilerIrBundle()
            )
            seam = verify_metal_compute_seams(
                repo_root,
                metallib_paths=arts["metallib"],
                extra_metal_files=self._extra_metal_files,
            )
        except (OSError, ValueError):
            return {}
        if not (ir_bundle.functions or ir_bundle.usr_index.symbols_by_usr or seam.has_metal_surface):
            return {}

        badges_by_node: dict[str, list[StratumSummaryBadge]] = {}
        for node in report.nodes:
            b_list = _badges_for_node(node, ir_bundle, seam)
            if b_list:
                badges_by_node[node.id] = b_list
        return badges_by_node

    def expand_node_stratum(
        self,
        repo_root: Path,
        report: TruthAtlasReport,
        node_id: str,
        zoom: Literal[2, 3],
        *,
        index_store: str | Path | Sequence[str | Path] | None = None,
        sil: str | Path | Sequence[str | Path] | None = None,
        llvm_ir: str | Path | Sequence[str | Path] | None = None,
        metallib: str | Path | Sequence[str | Path] | None = None,
    ) -> StratumExpansionResult:
        if zoom != 2:
            return StratumExpansionResult()
        parent = next((n for n in report.nodes if n.id == node_id), None)
        if parent is None:
            return StratumExpansionResult()

        arts = self._collect_artifacts(
            index_store=index_store,
            sil=sil,
            llvm_ir=llvm_ir,
            metallib=metallib,
        )
        ir_bundle = (
            load_combined_ir_bundle(
                repo_root,
                index_store=arts["index_store"],
                sil=arts["sil"],
                llvm_ir=arts["llvm_ir"],
            )
            if (arts["index_store"] or arts["sil"] or arts["llvm_ir"])
            else CompilerIrBundle()
        )
        seam = verify_metal_compute_seams(
            repo_root,
            metallib_paths=arts["metallib"],
            extra_metal_files=self._extra_metal_files,
        )
        return _expand_node_zoom2(parent, ir_bundle, seam)

    def to_spec(self) -> WythePluginSpec:
        """Build a normalized `WythePluginSpec` bound to this plugin instance."""
        return WythePluginSpec(
            name=self.name,
            kind="stratum_inspector",
            origin="entry_point",
            version=self.version,
            description=self.description,
            enabled_by_default=self.enabled_by_default,
            supported_zooms=self.supported_zooms,
            manipulator_hook=self.augment_manipulator,
            post_scan_hook=self.check_report,
            stratum_badge_hook=self.summarize_zoom1_badges,
            stratum_expand_hook=self.expand_node_stratum,
            rules=COMPILER_IR_RULES,
        )


_DEFAULT_COMPILER_IR_INSTANCE = CompilerIrPlugin()
COMPILER_IR_PLUGIN: WythePluginSpec = _DEFAULT_COMPILER_IR_INSTANCE.to_spec()
WYTHE_PLUGIN: WythePluginSpec = COMPILER_IR_PLUGIN


def register_wythe_plugin() -> WythePluginSpec:
    """Entry-point factory returning `COMPILER_IR_PLUGIN`."""
    return COMPILER_IR_PLUGIN
