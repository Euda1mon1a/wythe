"""Wythe Zoom-3 runtime wiretap, `.memgraph`/`vmmap` heap, and port occupancy plugin (`#79`)."""

from __future__ import annotations

import re
from collections.abc import Iterator, Mapping, Sequence
from contextlib import contextmanager
from contextvars import ContextVar
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Literal

from app.adapters import plugin_registry
from app.adapters.plugin_registry import PluginRuleSpec, WythePluginSpec
from app.schemas.atlas import (
    StratumExpansionResult,
    StratumMicroEdge,
    StratumMicroNode,
    StratumSummaryBadge,
    TruthAtlasReport,
)
from wythe_plugin_wiretap.heap_memgraph import (
    attribute_heap_to_nodes,
    parse_memgraph_artifact,
    parse_vmmap_artifact,
)
from wythe_plugin_wiretap.otel_ebpf import (
    NON_CERTIFICATION_NOTICE,
    ObservedRuntimeTransition,
    correlate_traces_and_flows,
    parse_ebpf_flows,
    parse_otel_traces,
)
from wythe_plugin_wiretap.port_occupancy import correlate_port_occupancy

PORT_001_RULE = PluginRuleSpec(
    rule_code="PORT-001",
    tier="manipulate",
    title="Declared service port is occupied at runtime by an unexpected squatter process",
    severity="blocking",
    blocks_gate=True,
    enabled=True,
    confidence="confirmed",
    evidence_strength="structural_match",
)

PORT_002_RULE = PluginRuleSpec(
    rule_code="PORT-002",
    tier="manipulate",
    title="Runtime listener bind exposure drifts between wildcard 0.0.0.0 and loopback 127.0.0.1",
    severity="blocking",
    blocks_gate=True,
    enabled=True,
    confidence="confirmed",
    evidence_strength="structural_match",
)


@dataclass(frozen=True)
class WiretapInputs:
    """Normalized active capture paths and opt-in host listener flag."""

    otel_traces: tuple[str, ...] = ()
    ebpf_flows: tuple[str, ...] = ()
    memgraph: tuple[str, ...] = ()
    vmmap: tuple[str, ...] = ()
    port_listeners: tuple[str, ...] = ()
    probe_local_ports: bool = False

    @property
    def any_active(self) -> bool:
        return bool(
            self.otel_traces
            or self.ebpf_flows
            or self.memgraph
            or self.vmmap
            or self.port_listeners
            or self.probe_local_ports
        )


_ACTIVE_WIRETAP_VAR: ContextVar[WiretapInputs | None] = ContextVar(
    "_wythe_plugin_wiretap_active_inputs",
    default=None,
)


def _norm_paths(raw: object) -> list[str]:
    if raw is None or isinstance(raw, bool):
        return []
    if isinstance(raw, (str, Path)):
        s = str(raw).strip()
        return [s] if s else []
    if isinstance(raw, Sequence):
        out: list[str] = []
        for item in raw:
            if isinstance(item, (str, Path)):
                s = str(item).strip()
                if s and s not in out:
                    out.append(s)
        return out
    return []


@contextmanager
def wiretap_inspection_scope(
    *,
    otel_traces: str | Path | Sequence[str | Path] | None = None,
    ebpf_flows: str | Path | Sequence[str | Path] | None = None,
    memgraph: str | Path | Sequence[str | Path] | None = None,
    vmmap: str | Path | Sequence[str | Path] | None = None,
    port_listeners: str | Path | Sequence[str | Path] | None = None,
    probe_local_ports: bool = False,
) -> Iterator[WiretapInputs]:
    """Bind read-only wiretap capture files for Zoom-1 badges, Zoom-3 drilldown, or companions."""
    inputs = WiretapInputs(
        otel_traces=tuple(_norm_paths(otel_traces)),
        ebpf_flows=tuple(_norm_paths(ebpf_flows)),
        memgraph=tuple(_norm_paths(memgraph)),
        vmmap=tuple(_norm_paths(vmmap)),
        port_listeners=tuple(_norm_paths(port_listeners)),
        probe_local_ports=bool(probe_local_ports),
    )
    token = _ACTIVE_WIRETAP_VAR.set(inputs)
    try:
        yield inputs
    finally:
        _ACTIVE_WIRETAP_VAR.reset(token)


def get_active_wiretap_inputs(**overrides: object) -> WiretapInputs:
    """Merge explicit kwargs, `plugin_registry.get_active_stratum_artifacts()`, and local scope."""
    reg_map: Mapping[str, Any] = getattr(
        plugin_registry, "get_active_stratum_artifacts", dict
    )()
    scoped = _ACTIVE_WIRETAP_VAR.get() or WiretapInputs()

    def _merge_key(primary: str, *aliases: str, scoped_vals: tuple[str, ...]) -> tuple[str, ...]:
        merged: list[str] = []
        sources: list[object] = [overrides.get(primary)]
        sources.extend(overrides.get(a) for a in aliases)
        sources.append(reg_map.get(primary))
        sources.extend(reg_map.get(a) for a in aliases)
        sources.append(scoped_vals)
        for src in sources:
            for p in _norm_paths(src):
                if p not in merged:
                    merged.append(p)
        return tuple(merged)

    probe_override = overrides.get("probe_local_ports")
    reg_probe = reg_map.get("probe_local_ports")
    probe_flag = (
        bool(probe_override)
        if probe_override is not None
        else (
            str(reg_probe[0]).lower() in ("1", "true", "yes")
            if isinstance(reg_probe, tuple) and reg_probe
            else scoped.probe_local_ports
        )
    )

    return WiretapInputs(
        otel_traces=_merge_key("otel_traces", "otel_traces_path", "otel", scoped_vals=scoped.otel_traces),
        ebpf_flows=_merge_key("ebpf_flows", "ebpf_flows_path", "ebpf", scoped_vals=scoped.ebpf_flows),
        memgraph=_merge_key("memgraph", "memgraph_path", scoped_vals=scoped.memgraph),
        vmmap=_merge_key("vmmap", "vmmap_path", scoped_vals=scoped.vmmap),
        port_listeners=_merge_key(
            "port_listeners", "port_listeners_path", "listeners", scoped_vals=scoped.port_listeners
        ),
        probe_local_ports=probe_flag,
    )


def _slug_tok(raw: str) -> str:
    cleaned = re.sub(r"[^A-Za-z0-9_.:-]+", "_", raw.strip())
    return cleaned[:96] or "item"


def _evaluate_wiretap_bundle(
    repo_root: Path,
    report: TruthAtlasReport,
    inputs: WiretapInputs,
) -> dict[str, Any]:
    transitions: list[ObservedRuntimeTransition] = []
    redacted_fields = 0
    for ot_p in inputs.otel_traces:
        ot_list, r_cnt = parse_otel_traces(ot_p)
        transitions.extend(ot_list)
        redacted_fields += r_cnt
    for eb_p in inputs.ebpf_flows:
        eb_list, r_cnt = parse_ebpf_flows(eb_p)
        transitions.extend(eb_list)
        redacted_fields += r_cnt

    trace_corr = (
        correlate_traces_and_flows(report, transitions)
        if (inputs.otel_traces or inputs.ebpf_flows)
        else {
            "transition_count": 0,
            "corroborated_edge_count": 0,
            "static_dark_matter_edge_count": len(getattr(report, "edges", ())),
            "static_dark_matter_node_count": len(getattr(report, "nodes", ())),
            "runtime_only_count": 0,
            "corroborated_edges": [],
            "static_dark_matter": {
                "epistemic_note": (
                    "Zero observed spans in this capture window means unexercised in this sample "
                    "(static dark matter), NEVER proof of dead or unreachable code."
                ),
                "edges": [],
                "nodes": [],
            },
            "runtime_only": [],
            "node_hit_counts": {},
            "sample_transitions": [],
        }
    )

    memgraph_summaries = [parse_memgraph_artifact(mp) for mp in inputs.memgraph]
    vmmap_summaries = [parse_vmmap_artifact(vp) for vp in inputs.vmmap]
    merged_memgraph: dict[str, Any] | None = None
    if memgraph_summaries:
        merged_memgraph = {
            "paths": [m["path"] for m in memgraph_summaries],
            "live_instance_count": sum(int(m["live_instance_count"]) for m in memgraph_summaries),
            "live_heap_bytes": sum(int(m["live_heap_bytes"]) for m in memgraph_summaries),
            "retain_cycle_count": sum(int(m["retain_cycle_count"]) for m in memgraph_summaries),
            "redacted_heap_buffers": sum(int(m["redacted_heap_buffers"]) for m in memgraph_summaries),
            "classes": [c for m in memgraph_summaries for c in m["classes"]],
            "retain_cycles": [cy for m in memgraph_summaries for cy in m["retain_cycles"]],
        }
        redacted_fields += int(merged_memgraph["redacted_heap_buffers"])

    merged_vmmap: dict[str, Any] | None = None
    if vmmap_summaries:
        merged_vmmap = {
            "paths": [v["path"] for v in vmmap_summaries],
            "region_count": sum(int(v["region_count"]) for v in vmmap_summaries),
            "total_dirty_bytes": sum(int(v["total_dirty_bytes"]) for v in vmmap_summaries),
            "total_wired_bytes": sum(int(v["total_wired_bytes"]) for v in vmmap_summaries),
            "total_resident_bytes": sum(int(v["total_resident_bytes"]) for v in vmmap_summaries),
            "malloc_dirty_bytes": sum(int(v["malloc_dirty_bytes"]) for v in vmmap_summaries),
            "metal_ioaccelerator_dirty_bytes": sum(
                int(v["metal_ioaccelerator_dirty_bytes"]) for v in vmmap_summaries
            ),
            "data_dirty_bytes": sum(int(v["data_dirty_bytes"]) for v in vmmap_summaries),
            "regions": [r for v in vmmap_summaries for r in v["regions"]],
        }

    heap_by_node = attribute_heap_to_nodes(report, merged_memgraph, merged_vmmap)
    port_occ = correlate_port_occupancy(
        repo_root,
        report,
        port_listeners_paths=inputs.port_listeners,
        probe_local_ports=inputs.probe_local_ports,
    )
    return {
        "traces_and_flows": trace_corr,
        "memgraph": merged_memgraph,
        "vmmap": merged_vmmap,
        "heap_by_node": heap_by_node,
        "port_occupancy": port_occ,
        "redacted_field_count": redacted_fields,
    }


def _badges_for_node(
    nid: str,
    bundle: Mapping[str, Any],
) -> list[StratumSummaryBadge]:
    badges: list[StratumSummaryBadge] = []
    hit_cnt = int(bundle["traces_and_flows"].get("node_hit_counts", {}).get(nid, 0))
    if hit_cnt > 0:
        badges.append(
            StratumSummaryBadge(
                key="wiretap_runtime_hits",
                label="Observed Runtime Hits",
                count=hit_cnt,
            )
        )
    heap_b = bundle["heap_by_node"].get(nid)
    if heap_b:
        if int(heap_b["live_instances"]) > 0:
            badges.append(
                StratumSummaryBadge(
                    key="wiretap_heap_instances",
                    label="Live Heap Instances",
                    count=int(heap_b["live_instances"]),
                )
            )
        if heap_b["retain_cycles"]:
            badges.append(
                StratumSummaryBadge(
                    key="wiretap_retain_cycles",
                    label="Retain Cycle SCCs",
                    count=len(heap_b["retain_cycles"]),
                )
            )
        if int(heap_b["dirty_bytes"]) > 0:
            badges.append(
                StratumSummaryBadge(
                    key="wiretap_dirty_kib",
                    label="Dirty Heap/VM KiB",
                    count=max(1, int(heap_b["dirty_bytes"]) // 1024),
                )
            )
    port_entries = [
        e
        for e in bundle["port_occupancy"].get("entries", ())
        if any(d.get("node_id") == nid for d in e.get("declared", ()))
    ]
    if port_entries:
        badges.append(
            StratumSummaryBadge(
                key="wiretap_ports",
                label="Observed Port Bindings",
                count=len(port_entries),
            )
        )
    return badges


def summarize_wiretap_zoom1_badges(
    repo_root: Path,
    report: TruthAtlasReport,
) -> dict[str, list[StratumSummaryBadge]]:
    """Attach optional Zoom-1 runtime/heap/port summary badges without altering digests."""
    inputs = get_active_wiretap_inputs()
    if not inputs.any_active:
        return {}
    bundle = _evaluate_wiretap_bundle(repo_root, report, inputs)
    out: dict[str, list[StratumSummaryBadge]] = {}
    for node in report.nodes:
        b_list = _badges_for_node(node.id, bundle)
        if b_list:
            out[node.id] = b_list
    return out


def expand_wiretap_zoom3_stratum(
    repo_root: Path,
    report: TruthAtlasReport,
    node_id: str,
    zoom: Literal[2, 3],
) -> StratumExpansionResult:
    """Expand Zoom-3 heap classes, Tarjan retain cycles, `vmmap` regions, & runtime overlays."""
    if zoom != 3:
        return StratumExpansionResult()
    inputs = get_active_wiretap_inputs()
    if not inputs.any_active:
        return StratumExpansionResult(
            notes=[
                (
                    "Pass `--otel-traces`, `--ebpf-flows`, `--memgraph`, `--vmmap`, or "
                    "`--port-listeners` to inspect Zoom-3 runtime wiretap strata."
                )
            ]
        )
    parent = next((n for n in report.nodes if n.id == node_id), None)
    if parent is None:
        return StratumExpansionResult()

    bundle = _evaluate_wiretap_bundle(repo_root, report, inputs)
    micro_nodes: list[StratumMicroNode] = []
    micro_edges: list[StratumMicroEdge] = []
    notes: list[str] = []

    heap_b = bundle["heap_by_node"].get(node_id)
    if heap_b:
        for idx, cls_d in enumerate(heap_b["classes"][:64], start=1):
            c_name = str(cls_d["class_name"])
            cid = f"z3:{node_id}:heap_cls:{idx}:{_slug_tok(c_name)}"
            micro_nodes.append(
                StratumMicroNode(
                    id=cid,
                    label=c_name,
                    kind="heap_allocation_class",
                    zoom=3,
                    source_file=parent.source_file,
                    line=parent.line,
                    verification="verified",
                    summary=f"{cls_d['instance_count']} live instances ({cls_d['total_bytes']} B)",
                )
            )
            micro_edges.append(
                StratumMicroEdge(
                    id=f"e:{node_id}->heap_cls:{idx}",
                    source_id=node_id,
                    target_id=cid,
                    label="allocates_heap_class",
                    kind="allocates_heap_class",
                    verification="verified",
                    evidence_note=f"Live heap class `{c_name}` ({cls_d['instance_count']} instances)",
                )
            )
        for idx, cyc in enumerate(heap_b["retain_cycles"][:32], start=1):
            cyc_lbl = " -> ".join(cyc["class_names"][:4])
            sid = f"z3:{node_id}:retain_scc:{idx}"
            micro_nodes.append(
                StratumMicroNode(
                    id=sid,
                    label=f"Retain Cycle ({cyc_lbl})",
                    kind="retain_cycle_scc",
                    zoom=3,
                    source_file=parent.source_file,
                    line=parent.line,
                    verification="broken",
                    summary=f"Tarjan SCC ({len(cyc['member_ids'])} nodes, {cyc['retained_bytes']} B)",
                )
            )
            micro_edges.append(
                StratumMicroEdge(
                    id=f"e:{node_id}->retain_scc:{idx}",
                    source_id=node_id,
                    target_id=sid,
                    label="retains_cycle_scc",
                    kind="retains_cycle_scc",
                    verification="broken",
                    evidence_note=f"Strong retain cycle SCC across {cyc['member_ids']}",
                )
            )
        for idx, reg in enumerate(heap_b["vmmap_regions"][:32], start=1):
            rid = f"z3:{node_id}:vmmap:{idx}:{_slug_tok(reg['region_type'])}"
            micro_nodes.append(
                StratumMicroNode(
                    id=rid,
                    label=reg["region_type"],
                    kind="vmmap_region",
                    zoom=3,
                    source_file=parent.source_file,
                    line=parent.line,
                    verification="declared",
                    summary=(
                        f"{reg['category']} dirty={reg['dirty_bytes']} B, "
                        f"wired={reg['wired_bytes']} B"
                    ),
                )
            )
            micro_edges.append(
                StratumMicroEdge(
                    id=f"e:{node_id}->vmmap:{idx}",
                    source_id=node_id,
                    target_id=rid,
                    label="maps_vm_region",
                    kind="maps_vm_region",
                    verification="declared",
                    evidence_note=f"`vmmap` region `{reg['region_type']}`",
                )
            )

    default_manip = next((n.id for n in report.nodes if n.tier == "manipulate"), "")
    if node_id == default_manip:
        for idx, b_spot in enumerate(bundle["traces_and_flows"].get("runtime_only", ())[:32], start=1):
            bid = f"z3:{node_id}:runtime_only:{idx}:{_slug_tok(str(b_spot['target']))}"
            micro_nodes.append(
                StratumMicroNode(
                    id=bid,
                    label=f"{b_spot['protocol']}:{b_spot['target']}",
                    kind="runtime_only_blind_spot",
                    zoom=3,
                    verification="unverified",
                    summary=f"Runtime-only transition ({b_spot['witness_count']} witness(es))",
                )
            )
            micro_edges.append(
                StratumMicroEdge(
                    id=f"e:{node_id}->runtime_only:{idx}",
                    source_id=node_id,
                    target_id=bid,
                    label="runtime_only",
                    kind="runtime_only",
                    verification="unverified",
                    evidence_note="Observed in runtime capture; absent from static Zoom-1 graph",
                )
            )

    for idx, p_ent in enumerate(bundle["port_occupancy"].get("entries", ())[:32], start=1):
        decl_nids = {d.get("node_id") for d in p_ent.get("declared", ()) if d.get("node_id")}
        if node_id not in decl_nids and not (not decl_nids and node_id == default_manip):
            continue
        cls_state = str(p_ent["classification"])
        verif: Literal["verified", "broken", "unverified", "declared"] = (
            "broken"
            if cls_state in ("squatter_conflict", "bind_exposure_drift")
            else ("verified" if cls_state == "corroborated" else ("unverified" if cls_state == "dark_listener" else "declared"))
        )
        pid_node = f"z3:{node_id}:port:{idx}:{p_ent['port']}"
        micro_nodes.append(
            StratumMicroNode(
                id=pid_node,
                label=f"{p_ent['protocol'].upper()} :{p_ent['port']} ({cls_state})",
                kind="port_occupancy",
                zoom=3,
                verification=verif,
                summary=f"Port occupancy state `{cls_state}`",
            )
        )
        micro_edges.append(
            StratumMicroEdge(
                id=f"e:{node_id}->port:{idx}",
                source_id=node_id,
                target_id=pid_node,
                label=cls_state,
                kind="binds_port",
                verification=verif,
                evidence_note=f"Host port `{p_ent['port']}` classified as `{cls_state}`",
            )
        )

    return StratumExpansionResult(
        summary_badges=_badges_for_node(node_id, bundle),
        nodes=micro_nodes,
        edges=micro_edges,
        notes=notes,
    )


def correlate_wiretap_companions(
    repo_root: Path | str,
    report: TruthAtlasReport,
    *,
    otel_traces_path: str | Path | Sequence[str | Path] | None = None,
    ebpf_flows_path: str | Path | Sequence[str | Path] | None = None,
    memgraph_path: str | Path | Sequence[str | Path] | None = None,
    vmmap_path: str | Path | Sequence[str | Path] | None = None,
    port_listeners_path: str | Path | Sequence[str | Path] | None = None,
    probe_local_ports: bool | None = None,
    **extra: object,
) -> dict[str, object]:
    """Correlate passive OTLP/eBPF traces, `.memgraph`/`vmmap` heap, & host port occupancy."""
    root_p = Path(repo_root)
    merged_kw: dict[str, object] = dict(extra)
    if otel_traces_path is not None:
        merged_kw["otel_traces"] = otel_traces_path
    if ebpf_flows_path is not None:
        merged_kw["ebpf_flows"] = ebpf_flows_path
    if memgraph_path is not None:
        merged_kw["memgraph"] = memgraph_path
    if vmmap_path is not None:
        merged_kw["vmmap"] = vmmap_path
    if port_listeners_path is not None:
        merged_kw["port_listeners"] = port_listeners_path
    if probe_local_ports is not None:
        merged_kw["probe_local_ports"] = probe_local_ports

    inputs = get_active_wiretap_inputs(**merged_kw)
    if not inputs.any_active:
        return {
            "plugin": "wiretap",
            "version": "0.1.0",
            "target_slug": getattr(report, "target_slug", "unknown"),
            "source_commit": getattr(report, "source_commit", "unknown"),
            "z0_content_digest": getattr(report, "content_digest", ""),
            "target_code_executed": False,
            "automated_security_audit": False,
            "subprocesses_invoked": 0,
            "non_certification_disclaimer": NON_CERTIFICATION_NOTICE,
            "present": False,
            "redacted_field_count": 0,
            "traces_and_flows": None,
            "heap": {"memgraph": None, "vmmap": None, "by_node": {}},
            "port_occupancy": correlate_port_occupancy(root_p, report),
            "findings": [],
            "explorer_overlay_lens": {
                "lens_key": "wiretap_runtime",
                "mutates_static_verification": False,
                "badges_by_node": {},
            },
            "wall_ties": [],
        }

    bundle = _evaluate_wiretap_bundle(root_p, report, inputs)
    port_occ = bundle["port_occupancy"]
    subprocs = int(port_occ["provenance"]["subprocesses_invoked"])
    badges_map = {
        n.id: [b.model_dump() for b in _badges_for_node(n.id, bundle)]
        for n in getattr(report, "nodes", ())
        if _badges_for_node(n.id, bundle)
    }

    wall_ties: list[dict[str, object]] = []
    default_nid = next(
        (n.id for n in getattr(report, "nodes", ()) if n.tier == "manipulate"),
        "m:wiretap:default",
    )
    for idx, p_ent in enumerate(port_occ["entries"], start=1):
        cls_st = str(p_ent["classification"])
        has_drift = cls_st in ("squatter_conflict", "bind_exposure_drift")
        src_nid = next(
            (d["node_id"] for d in p_ent.get("declared", ()) if d.get("node_id")),
            default_nid,
        )
        wall_ties.append(
            {
                "id": f"wt:wiretap:port:{idx}:{p_ent['port']}",
                "logical_key": f"{p_ent['protocol']}:{p_ent['port']}",
                "source_node_id": src_nid,
                "target_node_id": f"z3:{src_nid}:port:{idx}:{p_ent['port']}",
                "from_wythe": 0,
                "to_wythe": 3,
                "status": "drift" if has_drift else "intact",
                "kind": "plugin_stratum_mismatch" if has_drift else "plugin_stratum_tie",
                "rule_code": p_ent.get("rule_code"),
                "label": f"Z=0->Z=3 port {p_ent['port']}/{p_ent['protocol']} ({cls_st})",
            }
        )

    return {
        "plugin": "wiretap",
        "version": "0.1.0",
        "target_slug": getattr(report, "target_slug", "unknown"),
        "source_commit": getattr(report, "source_commit", "unknown"),
        "z0_content_digest": getattr(report, "content_digest", ""),
        "target_code_executed": False,
        "automated_security_audit": False,
        "subprocesses_invoked": subprocs,
        "non_certification_disclaimer": NON_CERTIFICATION_NOTICE,
        "present": True,
        "redacted_field_count": bundle["redacted_field_count"],
        "traces_and_flows": bundle["traces_and_flows"],
        "heap": {
            "memgraph": bundle["memgraph"],
            "vmmap": bundle["vmmap"],
            "by_node": bundle["heap_by_node"],
        },
        "port_occupancy": port_occ,
        "findings": list(port_occ["findings"]),
        "explorer_overlay_lens": {
            "lens_key": "wiretap_runtime",
            "mutates_static_verification": False,
            "badges_by_node": badges_map,
        },
        "wall_ties": wall_ties,
    }


WIRETAP_PLUGIN = WythePluginSpec(
    name="wiretap",
    kind="stratum_inspector",
    origin="entry_point",
    version="0.1.0",
    description=(
        "Passive Zoom-3 runtime OTLP/eBPF trace correlator, macOS .memgraph/vmmap heap "
        "inspector, and host port occupancy verifier (PORT-001, PORT-002)."
    ),
    enabled_by_default=True,
    supported_zooms=(3,),
    stratum_badge_hook=summarize_wiretap_zoom1_badges,
    stratum_expand_hook=expand_wiretap_zoom3_stratum,
    rules=(PORT_001_RULE, PORT_002_RULE),
    companion_handlers={"wiretap": correlate_wiretap_companions},
)

WYTHE_PLUGIN = WIRETAP_PLUGIN


def register_wythe_plugin() -> WythePluginSpec:
    """Entry-point factory returning `WIRETAP_PLUGIN`."""
    return WIRETAP_PLUGIN
