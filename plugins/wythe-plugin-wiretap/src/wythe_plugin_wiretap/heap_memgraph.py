"""Passive macOS `.memgraph` (`leaks`) Tarjan SCC retain-cycle & `vmmap` region correlator."""

from __future__ import annotations

import json
import math
import re
from collections.abc import Mapping, Sequence
from dataclasses import asdict, dataclass
from pathlib import Path
from typing import Any

from wythe_plugin_wiretap.otel_ebpf import (
    ensure_json_depth_bounded,
    read_bounded_regular_bytes,
)

_MAX_BYTE_SIZE_INT_BITS = 128
_MAX_BYTE_SIZE_DIGITS = 38
_SCI_FLOAT_RE = re.compile(r"^[+-]?(?:[0-9]+(?:\.[0-9]+)?e[+-]?[0-9]+|inf(?:inity)?|nan)$", re.IGNORECASE)
_SIZE_TOKEN_RE = re.compile(r"^([0-9]+(?:\.[0-9]+)?)\s*([BKMGTP]?)(?:i?B)?$", re.IGNORECASE)
_LEAKS_TABLE_ROW_RE = re.compile(
    r"^\s*(\d+)\s+(\d+)\s+[0-9.]+\s+([A-Za-z_][A-Za-z0-9_.:<>]*)(?:\s+\(in\s+([^)]+)\))?\s*$"
)
_LEAKS_EDGE_RE = re.compile(
    r"(0x[0-9a-fA-F]+)\s*(?:\(([^)]+)\))?\s*--([A-Za-z_]*)-->\s*(0x[0-9a-fA-F]+)\s*(?:\(([^)]+)\))?"
)
_QUOTED_BUFFER_RE = re.compile(r'"[^"\r\n]+"')


def _parse_finite_json_float(raw_float: str) -> float:
    val = float(raw_float)
    if not math.isfinite(val):
        raise ValueError("Non-finite float value in heap/vmmap JSON.")
    return val


def _reject_nonfinite_json_const(raw_const: str) -> Any:
    raise ValueError(f"Non-finite JSON constant {raw_const!r} is forbidden.")


def _parse_bounded_json_int(raw_digits: str) -> int:
    s = raw_digits.strip()
    digits = s.removeprefix("-")
    if len(digits) > _MAX_BYTE_SIZE_DIGITS:
        raise ValueError("Oversized integer token in heap/vmmap JSON.")
    return int(s)


def _safe_nonneg_int(raw: object, *, default: int, minimum: int = 0) -> int:
    if raw is None or raw == "":
        return default
    if isinstance(raw, bool):
        return max(minimum, int(raw))
    if isinstance(raw, int):
        if raw.bit_length() > _MAX_BYTE_SIZE_INT_BITS:
            raise ValueError("Integer value exceeds maximum bit length.")
        return max(minimum, raw)
    if isinstance(raw, float):
        if not math.isfinite(raw) or abs(raw) > 1e38:
            raise ValueError("Non-finite or out-of-range numeric value.")
        return max(minimum, int(raw))
    if isinstance(raw, str):
        s = raw.strip()
        if not s:
            return default
        if _SCI_FLOAT_RE.match(s):
            val = float(s)
            if not math.isfinite(val) or abs(val) > 1e38:
                raise ValueError("Non-finite or out-of-range numeric string.")
            return max(minimum, int(val))
        if len(s.lstrip("+-")) > _MAX_BYTE_SIZE_DIGITS:
            raise ValueError("Integer string exceeds maximum digit length.")
        return max(minimum, int(s))
    raise ValueError(f"Expected numeric count, got {type(raw).__name__}.")


def parse_byte_size_token(raw: object) -> int:
    """Parse macOS `vmmap`/`leaks` byte counts (`48.5M`, `512K`, `4096`, `16B`) into integer bytes."""
    if isinstance(raw, float):
        if not math.isfinite(raw) or abs(raw) > 1e38:
            raise ValueError("Non-finite or out-of-range byte size float.")
        return max(0, int(raw))
    if isinstance(raw, int) and not isinstance(raw, bool):
        if raw.bit_length() > _MAX_BYTE_SIZE_INT_BITS:
            raise ValueError("Byte size integer exceeds maximum bit length.")
        return max(0, raw)
    text = str(raw or "").strip().replace(",", "")
    if not text or text in ("-", "0", "0B", "0K"):
        return 0
    if _SCI_FLOAT_RE.match(text):
        val = float(text)
        if not math.isfinite(val) or abs(val) > 1e38:
            raise ValueError("Non-finite or out-of-range byte size token.")
        return max(0, int(val))
    m = _SIZE_TOKEN_RE.match(text)
    if not m:
        return 0
    num_str = m.group(1)
    if len(num_str.split(".", 1)[0]) > _MAX_BYTE_SIZE_DIGITS:
        raise ValueError("Byte size token exceeds maximum digit length.")
    val = float(num_str)
    if not math.isfinite(val):
        raise ValueError("Non-finite byte size token.")
    unit = m.group(2).upper()
    mult = {
        "": 1,
        "B": 1,
        "K": 1024,
        "M": 1024**2,
        "G": 1024**3,
        "T": 1024**4,
        "P": 1024**5,
    }.get(unit, 1)
    scaled = val * mult
    if not math.isfinite(scaled) or scaled > 1e38:
        raise ValueError("Byte size token overflows representable range.")
    return max(0, int(scaled))


@dataclass(frozen=True)
class HeapClassSummary:
    """Aggregated live object allocation counts and bytes for one class/type."""

    class_name: str
    module: str
    instance_count: int
    total_bytes: int


@dataclass(frozen=True)
class HeapGraphNode:
    """Single object node in an exported `.memgraph` / `leaks` reference graph."""

    node_id: str
    class_name: str
    module: str = ""
    size_bytes: int = 0


@dataclass(frozen=True)
class HeapGraphEdge:
    """Directed object reference edge (`strong`, `retain`, `capture`, `weak`, `unowned`)."""

    source_id: str
    target_id: str
    reference_kind: str = "strong"


@dataclass(frozen=True)
class RetainCycleScc:
    """Tarjan strongly connected component representing a strong retain cycle."""

    cycle_id: str
    member_ids: tuple[str, ...]
    class_names: tuple[str, ...]
    modules: tuple[str, ...]
    retained_bytes: int


@dataclass(frozen=True)
class VmmapRegionRecord:
    """Parsed `vmmap` region summary (`MALLOC_*`, `IOAccelerator`/Metal, `__DATA_DIRTY`)."""

    region_type: str
    category: str
    module: str
    virtual_bytes: int
    resident_bytes: int
    dirty_bytes: int
    wired_bytes: int
    swapped_bytes: int
    region_count: int = 1


def find_retain_cycle_sccs(
    nodes: Sequence[HeapGraphNode],
    edges: Sequence[HeapGraphEdge],
) -> list[RetainCycleScc]:
    """Iterative Tarjan SCC pass over strong/retain heap edges (zero call-stack recursion)."""
    node_map: dict[str, HeapGraphNode] = {n.node_id: n for n in nodes}
    adj: dict[str, list[str]] = {n.node_id: [] for n in nodes}
    self_loops: set[str] = set()

    for edge in edges:
        if edge.reference_kind.lower() in ("weak", "unowned"):
            continue
        node_map.setdefault(edge.source_id, HeapGraphNode(node_id=edge.source_id, class_name=edge.source_id))
        node_map.setdefault(edge.target_id, HeapGraphNode(node_id=edge.target_id, class_name=edge.target_id))
        adj.setdefault(edge.source_id, []).append(edge.target_id)
        adj.setdefault(edge.target_id, [])
        if edge.source_id == edge.target_id:
            self_loops.add(edge.source_id)

    index_counter = 0
    disc: dict[str, int] = {}
    low: dict[str, int] = {}
    stack: list[str] = []
    on_stack: set[str] = set()
    cycles: list[RetainCycleScc] = []

    for root_id in sorted(node_map):
        if root_id in disc:
            continue
        disc[root_id] = index_counter
        low[root_id] = index_counter
        index_counter += 1
        stack.append(root_id)
        on_stack.add(root_id)
        work: list[tuple[str, int]] = [(root_id, 0)]

        while work:
            u, idx = work[-1]
            nbrs = adj.get(u, ())
            if idx < len(nbrs):
                work[-1] = (u, idx + 1)
                v = nbrs[idx]
                if v not in disc:
                    disc[v] = index_counter
                    low[v] = index_counter
                    index_counter += 1
                    stack.append(v)
                    on_stack.add(v)
                    work.append((v, 0))
                elif v in on_stack and disc[v] < low[u]:
                    low[u] = disc[v]
            else:
                work.pop()
                if work:
                    parent = work[-1][0]
                    low[parent] = min(low[parent], low[u])
                if low[u] == disc[u]:
                    comp: list[str] = []
                    while True:
                        w = stack.pop()
                        on_stack.discard(w)
                        comp.append(w)
                        if w == u:
                            break
                    if len(comp) >= 2 or (len(comp) == 1 and comp[0] in self_loops):
                        members_sorted = tuple(sorted(comp))
                        cls_names = tuple(
                            dict.fromkeys(node_map[m].class_name for m in members_sorted)
                        )
                        mods = tuple(
                            sorted({node_map[m].module for m in members_sorted if node_map[m].module})
                        )
                        ret_bytes = sum(node_map[m].size_bytes for m in members_sorted)
                        cycles.append(
                            RetainCycleScc(
                                cycle_id=f"scc:{len(cycles) + 1}:{members_sorted[0]}",
                                member_ids=members_sorted,
                                class_names=cls_names,
                                modules=mods,
                                retained_bytes=ret_bytes,
                            )
                        )

    cycles.sort(key=lambda c: (-c.retained_bytes, c.member_ids))
    return cycles


def _infer_module_from_class(class_name: str, explicit_mod: str = "") -> str:
    if explicit_mod.strip():
        return explicit_mod.strip()
    if "." in class_name:
        return class_name.split(".", 1)[0]
    if "::" in class_name:
        return class_name.split("::", 1)[0]
    return ""


def parse_memgraph_artifact(
    raw_path: Path | str,
    *,
    repo_root: Path | None = None,
    allow_external: bool = False,
) -> dict[str, object]:
    """Passively parse a recorded `.memgraph` / `leaks` JSON or text summary (redacting buffers)."""
    resolved, raw_bytes = read_bounded_regular_bytes(
        raw_path, repo_root=repo_root, allow_external=allow_external
    )
    if raw_bytes.startswith(b"bplist"):
        raise ValueError(
            f"Binary plist memgraph '{resolved.name}' requires exported text/JSON summary; "
            "Wythe never attaches native debuggers to untrusted heap archives."
        )
    text = raw_bytes.decode("utf-8-sig")
    if "\x00" in text:
        raise ValueError(f"Refusing memgraph artifact '{raw_path}' containing embedded NUL bytes.")

    classes: list[HeapClassSummary] = []
    graph_nodes: list[HeapGraphNode] = []
    graph_edges: list[HeapGraphEdge] = []
    redacted_buffers = 0

    stripped = text.lstrip()
    if stripped.startswith("{"):
        ensure_json_depth_bounded(stripped)
        data = json.loads(
            stripped,
            parse_float=_parse_finite_json_float,
            parse_constant=_reject_nonfinite_json_const,
            parse_int=_parse_bounded_json_int,
        )
        if not isinstance(data, Mapping):
            raise ValueError("Memgraph JSON root must be an object.")
        raw_classes = data.get("classes")
        if raw_classes is None or raw_classes == []:
            raw_allocs = data.get("allocations")
            if raw_allocs is not None:
                raw_classes = raw_allocs
        if raw_classes is None:
            raw_classes = []
        if not isinstance(raw_classes, list):
            raise ValueError("Memgraph JSON 'classes'/'allocations' field must be a list.")
        for cls_item in raw_classes:
            if not isinstance(cls_item, Mapping):
                continue
            if any(k in cls_item for k in ("raw_buffer", "string_preview", "bytes_hex", "payload")):
                redacted_buffers += 1
            cname = str(cls_item.get("class_name") or cls_item.get("type") or "Object")
            mod = _infer_module_from_class(cname, str(cls_item.get("module") or cls_item.get("binary") or ""))
            cnt = _safe_nonneg_int(
                cls_item.get("instance_count") or cls_item.get("count"),
                default=1,
                minimum=0,
            )
            tot_b = parse_byte_size_token(cls_item.get("total_bytes") or cls_item.get("bytes") or cls_item.get("size") or 0)
            classes.append(HeapClassSummary(class_name=cname, module=mod, instance_count=cnt, total_bytes=tot_b))

        raw_nodes = data.get("nodes", [])
        if raw_nodes is None:
            raw_nodes = []
        if not isinstance(raw_nodes, list):
            raise ValueError("Memgraph JSON 'nodes' field must be a list.")
        for n_item in raw_nodes:
            if not isinstance(n_item, Mapping):
                continue
            if any(k in n_item for k in ("raw_buffer", "string_preview", "string_value", "contents")):
                redacted_buffers += 1
            nid = str(n_item.get("id") or n_item.get("address") or "")
            cname = str(n_item.get("class_name") or n_item.get("type") or nid or "Object")
            mod = _infer_module_from_class(cname, str(n_item.get("module") or ""))
            sz = parse_byte_size_token(n_item.get("size_bytes") or n_item.get("size") or n_item.get("bytes") or 0)
            if nid:
                graph_nodes.append(HeapGraphNode(node_id=nid, class_name=cname, module=mod, size_bytes=sz))

        raw_edges = data.get("edges")
        if raw_edges is None or raw_edges == []:
            raw_refs = data.get("references")
            if raw_refs is not None:
                raw_edges = raw_refs
        if raw_edges is None:
            raw_edges = []
        if not isinstance(raw_edges, list):
            raise ValueError("Memgraph JSON 'edges'/'references' field must be a list.")
        for e_item in raw_edges:
            if not isinstance(e_item, Mapping):
                continue
            src = str(e_item.get("source") or e_item.get("source_id") or e_item.get("from") or "")
            tgt = str(e_item.get("target") or e_item.get("target_id") or e_item.get("to") or "")
            kind = str(e_item.get("kind") or e_item.get("reference_kind") or "strong")
            if src and tgt:
                graph_edges.append(HeapGraphEdge(source_id=src, target_id=tgt, reference_kind=kind))
    else:
        seen_nodes: dict[str, HeapGraphNode] = {}
        for raw_line in text.splitlines()[:32768]:
            if '"' in raw_line and _QUOTED_BUFFER_RE.search(raw_line):
                redacted_buffers += 1
                raw_line = _QUOTED_BUFFER_RE.sub('"[REDACTED_HEAP_STRING]"', raw_line)
            m_row = _LEAKS_TABLE_ROW_RE.match(raw_line)
            if m_row:
                cnt = _safe_nonneg_int(m_row.group(1), default=0, minimum=0)
                tot_b = _safe_nonneg_int(m_row.group(2), default=0, minimum=0)
                cname = m_row.group(3)
                mod = _infer_module_from_class(cname, m_row.group(4) or "")
                classes.append(
                    HeapClassSummary(
                        class_name=cname, module=mod, instance_count=cnt, total_bytes=tot_b
                    )
                )
                continue
            m_edge = _LEAKS_EDGE_RE.search(raw_line)
            if m_edge:
                src_addr, src_cls, ref_k, tgt_addr, tgt_cls = m_edge.groups()
                s_cls = (src_cls or src_addr).strip()
                t_cls = (tgt_cls or tgt_addr).strip()
                seen_nodes.setdefault(
                    src_addr,
                    HeapGraphNode(
                        node_id=src_addr,
                        class_name=s_cls,
                        module=_infer_module_from_class(s_cls),
                        size_bytes=64,
                    ),
                )
                seen_nodes.setdefault(
                    tgt_addr,
                    HeapGraphNode(
                        node_id=tgt_addr,
                        class_name=t_cls,
                        module=_infer_module_from_class(t_cls),
                        size_bytes=64,
                    ),
                )
                graph_edges.append(
                    HeapGraphEdge(
                        source_id=src_addr,
                        target_id=tgt_addr,
                        reference_kind=ref_k or "strong",
                    )
                )
        graph_nodes.extend(seen_nodes.values())

    if not classes and graph_nodes:
        agg: dict[tuple[str, str], tuple[int, int]] = {}
        for gn in graph_nodes:
            key = (gn.class_name, gn.module)
            c_prev, b_prev = agg.get(key, (0, 0))
            agg[key] = (c_prev + 1, b_prev + gn.size_bytes)
        for (cname, mod), (cnt, tot_b) in sorted(agg.items()):
            classes.append(
                HeapClassSummary(class_name=cname, module=mod, instance_count=cnt, total_bytes=tot_b)
            )

    cycles = find_retain_cycle_sccs(graph_nodes, graph_edges)
    return {
        "path": str(resolved),
        "live_instance_count": sum(c.instance_count for c in classes),
        "live_heap_bytes": sum(c.total_bytes for c in classes),
        "class_count": len(classes),
        "retain_cycle_count": len(cycles),
        "redacted_heap_buffers": redacted_buffers,
        "classes": [asdict(c) for c in classes],
        "retain_cycles": [asdict(cy) for cy in cycles],
    }


def _categorize_vmmap_region(region_type: str) -> str:
    up = region_type.upper()
    if up.startswith("MALLOC"):
        return "malloc_heap"
    if "IOACCELERATOR" in up or "METAL" in up or "IOSURFACE" in up:
        return "gpu_metal_ioaccelerator"
    if "__DATA_DIRTY" in up or up == "__DATA":
        return "data_dirty"
    if "STACK" in up:
        return "stack"
    return "other"


def parse_vmmap_artifact(
    raw_path: Path | str,
    *,
    repo_root: Path | None = None,
    allow_external: bool = False,
) -> dict[str, object]:
    """Passively parse a recorded `vmmap` JSON or text region summary table."""
    resolved, raw_bytes = read_bounded_regular_bytes(
        raw_path, repo_root=repo_root, allow_external=allow_external
    )
    text = raw_bytes.decode("utf-8-sig")
    if "\x00" in text:
        raise ValueError(f"Refusing vmmap artifact '{raw_path}' containing embedded NUL bytes.")

    regions: list[VmmapRegionRecord] = []
    stripped = text.lstrip()
    if stripped.startswith(("{", "[")):
        ensure_json_depth_bounded(stripped)
        data = json.loads(
            stripped,
            parse_float=_parse_finite_json_float,
            parse_constant=_reject_nonfinite_json_const,
            parse_int=_parse_bounded_json_int,
        )
        raw_list = data.get("regions", []) if isinstance(data, Mapping) else data
        if raw_list is None:
            raw_list = []
        if not isinstance(raw_list, list):
            raise ValueError("vmmap JSON must contain a regions list.")
        for item in raw_list:
            if not isinstance(item, Mapping):
                continue
            rtype = str(item.get("region_type") or item.get("type") or "UNKNOWN").strip()
            regions.append(
                VmmapRegionRecord(
                    region_type=rtype,
                    category=_categorize_vmmap_region(rtype),
                    module=str(item.get("module") or item.get("binary") or "").strip(),
                    virtual_bytes=parse_byte_size_token(item.get("virtual_bytes") or item.get("virtual") or 0),
                    resident_bytes=parse_byte_size_token(item.get("resident_bytes") or item.get("resident") or 0),
                    dirty_bytes=parse_byte_size_token(item.get("dirty_bytes") or item.get("dirty") or 0),
                    wired_bytes=parse_byte_size_token(item.get("wired_bytes") or item.get("wired") or 0),
                    swapped_bytes=parse_byte_size_token(item.get("swapped_bytes") or item.get("swapped") or 0),
                    region_count=_safe_nonneg_int(
                        item.get("region_count") or item.get("count"),
                        default=1,
                        minimum=1,
                    ),
                )
            )
    else:
        for raw_line in text.splitlines()[:16384]:
            s = raw_line.strip()
            if not s or s.startswith(("REGION TYPE", "====", "----", "Process:", "Physical")):
                continue
            tokens = s.split()
            if len(tokens) < 4:
                continue
            # Match summary table row: `<REGION_TYPE> <VIRTUAL> <RESIDENT> <DIRTY> [SWAPPED/WIRED] ... [MODULE]`
            size_idxs = [i for i, tok in enumerate(tokens) if i > 0 and _SIZE_TOKEN_RE.match(tok)]
            if len(size_idxs) >= 3 and size_idxs[0] <= 3:
                first_sz = size_idxs[0]
                rtype = " ".join(tokens[:first_sz])
                if rtype.upper() == "TOTAL":
                    continue
                virt_b = parse_byte_size_token(tokens[size_idxs[0]])
                res_b = parse_byte_size_token(tokens[size_idxs[1]])
                dirty_b = parse_byte_size_token(tokens[size_idxs[2]])
                swap_b = parse_byte_size_token(tokens[size_idxs[3]]) if len(size_idxs) >= 4 else 0
                wired_b = parse_byte_size_token(tokens[size_idxs[4]]) if len(size_idxs) >= 5 else 0
                tail_tok = tokens[-1]
                mod = Path(tail_tok).stem if ("/" in tail_tok or not tail_tok[0].isdigit()) and tail_tok != rtype else ""
                regions.append(
                    VmmapRegionRecord(
                        region_type=rtype,
                        category=_categorize_vmmap_region(rtype),
                        module=mod,
                        virtual_bytes=virt_b,
                        resident_bytes=res_b,
                        dirty_bytes=dirty_b,
                        wired_bytes=wired_b,
                        swapped_bytes=swap_b,
                    )
                )

    return {
        "path": str(resolved),
        "region_count": len(regions),
        "total_dirty_bytes": sum(r.dirty_bytes for r in regions),
        "total_wired_bytes": sum(r.wired_bytes for r in regions),
        "total_resident_bytes": sum(r.resident_bytes for r in regions),
        "malloc_dirty_bytes": sum(r.dirty_bytes for r in regions if r.category == "malloc_heap"),
        "metal_ioaccelerator_dirty_bytes": sum(
            r.dirty_bytes for r in regions if r.category == "gpu_metal_ioaccelerator"
        ),
        "data_dirty_bytes": sum(r.dirty_bytes for r in regions if r.category == "data_dirty"),
        "regions": [asdict(r) for r in regions],
    }


def _norm_ident(raw: str) -> str:
    return re.sub(r"[^a-z0-9]+", "", raw.lower())


def attribute_heap_to_nodes(
    report: Any,
    memgraph_summary: Mapping[str, Any] | None,
    vmmap_summary: Mapping[str, Any] | None,
) -> dict[str, dict[str, Any]]:
    """Attribute `.memgraph` classes, Tarjan retain cycles, and `vmmap` regions to `AtlasNode`s."""
    nodes = list(getattr(report, "nodes", ()))
    manip_nodes = [n for n in nodes if n.tier == "manipulate"]
    fallback_nid = manip_nodes[0].id if manip_nodes else (nodes[0].id if nodes else "")

    def _match_node_id(*hints: str) -> str:
        norm_hints = [_norm_ident(h) for h in hints if _norm_ident(h)]
        for n in manip_nodes + nodes:
            stem_n = _norm_ident(Path(n.source_file).stem)
            lbl_n = _norm_ident(n.label)
            for nh in norm_hints:
                if len(nh) >= 3 and (
                    (stem_n and (nh in stem_n or stem_n in nh))
                    or (lbl_n and len(lbl_n) >= 3 and (nh in lbl_n or lbl_n in nh))
                ):
                    return n.id
        return fallback_nid

    by_node: dict[str, dict[str, Any]] = {}

    def _bucket(nid: str) -> dict[str, Any]:
        return by_node.setdefault(
            nid,
            {
                "live_instances": 0,
                "live_heap_bytes": 0,
                "dirty_bytes": 0,
                "wired_bytes": 0,
                "classes": [],
                "retain_cycles": [],
                "vmmap_regions": [],
            },
        )

    if memgraph_summary:
        for cls_d in memgraph_summary.get("classes", []):
            nid = _match_node_id(str(cls_d.get("module") or ""), str(cls_d.get("class_name") or ""))
            if nid:
                b = _bucket(nid)
                b["live_instances"] += int(cls_d.get("instance_count", 0))
                b["live_heap_bytes"] += int(cls_d.get("total_bytes", 0))
                b["classes"].append(cls_d)
        for cyc_d in memgraph_summary.get("retain_cycles", []):
            hints = [*(cyc_d.get("modules") or ()), *(cyc_d.get("class_names") or ())]
            nid = _match_node_id(*(str(h) for h in hints))
            if nid:
                _bucket(nid)["retain_cycles"].append(cyc_d)

    if vmmap_summary:
        for reg_d in vmmap_summary.get("regions", []):
            nid = _match_node_id(str(reg_d.get("module") or ""), str(reg_d.get("region_type") or ""))
            if nid:
                b = _bucket(nid)
                b["dirty_bytes"] += int(reg_d.get("dirty_bytes", 0))
                b["wired_bytes"] += int(reg_d.get("wired_bytes", 0))
                b["vmmap_regions"].append(reg_d)

    return by_node
