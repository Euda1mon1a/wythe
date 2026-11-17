"""OpenLineage Static Lineage exporter and crate-stage security artifact correlator.

All functions in this module are deterministic, read-only, and non-executing:
- `build_openlineage_static_bundle(report)` adapts a `TruthAtlasReport` into a static
  OpenLineage JSON document (`producer`, `schemaURL`, `datasets`, `jobs`).
- `summarize_companion_security_artifacts(report, trivy_path, syft_path)` correlates
  Wythe blueprint-stage findings (`TRUTH-003`, `DISP-001`, `TRUTH-001`, `MANIP-004..006`)
  with optional read-only `Trivy` (JSON/SARIF) and `Syft` (CycloneDX/SPDX) artifacts
  for Blue / Red / Purple team handoffs while preserving `SECURITY.md` non-certification.
"""

from __future__ import annotations

import json
from collections import deque
from pathlib import Path
from typing import Any

from app.schemas.atlas import AtlasEdge, AtlasNode, BoundaryFinding, TruthAtlasReport
from app.services.llm_context_service import _parse_symbol_pairs

OPENLINEAGE_PRODUCER = "https://github.com/Euda1mon1a/wythe"
OPENLINEAGE_SPEC_URL = "https://openlineage.io/spec/2-0-2/OpenLineage.json"
SCHEMA_FACET_URL = "https://openlineage.io/spec/facets/1-1-1/SchemaDatasetFacet.json"
DOC_FACET_URL = "https://openlineage.io/spec/facets/1-0-1/DocumentationDatasetFacet.json"
SOURCE_LOCATION_FACET_URL = (
    "https://openlineage.io/spec/facets/1-1-0/SourceCodeLocationJobFacet.json"
)
JOB_TYPE_FACET_URL = "https://openlineage.io/spec/facets/2-0-3/JobTypeJobFacet.json"

MAX_COMPANION_BYTES = 32 * 1024 * 1024  # 32 MiB bounded read ceiling for SBOM/CVE JSON
NON_CERTIFICATION_NOTICE = (
    "Bounded static architecture and companion artifact evidence only — NOT an automated "
    "security audit, taint proof, exploitability verdict, or authentication/authorization "
    "certification (see SECURITY.md). Target code was never executed."
)


def _file_uri(repo_path: str, rel_file: str, line: int) -> str:
    clean_repo = repo_path.rstrip("/")
    clean_rel = rel_file.lstrip("/")
    return f"file://{clean_repo}/{clean_rel}#L{max(line, 1)}"


def _parse_column_field(raw_col: str) -> dict[str, str]:
    text = raw_col.strip()
    if ":" in text:
        col_name, _, col_type = text.partition(":")
        return {"name": col_name.strip(), "type": col_type.strip() or "unknown"}
    parts = text.split(None, 1)
    if len(parts) == 2:
        return {"name": parts[0].strip(), "type": parts[1].strip()}
    return {"name": text, "type": "unknown"}


def _source_location_facet(
    repo_path: str,
    source_file: str,
    line: int,
    commit: str,
) -> dict[str, object]:
    return {
        "_producer": OPENLINEAGE_PRODUCER,
        "_schemaURL": SOURCE_LOCATION_FACET_URL,
        "type": "git",
        "url": _file_uri(repo_path, source_file, line),
        "path": source_file,
        "line": line,
        "version": commit,
    }


def _dataset_namespace_kind(subkind: str) -> str:
    if subkind == "cache_store":
        return "cache"
    if subkind == "entity_store":
        return "entity_store"
    if subkind == "entitlement_spec":
        return "entitlement_spec"
    return "sql"


def build_openlineage_static_bundle(report: TruthAtlasReport) -> dict[str, object]:
    """Build a deterministic OpenLineage Static Lineage JSON bundle from `report`."""
    node_by_id: dict[str, AtlasNode] = {n.id: n for n in report.nodes}
    dataset_nodes = sorted(
        (
            n
            for n in report.nodes
            if n.tier == "truth"
            and n.subkind in ("table", "cache_store", "entity_store", "entitlement_spec")
        ),
        key=lambda n: (n.subkind, n.label, n.id),
    )

    label_counts: dict[tuple[str, str], int] = {}
    for dn in dataset_nodes:
        ns_kind = _dataset_namespace_kind(dn.subkind)
        label_counts[(ns_kind, dn.label)] = label_counts.get((ns_kind, dn.label), 0) + 1

    dataset_ref_by_id: dict[str, dict[str, str]] = {}
    datasets_out: list[dict[str, object]] = []
    for dn in dataset_nodes:
        ns_kind = _dataset_namespace_kind(dn.subkind)
        namespace = f"wythe://{report.target_slug}/{ns_kind}"
        ds_name = dn.label if label_counts[(ns_kind, dn.label)] == 1 else f"{dn.label}:{dn.id}"
        dataset_ref_by_id[dn.id] = {"namespace": namespace, "name": ds_name}
        datasets_out.append(
            {
                "namespace": namespace,
                "name": ds_name,
                "facets": {
                    "schema": {
                        "_producer": OPENLINEAGE_PRODUCER,
                        "_schemaURL": SCHEMA_FACET_URL,
                        "fields": [_parse_column_field(c) for c in dn.columns],
                    },
                    "sourceCodeLocation": _source_location_facet(
                        report.repo_path, dn.source_file, dn.line, report.source_commit
                    ),
                    "documentation": {
                        "_producer": OPENLINEAGE_PRODUCER,
                        "_schemaURL": DOC_FACET_URL,
                        "description": dn.summary,
                    },
                    "wytheDataset": {
                        "_producer": OPENLINEAGE_PRODUCER,
                        "_schemaURL": OPENLINEAGE_SPEC_URL,
                        "nodeId": dn.id,
                        "subkind": dn.subkind,
                        "status": dn.status,
                        "readByCount": dn.read_by_count,
                        "writtenByCount": dn.written_by_count,
                        "staticAnalysisOnly": True,
                    },
                },
            }
        )

    read_edges_by_src: dict[str, list[tuple[AtlasEdge, str]]] = {}
    write_edges_by_src: dict[str, list[tuple[AtlasEdge, str]]] = {}
    prop_edges_by_src: dict[str, list[tuple[AtlasEdge, str]]] = {}
    nodes_with_scoped_out_edges: set[str] = set()
    container_custom_cmd_sources = {
        e.source_id
        for e in report.edges
        if e.id.startswith(("e:compose:", "e:k8s:"))
        and "->dockerfile:" not in e.id
        and "->svc:" not in e.id
        and "->cm:" not in e.id
    }

    for edge in report.edges:
        if _parse_symbol_pairs(edge.symbol_links):
            nodes_with_scoped_out_edges.add(edge.source_id)
        tgt = node_by_id.get(edge.target_id)
        is_sql_fn = tgt is not None and tgt.subkind == "sql_function"
        if edge.kind in ("reads_truth", "guards_truth"):
            if edge.target_id in dataset_ref_by_id:
                read_edges_by_src.setdefault(edge.source_id, []).append((edge, edge.target_id))
            elif is_sql_fn:
                prop_edges_by_src.setdefault(edge.source_id, []).append((edge, edge.target_id))
        elif edge.kind == "writes_truth":
            if edge.target_id in dataset_ref_by_id:
                write_edges_by_src.setdefault(edge.source_id, []).append((edge, edge.target_id))
            elif is_sql_fn:
                prop_edges_by_src.setdefault(edge.source_id, []).append((edge, edge.target_id))
        elif edge.kind == "calls_helper" and edge.verification in ("verified", "declared"):
            if edge.id.startswith("e:deployment:"):
                continue
            if edge.id.startswith(("e:compose:", "e:k8s:")) and (
                "->svc:" in edge.id
                or "->cm:" in edge.id
                or ("->dockerfile:" in edge.id and edge.source_id in container_custom_cmd_sources)
            ):
                continue
            prop_edges_by_src.setdefault(edge.source_id, []).append((edge, edge.target_id))
        elif (
            edge.kind in ("queries_endpoint", "mutates_endpoint", "uses_client")
            and edge.verification in ("verified", "declared")
        ):
            src_n = node_by_id.get(edge.source_id)
            if src_n is not None and (
                (src_n.tier == "display" and src_n.subkind == "cli")
                or (src_n.tier == "manipulate" and tgt is not None and tgt.tier == "manipulate")
            ):
                prop_edges_by_src.setdefault(edge.source_id, []).append((edge, edge.target_id))

    for src_id, edge_list in prop_edges_by_src.items():
        prop_edges_by_src[src_id] = sorted(edge_list, key=lambda item: (item[1], item[0].id))

    def _active_closure(start_id: str, seed_syms: set[str] | None = None) -> dict[str, set[str]]:
        init = set(seed_syms) if seed_syms else {"*"}
        active_syms: dict[str, set[str]] = {start_id: init}
        q: deque[str] = deque([start_id])
        while q:
            cur = q.popleft()
            cur_syms = active_syms[cur]
            eff_syms = cur_syms if cur in nodes_with_scoped_out_edges else {"*"}
            for edge, nxt in prop_edges_by_src.get(cur, ()):
                pairs = _parse_symbol_pairs(edge.symbol_links)
                if pairs:
                    next_syms = {
                        callee
                        for caller, callee in pairs
                        if "*" in eff_syms or caller == "*" or caller in eff_syms
                    }
                    if not next_syms:
                        continue
                else:
                    if "*" not in eff_syms:
                        continue
                    next_syms = {"*"}
                prev_nxt = active_syms.get(nxt)
                if prev_nxt is None:
                    if len(active_syms) >= 512:
                        continue
                    active_syms[nxt] = set(next_syms)
                    q.append(nxt)
                else:
                    added = next_syms - prev_nxt
                    if added:
                        prev_nxt.update(added)
                        q.append(nxt)
        return active_syms

    def _truth_edge_active(src_id: str, edge: AtlasEdge, cur_syms: set[str]) -> bool:
        if "*" in cur_syms or src_id not in nodes_with_scoped_out_edges:
            return True
        pairs = _parse_symbol_pairs(edge.symbol_links)
        if not pairs:
            return False
        return any(caller == "*" or caller in cur_syms for caller, _ in pairs)

    def _refs_for(ids: set[str]) -> list[dict[str, str]]:
        return sorted(
            (dataset_ref_by_id[i] for i in ids if i in dataset_ref_by_id),
            key=lambda r: (r["namespace"], r["name"]),
        )

    jobs_out: list[dict[str, object]] = []
    manip_nodes = sorted(
        (n for n in report.nodes if n.tier == "manipulate"),
        key=lambda n: (n.subkind, n.id),
    )
    display_cli_nodes = sorted(
        (n for n in report.nodes if n.tier == "display" and n.subkind == "cli"),
        key=lambda n: (n.subkind, n.id),
    )
    cli_out_kinds: dict[str, set[str]] = {}
    for edge in report.edges:
        if edge.verification in ("verified", "declared"):
            cli_out_kinds.setdefault(edge.source_id, set()).add(edge.kind)

    for mn in (*manip_nodes, *display_cli_nodes):
        reached = _active_closure(mn.id)
        r_ids: set[str] = set()
        w_ids: set[str] = set()
        is_readonly_http = (
            mn.subkind == "route"
            and bool(mn.http_methods)
            and all(m in ("GET", "HEAD", "OPTIONS") for m in mn.http_methods)
        ) or (
            mn.tier == "display"
            and mn.subkind == "cli"
            and "queries_endpoint" in cli_out_kinds.get(mn.id, set())
            and "mutates_endpoint" not in cli_out_kinds.get(mn.id, set())
        )
        for nid, cur_syms in reached.items():
            for edge, ds_id in read_edges_by_src.get(nid, ()):
                if _truth_edge_active(nid, edge, cur_syms):
                    r_ids.add(ds_id)
            nid_node = node_by_id.get(nid)
            is_sql_fn_node = nid_node is not None and nid_node.subkind == "sql_function"
            if nid == mn.id or not is_readonly_http or is_sql_fn_node:
                for edge, ds_id in write_edges_by_src.get(nid, ()):
                    if _truth_edge_active(nid, edge, cur_syms):
                        w_ids.add(ds_id)
        job_ns_tier = "display" if mn.tier == "display" else "manipulate"
        jobs_out.append(
            {
                "namespace": f"wythe://{report.target_slug}/{job_ns_tier}",
                "name": mn.id,
                "inputs": _refs_for(r_ids),
                "outputs": _refs_for(w_ids),
                "facets": {
                    "jobType": {
                        "_producer": OPENLINEAGE_PRODUCER,
                        "_schemaURL": JOB_TYPE_FACET_URL,
                        "processingType": "NONE",
                        "integration": "WYTHE_STATIC",
                        "jobType": mn.subkind.upper(),
                    },
                    "sourceCodeLocation": _source_location_facet(
                        report.repo_path, mn.source_file, mn.line, report.source_commit
                    ),
                    "documentation": {
                        "_producer": OPENLINEAGE_PRODUCER,
                        "_schemaURL": DOC_FACET_URL,
                        "description": f"{mn.label}: {mn.summary}",
                    },
                    "wytheJob": {
                        "_producer": OPENLINEAGE_PRODUCER,
                        "_schemaURL": OPENLINEAGE_SPEC_URL,
                        "nodeId": mn.id,
                        "label": mn.label,
                        "subkind": mn.subkind,
                        "cluster": mn.cluster,
                        "httpMethods": list(mn.http_methods),
                        "httpPaths": list(mn.http_paths),
                        "staticAnalysisOnly": True,
                    },
                },
            }
        )

    for chain in sorted(report.chains, key=lambda c: c.id):
        actors = {chain.route_node_id, *chain.manipulator_node_ids}
        chain_tbl_set = set(chain.truth_table_ids)
        route_key = f"{chain.http_method} {chain.http_path}"
        route_out_edges = [
            *prop_edges_by_src.get(chain.route_node_id, ()),
            *read_edges_by_src.get(chain.route_node_id, ()),
            *write_edges_by_src.get(chain.route_node_id, ()),
        ]
        has_route_scope = any(
            caller == route_key
            for edge, _ in route_out_edges
            for caller, _ in _parse_symbol_pairs(edge.symbol_links)
        )
        chain_reached = _active_closure(
            chain.route_node_id,
            {route_key} if has_route_scope else {"*"},
        )
        actor_r: set[str] = set()
        actor_w: set[str] = set()
        for nid, cur_syms in chain_reached.items():
            nid_node = node_by_id.get(nid)
            if nid not in actors and not (nid_node is not None and nid_node.subkind == "sql_function"):
                continue
            for edge, ds_id in read_edges_by_src.get(nid, ()):
                if ds_id in chain_tbl_set and _truth_edge_active(nid, edge, cur_syms):
                    actor_r.add(ds_id)
            for edge, ds_id in write_edges_by_src.get(nid, ()):
                if ds_id in chain_tbl_set and _truth_edge_active(nid, edge, cur_syms):
                    actor_w.add(ds_id)
        if chain.operation == "read":
            c_in = actor_r or chain_tbl_set
            c_out: set[str] = set()
        else:
            c_in = actor_r
            c_out = actor_w or (chain_tbl_set - actor_r) or chain_tbl_set

        anchor_node = node_by_id.get(chain.route_node_id) or node_by_id.get(chain.display_node_id)
        src_file = anchor_node.source_file if anchor_node else ""
        src_line = anchor_node.line if anchor_node else 1
        jobs_out.append(
            {
                "namespace": f"wythe://{report.target_slug}/chains",
                "name": f"{chain.id}:{chain.http_method}:{chain.http_path}",
                "inputs": _refs_for(c_in),
                "outputs": _refs_for(c_out),
                "facets": {
                    "jobType": {
                        "_producer": OPENLINEAGE_PRODUCER,
                        "_schemaURL": JOB_TYPE_FACET_URL,
                        "processingType": "NONE",
                        "integration": "WYTHE_STATIC",
                        "jobType": "E2E_CHAIN",
                    },
                    "sourceCodeLocation": _source_location_facet(
                        report.repo_path, src_file, src_line, report.source_commit
                    ),
                    "documentation": {
                        "_producer": OPENLINEAGE_PRODUCER,
                        "_schemaURL": DOC_FACET_URL,
                        "description": (
                            f"{chain.display_label} -> {chain.http_method} {chain.http_path} "
                            f"({chain.operation})"
                        ),
                    },
                    "wytheChain": {
                        "_producer": OPENLINEAGE_PRODUCER,
                        "_schemaURL": OPENLINEAGE_SPEC_URL,
                        "chainId": chain.id,
                        "displayNodeId": chain.display_node_id,
                        "routeNodeId": chain.route_node_id,
                        "viaNodeIds": list(chain.via_node_ids),
                        "manipulatorNodeIds": list(chain.manipulator_node_ids),
                        "httpMethod": chain.http_method,
                        "httpPath": chain.http_path,
                        "operation": chain.operation,
                        "verified": chain.verified,
                        "staticAnalysisOnly": True,
                    },
                },
            }
        )

    return {
        "producer": OPENLINEAGE_PRODUCER,
        "schemaURL": OPENLINEAGE_SPEC_URL,
        "bundleType": "openlineage_static_lineage",
        "eventTime": report.observed_at.isoformat(),
        "target": {
            "slug": report.target_slug,
            "name": report.target_name,
            "stackProfile": report.stack_profile,
            "sourceCommit": report.source_commit,
            "contentDigest": report.content_digest,
            "observationSource": report.observation_source,
        },
        "datasets": datasets_out,
        "jobs": jobs_out,
        "nonCertificationNotice": NON_CERTIFICATION_NOTICE,
    }


def _read_bounded_json(path_arg: Path | str) -> tuple[str, Any]:
    target = Path(path_arg)
    if target.is_symlink() or not target.is_file():
        raise ValueError(f"Companion artifact '{target}' must be an existing regular file.")
    size = target.stat().st_size
    if size > MAX_COMPANION_BYTES:
        raise ValueError(
            f"Companion artifact '{target}' ({size} bytes) exceeds bounded read limit."
        )
    payload = json.loads(target.read_text(encoding="utf-8-sig"))
    return str(target), payload


def _ecosystem_from_purl(purl: str | None) -> str:
    if not purl or not purl.startswith("pkg:"):
        return "unknown"
    body = purl[4:]
    eco, _, _ = body.partition("/")
    return eco.strip().lower() or "unknown"


def _parse_syft_sbom(path_arg: Path | str) -> dict[str, object]:
    resolved_str, data = _read_bounded_json(path_arg)
    if not isinstance(data, dict):
        raise TypeError("Syft SBOM JSON root must be an object.")

    components: list[tuple[str, str, str]] = []
    if data.get("bomFormat") == "CycloneDX" or isinstance(data.get("components"), list):
        sbom_format = "cyclonedx"
        for comp in data.get("components", []):
            if not isinstance(comp, dict):
                continue
            name = str(comp.get("name", "")).strip()
            if not name:
                continue
            version = str(comp.get("version") or "unknown").strip()
            purl = comp.get("purl") if isinstance(comp.get("purl"), str) else None
            eco = _ecosystem_from_purl(purl)
            if eco == "unknown" and isinstance(comp.get("properties"), list):
                for prop in comp["properties"]:
                    if isinstance(prop, dict) and prop.get("name") == "syft:package:type":
                        eco = str(prop.get("value", "unknown")).strip().lower() or "unknown"
                        break
            components.append((name, version, eco))
    elif "spdxVersion" in data or isinstance(data.get("packages"), list):
        sbom_format = "spdx"
        for pkg in data.get("packages", []):
            if not isinstance(pkg, dict):
                continue
            spdx_id = str(pkg.get("SPDXID", ""))
            purpose = str(pkg.get("primaryPackagePurpose", "")).upper()
            if purpose in ("CONTAINER", "FILE", "SOURCE") or spdx_id.startswith(
                "SPDXRef-DocumentRoot-"
            ):
                continue
            name = str(pkg.get("name", "")).strip()
            if not name:
                continue
            version = str(pkg.get("versionInfo") or "unknown").strip()
            purl: str | None = None
            if isinstance(pkg.get("externalRefs"), list):
                for ref in pkg["externalRefs"]:
                    if isinstance(ref, dict) and ref.get("referenceType") == "purl":
                        loc = ref.get("referenceLocator")
                        if isinstance(loc, str):
                            purl = loc
                            break
            components.append((name, version, _ecosystem_from_purl(purl)))
    elif isinstance(data.get("artifacts"), list):
        sbom_format = "syft-json"
        for art in data.get("artifacts", []):
            if not isinstance(art, dict):
                continue
            name = str(art.get("name", "")).strip()
            if not name:
                continue
            version = str(art.get("version") or "unknown").strip()
            purl = art.get("purl") if isinstance(art.get("purl"), str) else None
            eco = _ecosystem_from_purl(purl)
            if eco == "unknown" and isinstance(art.get("type"), str):
                eco = art["type"].strip().lower() or "unknown"
            components.append((name, version, eco))
    else:
        raise ValueError("Unrecognized SBOM schema; expected CycloneDX, SPDX, or Syft JSON.")

    ecosystems: dict[str, int] = {}
    for _, _, eco in components:
        ecosystems[eco] = ecosystems.get(eco, 0) + 1
    sorted_ecosystems = dict(sorted(ecosystems.items()))
    unique_sorted = sorted(set(components), key=lambda item: (item[2], item[0], item[1]))
    top_components = [
        {"name": n, "version": v, "ecosystem": e} for n, v, e in unique_sorted[:15]
    ]
    return {
        "present": True,
        "path": resolved_str,
        "format": sbom_format,
        "package_count": len(components),
        "ecosystems": sorted_ecosystems,
        "top_components": top_components,
    }


_SEVERITY_LEVELS = ("CRITICAL", "HIGH", "MEDIUM", "LOW", "UNKNOWN")
_SARIF_VULN_HEADS = (
    "CVE-",
    "GHSA-",
    "OSV-",
    "RUSTSEC-",
    "PYSEC-",
    "GO-",
    "DSA-",
    "ALAS-",
    "USN-",
)


def _norm_severity(raw_sev: object) -> str:
    val = str(raw_sev or "UNKNOWN").strip().upper()
    return val if val in _SEVERITY_LEVELS else "UNKNOWN"


def _sarif_severity(result_obj: dict[str, Any], rule_obj: dict[str, Any]) -> str:
    for container in (result_obj.get("properties"), rule_obj.get("properties")):
        if isinstance(container, dict):
            tags = container.get("tags")
            if isinstance(tags, list):
                for tag in tags:
                    upper = str(tag).strip().upper()
                    if upper in ("CRITICAL", "HIGH", "MEDIUM", "LOW"):
                        return upper
            sec_sev = container.get("security-severity")
            if sec_sev is not None:
                try:
                    score = float(sec_sev)
                    if score >= 9.0:
                        return "CRITICAL"
                    if score >= 7.0:
                        return "HIGH"
                    if score >= 4.0:
                        return "MEDIUM"
                    return "LOW"
                except (TypeError, ValueError):
                    pass
    level = str(
        result_obj.get("level")
        or rule_obj.get("defaultConfiguration", {}).get("level")
        or ""
    ).lower()
    if level == "error":
        return "HIGH"
    if level == "warning":
        return "MEDIUM"
    if level == "note":
        return "LOW"
    return "UNKNOWN"


def _parse_trivy_report(path_arg: Path | str) -> dict[str, object]:
    resolved_str, data = _read_bounded_json(path_arg)
    if not isinstance(data, dict):
        raise TypeError("Trivy report JSON root must be an object.")

    sev_counts = {lvl: 0 for lvl in _SEVERITY_LEVELS}
    vuln_count = 0
    misconfig_count = 0
    secret_count = 0
    samples: list[dict[str, str]] = []

    if isinstance(data.get("runs"), list):
        report_format = "sarif"
        for run in data["runs"]:
            if not isinstance(run, dict):
                continue
            rules_list = run.get("tool", {}).get("driver", {}).get("rules", [])
            rule_map = {
                str(r.get("id")): r
                for r in (rules_list if isinstance(rules_list, list) else [])
                if isinstance(r, dict) and r.get("id")
            }
            results_list = run.get("results", [])
            if not isinstance(results_list, list):
                continue
            for res in results_list:
                if not isinstance(res, dict):
                    continue
                rule_id = str(res.get("ruleId") or "unknown")
                rule_meta = rule_map.get(rule_id, {})
                tags_raw = rule_meta.get("properties", {}).get("tags", [])
                tags = {str(t).lower() for t in tags_raw} if isinstance(tags_raw, list) else set()
                sev = _sarif_severity(res, rule_meta)
                sev_counts[sev] += 1
                if rule_id.upper().startswith(_SARIF_VULN_HEADS) or "vulnerability" in tags:
                    kind = "vulnerability"
                    vuln_count += 1
                elif "secret" in tags or "secret" in rule_id.lower():
                    kind = "secret"
                    secret_count += 1
                else:
                    kind = "misconfiguration"
                    misconfig_count += 1
                if len(samples) < 12:
                    msg = str(res.get("message", {}).get("text") or rule_id)[:140]
                    samples.append(
                        {"id": rule_id, "category": kind, "severity": sev, "title": msg}
                    )
    elif isinstance(data.get("Results"), list) or "SchemaVersion" in data:
        report_format = "trivy-json"
        for block in data.get("Results", []):
            if not isinstance(block, dict):
                continue
            for v in block.get("Vulnerabilities") or []:
                if not isinstance(v, dict):
                    continue
                vuln_count += 1
                sev = _norm_severity(v.get("Severity"))
                sev_counts[sev] += 1
                if len(samples) < 12:
                    vid = str(v.get("VulnerabilityID") or "CVE-UNKNOWN")
                    pkg = str(v.get("PkgName") or "pkg")
                    samples.append(
                        {
                            "id": vid,
                            "category": "vulnerability",
                            "severity": sev,
                            "title": f"{pkg}: {str(v.get('Title') or vid)[:110]}",
                        }
                    )
            for m in block.get("Misconfigurations") or []:
                if not isinstance(m, dict):
                    continue
                if str(m.get("Status") or "FAIL").upper() == "PASS":
                    continue
                misconfig_count += 1
                sev = _norm_severity(m.get("Severity"))
                sev_counts[sev] += 1
                if len(samples) < 12:
                    mid = str(m.get("ID") or "MISCONFIG")
                    samples.append(
                        {
                            "id": mid,
                            "category": "misconfiguration",
                            "severity": sev,
                            "title": str(m.get("Title") or mid)[:140],
                        }
                    )
            for s in block.get("Secrets") or []:
                if not isinstance(s, dict):
                    continue
                secret_count += 1
                sev = _norm_severity(s.get("Severity"))
                sev_counts[sev] += 1
                if len(samples) < 12:
                    sid = str(s.get("RuleID") or "SECRET")
                    # Never include `Match` secret material in correlated output.
                    samples.append(
                        {
                            "id": sid,
                            "category": "secret",
                            "severity": sev,
                            "title": str(s.get("Title") or "Detected secret rule match")[:140],
                        }
                    )
    else:
        raise ValueError("Unrecognized Trivy report schema; expected Trivy JSON or SARIF.")

    return {
        "present": True,
        "path": resolved_str,
        "format": report_format,
        "vulnerability_count": vuln_count,
        "misconfiguration_count": misconfig_count,
        "secret_count": secret_count,
        "severity_counts": sev_counts,
        "sample_findings": samples,
    }


def _finding_brief(f: BoundaryFinding) -> dict[str, object]:
    return {
        "rule_code": f.rule_code,
        "severity": f.severity,
        "source_file": f.source_file,
        "line": f.line,
        "node_id": f.node_id,
        "title": f.title,
    }


def summarize_companion_security_artifacts(
    report: TruthAtlasReport,
    trivy_path: Path | str | None = None,
    syft_path: Path | str | None = None,
) -> dict[str, object]:
    """Correlate Wythe blueprint findings with optional Syft SBOM & Trivy crate reports."""
    by_rule: dict[str, list[BoundaryFinding]] = {}
    for f in report.findings:
        by_rule.setdefault(f.rule_code, []).append(f)

    truth_003 = [_finding_brief(f) for f in by_rule.get("TRUTH-003", ())]
    disp_001 = [_finding_brief(f) for f in by_rule.get("DISP-001", ())]
    truth_001 = [_finding_brief(f) for f in by_rule.get("TRUTH-001", ())]
    manip_006 = [_finding_brief(f) for f in by_rule.get("MANIP-006", ())]
    container_drift = [
        _finding_brief(f)
        for f in (*by_rule.get("MANIP-004", ()), *by_rule.get("MANIP-005", ()))
    ]

    syft_summary: dict[str, object] = (
        _parse_syft_sbom(syft_path)
        if syft_path is not None
        else {
            "present": False,
            "path": None,
            "format": None,
            "package_count": 0,
            "ecosystems": {},
            "top_components": [],
        }
    )
    trivy_summary: dict[str, object] = (
        _parse_trivy_report(trivy_path)
        if trivy_path is not None
        else {
            "present": False,
            "path": None,
            "format": None,
            "vulnerability_count": 0,
            "misconfiguration_count": 0,
            "secret_count": 0,
            "severity_counts": {lvl: 0 for lvl in _SEVERITY_LEVELS},
            "sample_findings": [],
        }
    )

    crit_high = int(
        trivy_summary["severity_counts"].get("CRITICAL", 0)  # type: ignore[union-attr]
        + trivy_summary["severity_counts"].get("HIGH", 0)  # type: ignore[union-attr]
    )

    return {
        "observed_at": report.observed_at.isoformat(),
        "target_slug": report.target_slug,
        "source_commit": report.source_commit,
        "gate_verdict": report.gate.verdict,
        "target_code_executed": False,
        "automated_security_audit": False,
        "non_certification_disclaimer": NON_CERTIFICATION_NOTICE,
        "blueprint_stage": {
            "total_findings": len(report.findings),
            "blocking_findings": report.summary.blocking_findings,
            "warning_findings": report.summary.warning_findings,
            "unguarded_writes_truth_003": truth_003,
            "client_policy_shadows_disp_001": disp_001,
            "unplugged_policy_tables_truth_001": truth_001,
            "container_packaging_drift": container_drift,
            "horizontal_boundary_violations_manip_006": manip_006,
        },
        "crate_stage": {
            "syft_sbom": syft_summary,
            "trivy_report": trivy_summary,
        },
        "handoff": {
            "blue_team": {
                "focus": "Architectural guardrails + sealed-container patching",
                "blueprint_remediations": [
                    f"Gate {len(truth_003)} direct route write(s) (TRUTH-003) behind service doors.",
                    f"Eliminate {len(disp_001)} client-side policy shadow(s) (DISP-001).",
                    f"Resolve {len(container_drift)} container COPY/exec-form packaging drift item(s).",
                    f"Enforce {len(manip_006)} horizontal tach boundary rule(s) (MANIP-006).",
                ],
                "crate_remediations": [
                    f"Inventory {syft_summary['package_count']} SBOM package(s) from Syft.",
                    (
                        f"Triage {crit_high} CRITICAL/HIGH Trivy finding(s) and "
                        f"{trivy_summary['misconfiguration_count']} container misconfiguration(s)."
                    ),
                ],
            },
            "red_team": {
                "focus": "Manual hypothesis generation across architectural seams (non-certifying)",
                "candidate_seams": [
                    (
                        f"Inspect {len(truth_003)} TRUTH-003 unguarded route write(s) with "
                        "`wythe security ownership` for missing record-ownership predicates."
                    ),
                    (
                        f"Verify server-side enforcement behind {len(disp_001)} DISP-001 client "
                        f"policy constant(s) and {len(truth_001)} unplugged TRUTH-001 policy "
                        "table(s)."
                    ),
                    (
                        f"Cross-check {trivy_summary['vulnerability_count']} Trivy CVE(s) and "
                        f"{trivy_summary['secret_count']} secret rule match(es) against live routes."
                    ),
                ],
            },
            "purple_team": {
                "focus": "Two-stage CI verification (Source Blueprint -> Sealed OCI Crate)",
                "pipeline": [
                    "Stage 1 (Source Blueprint): tach + wythe gate --strict + export-openlineage",
                    "Build Boundary: docker build (strips AST/git/test context by design)",
                    "Stage 2 (Sealed Crate): syft SBOM + trivy image/config scan + correlation",
                ],
                "epistemic_limits": NON_CERTIFICATION_NOTICE,
            },
        },
    }
