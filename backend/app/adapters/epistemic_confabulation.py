"""Cross-tier anti-confabulation coordinator (#119, #120, #121)."""

from __future__ import annotations

from dataclasses import replace
from pathlib import Path

from app.adapters.base import (
    DisplayExtractionResult,
    ManipulatorExtractionResult,
    RawCandidateFinding,
)
from app.adapters.epistemic_display_checks import (
    DisplayCallReadSet,
    analyze_display_confabulation_and_reads,
)
from app.adapters.epistemic_freshness_manip import (
    ProducerPayloadContract,
    analyze_python_freshness_and_producers,
)


def _match_producer_contract(
    route_key: str, contracts_by_route: dict[str, ProducerPayloadContract]
) -> ProducerPayloadContract | None:
    if route_key in contracts_by_route:
        return contracts_by_route[route_key]
    if route_key.startswith("GET /api/v"):
        stripped = "/" + route_key.split("/", 3)[-1]
        if f"GET {stripped}" in contracts_by_route:
            return contracts_by_route[f"GET {stripped}"]
    return None


def evaluate_epistemic_confabulation(
    repo_root: Path,
    backend_subdir: str,
    frontend_subdir: str,
    manip: ManipulatorExtractionResult,
    disp: DisplayExtractionResult,
    *,
    strict: bool = False,
    trusted_allowlist: frozenset[str] | set[str] | None = None,
    coverage_out: list[bool] | None = None,
) -> tuple[list[RawCandidateFinding], list[str]]:
    """Run `#119` (`DISP-009/010`), `#120` (`DISP-011/012/013`), & `#121` (`MANIP-007`, `DISP-014`)."""
    manip_cov_notes: list[str] = []
    disp_cov_notes: list[str] = []
    manip_findings, contracts = analyze_python_freshness_and_producers(
        repo_root, backend_subdir, manip, coverage_notes=manip_cov_notes
    )
    known_slices = frozenset(
        rk.split("slice:", 1)[1] for rk in contracts if rk.startswith("slice:")
    )
    disp_findings, read_sets = analyze_display_confabulation_and_reads(
        repo_root,
        frontend_subdir,
        disp,
        known_slice_slugs=known_slices,
        strict=strict,
        trusted_allowlist=(None if strict else trusted_allowlist),
        coverage_notes=disp_cov_notes,
    )

    drift_findings: list[RawCandidateFinding] = []
    notes: list[str] = []
    if manip_cov_notes:
        manip = replace(manip, coverage_complete=False)
    if disp_cov_notes:
        disp = replace(disp, coverage_complete=False)
    all_cov_notes = [*manip_cov_notes, *disp_cov_notes]
    if all_cov_notes or not manip.coverage_complete or not disp.coverage_complete:
        if all_cov_notes:
            for detail in all_cov_notes:
                notes.append(f"epistemic_coverage_incomplete: {detail}")
        else:
            notes.append("epistemic_coverage_incomplete: extraction coverage_complete=False")
        if coverage_out is not None:
            coverage_out.append(False)
    partial_noted: set[tuple[str, int]] = set()
    read_union_by_producer: dict[tuple[str, int], tuple[ProducerPayloadContract, set[str], list[DisplayCallReadSet]]] = {}

    for rs in read_sets:
        contract = _match_producer_contract(rs.route_key, contracts)
        if contract is None:
            continue
        pkey = (contract.source_file, contract.line)
        if contract.coverage == "partial":
            if pkey not in partial_noted:
                partial_noted.add(pkey)
                notes.append(
                    f"Producer `{contract.func_name}` ({contract.source_file}:{contract.line}) builds dynamic payload keys "
                    "(coverage=partial); skipping strict producer/display field-drift assertion."
                )
            continue

        entry = read_union_by_producer.get(pkey)
        if entry is None:
            entry = (contract, set(), [])
            read_union_by_producer[pkey] = entry
        entry[1].update(p.split(".", 1)[0] for p in rs.read_paths)
        entry[2].append(rs)

        # #121: Producer emits `evidence_state`, but consumer never checks `evidence_state` at all
        if contract.has_evidence_state and "evidence_state" not in rs.read_paths:
            drift_findings.append(
                RawCandidateFinding(
                    rule_code="DISP-014",
                    node_id=rs.node_id,
                    target_node_id=contract.node_id,
                    source_file=rs.source_file,
                    line=rs.call_line,
                    title=f"Display renders `{rs.route_key}` without checking producer `evidence_state`",
                    detail=(
                        f"{rs.source_file}:{rs.call_line} consumes `{rs.route_key}` from `{contract.func_name}` "
                        f"({contract.source_file}:{contract.line}), which emits `evidence_state`, without branching on "
                        "`evidence_state` (such as `source_error` or `could_not_measure`)."
                    ),
                    remediation="Inspect `payload.evidence_state` before rendering an HTTP 200 observation envelope as valid.",
                )
            )

        # #120: Check every read path against static emit_paths
        reported_roots: set[str] = set()
        for r_path, r_line in sorted(rs.read_paths.items(), key=lambda kv: (kv[1], kv[0])):
            if "." in r_path:
                root_k = r_path.split(".", 1)[0]
                if root_k in reported_roots:
                    continue
                if root_k not in contract.nested_dict_roots:
                    # Only enforce nested `.k2` when `root_k` itself was statically resolved as a dict literal
                    continue
            if r_path in contract.emit_paths:
                continue
            if "." not in r_path:
                reported_roots.add(r_path)
            is_crit = r_path in rs.action_or_status_paths
            rcode = "DISP-011" if is_crit else "DISP-012"
            drift_findings.append(
                RawCandidateFinding(
                    rule_code=rcode,
                    node_id=rs.node_id,
                    target_node_id=contract.node_id,
                    source_file=rs.source_file,
                    line=r_line,
                    title=f"Display reads `{r_path}` absent from `{contract.func_name}` static emit set",
                    detail=(
                        f"Display {rs.source_file}:{r_line} reads `{r_path}` from `{rs.route_key}`, "
                        f"which producer `{contract.func_name}` at {contract.source_file}:{contract.line} never emits "
                        f"(emitted domain keys: {', '.join(sorted(contract.top_domain_keys)) or 'none'})."
                    ),
                    remediation=f"Align display property `{r_path}` with `{contract.source_file}:{contract.line}` or emit `{r_path}` explicitly.",
                )
            )

    # #120 Item 4: Report producer domain keys emitted on matched routes that zero display consumers read (DISP-013 info)
    for (_, _), (contract, consumed_roots, consumers) in sorted(read_union_by_producer.items()):
        if not consumers:
            continue
        unread = sorted(contract.top_domain_keys - consumed_roots)
        if not unread:
            continue
        consumer_locs = ", ".join(sorted({f"{c.source_file}:{c.call_line}" for c in consumers}))
        for uk in unread:
            drift_findings.append(
                RawCandidateFinding(
                    rule_code="DISP-013",
                    node_id=consumers[0].node_id,
                    target_node_id=contract.node_id,
                    source_file=contract.source_file,
                    line=contract.line,
                    title=f"Producer field `{uk}` emitted by `{contract.func_name}` is never read by display",
                    detail=(
                        f"Producer `{contract.func_name}` ({contract.source_file}:{contract.line}) emits `{uk}`, "
                        f"which is never read by matched display consumer(s) ({consumer_locs})."
                    ),
                    remediation=f"Render `{uk}` in the consuming view ({consumer_locs}) or remove unused payload keys if superseded.",
                )
            )

    return [*manip_findings, *disp_findings, *drift_findings], notes
