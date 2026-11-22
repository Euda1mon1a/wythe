"""Wythe Zoom-3 static Mach-O/ELF binary inspection & `BIN-ENT-001` plugin registration."""

from __future__ import annotations

import re
from collections.abc import Iterator, Sequence
from contextlib import contextmanager
from dataclasses import asdict, dataclass
from pathlib import Path
from typing import Literal

from app.adapters import plugin_registry
from app.adapters.base import RawCandidateFinding
from app.adapters.plugin_registry import PluginRuleSpec, WythePluginSpec
from app.schemas.atlas import (
    AtlasNode,
    StratumExpansionResult,
    StratumMicroEdge,
    StratumMicroNode,
    StratumSummaryBadge,
    TruthAtlasReport,
)
from wythe_plugin_binary.elf_parser import (
    _read_sidecar_elf_capabilities,
    is_elf_magic,
    parse_elf_bytes,
)
from wythe_plugin_binary.entitlement_drift import (
    ACTIVE_BINARY_PATHS_VAR,
    MAX_BINARY_BYTES,
    NON_CERTIFICATION_NOTICE,
    EntitlementDriftResult,
    SourceEntitlementSpec,
    collect_target_artifact_files,
    discover_repo_entitlements,
    evaluate_entitlement_drift,
    read_bounded_regular_bytes,
)
from wythe_plugin_binary.macho_parser import is_macho_magic, parse_macho_bytes
from wythe_plugin_binary.recorded_fixtures import (
    RecordedBinaryCapture,
    parse_recorded_fixture,
)

BIN_ENT_001_RULE = PluginRuleSpec(
    rule_code="BIN-ENT-001",
    tier="truth",
    title="Signed binary or ELF capability privilege drift exceeds declared source entitlements",
    severity="blocking",
    blocks_gate=True,
    enabled=True,
    confidence="confirmed",
    evidence_strength="structural_match",
)


@contextmanager
def binary_inspection_scope(*binary_paths: str | Path) -> Iterator[None]:
    """Bind explicit read-only `--binary` artifact paths for the active inspection scope."""
    normalized = tuple(str(p) for p in binary_paths if str(p).strip())
    ctx_handle = ACTIVE_BINARY_PATHS_VAR.set(normalized)
    try:
        yield
    finally:
        ACTIVE_BINARY_PATHS_VAR.reset(ctx_handle)


def _normalize_path_args(raw: object) -> list[str]:
    if raw is None:
        return []
    if isinstance(raw, (str, Path)):
        s = str(raw).strip()
        return [s] if s else []
    if isinstance(raw, Sequence):
        out: list[str] = []
        for item in raw:
            if isinstance(item, (str, Path)):
                s = str(item).strip()
                if s:
                    out.append(s)
        return out
    return []


def get_active_binary_paths(explicit_paths: object = None) -> tuple[str, ...]:
    """Merge explicit `binary_paths`, `plugin_registry.get_active_stratum_artifacts`, and local scope."""
    merged: list[str] = []
    for src in (
        _normalize_path_args(explicit_paths),
        _normalize_path_args(
            getattr(plugin_registry, "get_active_stratum_artifacts", dict)().get("binary", ())
        ),
        list(ACTIVE_BINARY_PATHS_VAR.get()),
    ):
        for p in src:
            if p not in merged:
                merged.append(p)
    return tuple(merged)


@dataclass(frozen=True)
class InspectedBinaryBundleItem:
    """Single passively parsed binary or recorded fixture paired with entitlement drift results."""

    resolved_path: str
    display_name: str
    capture: RecordedBinaryCapture
    drift: EntitlementDriftResult


def _slug_token(text: str) -> str:
    cleaned = re.sub(r"[^A-Za-z0-9_.:-]+", "_", text.strip())
    return cleaned[:96] or "item"


def inspect_single_artifact_file(
    file_path: Path | str,
    *,
    repo_root: Path | None = None,
    allow_external: bool = False,
    max_bytes: int = MAX_BINARY_BYTES,
) -> tuple[Path, RecordedBinaryCapture]:
    """Passively inspect one regular file (Mach-O 64/Universal, ELF64, or recorded fixture)."""
    resolved, raw = read_bounded_regular_bytes(
        file_path, repo_root=repo_root, allow_external=allow_external, max_bytes=max_bytes
    )
    if is_macho_magic(raw):
        return resolved, parse_macho_bytes(raw, source_name=resolved.name)
    if is_elf_magic(raw):
        side_caps = _read_sidecar_elf_capabilities(
            resolved, repo_root if not allow_external else None
        )
        return resolved, parse_elf_bytes(
            raw,
            source_name=resolved.name,
            extra_capabilities=side_caps,
        )
    if raw[:2] in (b"\xcf\xfa", b"\xfe\xed", b"\xca\xfe", b"\xbe\xba") or raw[:3] == b"\x7fEL":
        raise ValueError(f"Truncated or corrupt binary header in '{resolved.name}'.")
    return resolved, parse_recorded_fixture(raw, source_name=resolved.name)


def _probe_looks_like_xml_xxe(probe: bytes) -> bool:
    head = probe[:8192]
    upper_raw = head.upper()
    if b"<!ENTITY" in upper_raw or b"<!DOCTYPE" in upper_raw:
        return True
    encodings: list[str] = []
    if head.startswith((b"\xff\xfe", b"\xfe\xff")):
        encodings.append("utf-16")
    elif head.startswith((b"\xff\xfe\x00\x00", b"\x00\x00\xfe\xff")):
        encodings.append("utf-32")
    elif b"\x00" in head[:64]:
        encodings.extend(["utf-16-le", "utf-16-be"])
    encodings.extend(["utf-8", "latin-1"])
    for enc in encodings:
        try:
            dec = head.decode(enc, errors="ignore").upper()
        except LookupError:
            continue
        if "<!ENTITY" in dec or "<!DOCTYPE" in dec:
            return True
    return False


def inspect_binary_artifacts(
    repo_root: Path,
    binary_paths: Sequence[str | Path],
    *,
    source_specs: Sequence[SourceEntitlementSpec] | None = None,
    allow_external: bool = False,
) -> tuple[list[InspectedBinaryBundleItem], list[SourceEntitlementSpec]]:
    """Inspect all explicit files, `.app`/`.xpc` bundles, or unpacked ELF directories."""
    specs = list(source_specs) if source_specs is not None else discover_repo_entitlements(repo_root)
    items: list[InspectedBinaryBundleItem] = []
    seen_files: set[str] = set()

    for raw_target in binary_paths:
        target_files = collect_target_artifact_files(
            raw_target, repo_root=repo_root, allow_external=allow_external
        )
        raw_p = Path(str(raw_target))
        is_dir_scan = len(target_files) > 1 or (raw_p.exists() and raw_p.is_dir())
        is_bundle = str(raw_target).lower().rstrip("/").endswith((".app", ".xpc"))
        parsed_in_target = 0

        for fpath in target_files:
            resolved_key = str(fpath.resolve())
            if resolved_key in seen_files:
                parsed_in_target += 1
                continue
            try:
                resolved, cap = inspect_single_artifact_file(
                    fpath, repo_root=repo_root, allow_external=allow_external
                )
            except ValueError:
                if not is_dir_scan or is_bundle:
                    raise
                # Inside an unpacked rootfs directory, still fail closed on corrupt binaries/XXE
                _, probe = read_bounded_regular_bytes(
                    fpath, repo_root=repo_root, allow_external=allow_external
                )
                if (
                    is_macho_magic(probe)
                    or is_elf_magic(probe)
                    or _probe_looks_like_xml_xxe(probe)
                ):
                    raise
                continue

            seen_files.add(str(resolved))
            parsed_in_target += 1
            drift = evaluate_entitlement_drift(
                artifact_name=cap.name or resolved.name,
                signed_entitlements=cap.entitlements,
                linux_capabilities=cap.linux_capabilities,
                source_specs=specs,
                binary_format=cap.binary_format,
                slice_entitlements=cap.slice_entitlements,
                slice_has_entitlements_blob=cap.slice_has_entitlements_blob,
                slice_der_only_entitlements=cap.slice_der_only_entitlements,
            )
            items.append(
                InspectedBinaryBundleItem(
                    resolved_path=str(resolved),
                    display_name=cap.name or resolved.name,
                    capture=cap,
                    drift=drift,
                )
            )

        if parsed_in_target == 0:
            raise ValueError(f"No inspectable Mach-O, ELF64, or fixture binary found at '{raw_target}'.")

    return items, specs


def _caller_tokens_for_node(node: AtlasNode, report: TruthAtlasReport) -> set[str]:
    tokens: set[str] = set()
    for raw in (node.label, Path(node.source_file).stem):
        clean = raw.strip()
        if len(clean) >= 3:
            tokens.add(clean.lower())
            tokens.add(re.sub(r"[^a-z0-9]+", "", clean.lower()))
    for edge in report.edges:
        if edge.source_id == node.id or edge.target_id == node.id:
            for link in edge.symbol_links:
                for side in link.split("->"):
                    s = side.strip()
                    if s and s != "*" and len(s) >= 3:
                        tokens.add(s.lower())
    return {t for t in tokens if t}


def _symbol_matches_caller_tokens(demangled_name: str, caller_toks: set[str]) -> bool:
    dem_low = demangled_name.lower()
    tail = dem_low.rsplit(".", 1)[-1].rsplit("::", 1)[-1]
    if tail in caller_toks:
        return True
    dem_parts = {t for t in re.split(r"[^a-z0-9_]+", dem_low) if len(t) >= 4}
    dem_norm_parts = {re.sub(r"[^a-z0-9]+", "", t) for t in re.split(r"[^a-z0-9]+", dem_low) if t}
    if any(ct in dem_parts or ct in dem_norm_parts for ct in caller_toks if len(ct) >= 4):
        return True
    dem_norm = re.sub(r"[^a-z0-9]+", "", dem_low)
    return any(len(ct) >= 10 and (ct in dem_low or ct in dem_norm) for ct in caller_toks)


def _matching_symbols_for_node(
    node: AtlasNode,
    report: TruthAtlasReport,
    item: InspectedBinaryBundleItem,
) -> list[str]:
    caller_toks = _caller_tokens_for_node(node, report)
    matched_syms: list[str] = []
    for sym in item.capture.exported_symbols:
        if _symbol_matches_caller_tokens(sym.demangled_name, caller_toks):
            matched_syms.append(sym.demangled_name)
    for refl in item.capture.reflection_descriptors:
        r_low = refl.name.lower()
        if r_low in caller_toks or re.sub(r"[^a-z0-9]+", "", r_low) in caller_toks:
            matched_syms.append(refl.name)
    return matched_syms


def _select_artifacts_for_node(
    node: AtlasNode,
    report: TruthAtlasReport,
    items: Sequence[InspectedBinaryBundleItem],
) -> list[InspectedBinaryBundleItem]:
    if not items:
        return []
    direct: list[InspectedBinaryBundleItem] = []
    node_stem_norm = re.sub(r"[^a-z0-9]+", "", Path(node.source_file).stem.lower())
    label_norm = re.sub(r"[^a-z0-9]+", "", node.label.lower())

    for item in items:
        if item.drift.matched_source_file and item.drift.matched_source_file == node.source_file:
            direct.append(item)
            continue
        bin_norm = re.sub(r"[^a-z0-9]+", "", item.display_name.lower())
        if (
            (bin_norm and node_stem_norm and (bin_norm in node_stem_norm or node_stem_norm in bin_norm))
            or (bin_norm and label_norm and len(label_norm) >= 4 and (bin_norm in label_norm or label_norm in bin_norm))
            or _matching_symbols_for_node(node, report, item)
        ):
            direct.append(item)

    if direct:
        return direct
    if node.tier == "manipulate" or node.subkind in ("cli", "entitlement_spec"):
        any_specific = any(
            (it.drift.matched_source_file and it.drift.matched_source_file == other.source_file)
            or bool(_matching_symbols_for_node(other, report, it))
            for other in report.nodes
            for it in items
        )
        if not any_specific:
            return list(items)
    return []


def _badges_for_items(items: Sequence[InspectedBinaryBundleItem]) -> list[StratumSummaryBadge]:
    n_libs = sum(len(i.capture.linked_libraries) for i in items)
    n_syms = sum(
        len(i.capture.exported_symbols) + len(i.capture.imported_symbols) for i in items
    )
    n_refl = sum(len(i.capture.reflection_descriptors) for i in items)
    n_wit = sum(len(i.capture.string_witnesses) for i in items)
    n_caps = sum(
        len(i.capture.entitlements) + len(i.capture.linux_capabilities) for i in items
    )
    badges = [
        StratumSummaryBadge(key="binary_libs", label="Linked Libraries", count=n_libs),
        StratumSummaryBadge(key="binary_symbols", label="Binary Symbols", count=n_syms),
    ]
    if n_refl > 0:
        badges.append(
            StratumSummaryBadge(
                key="binary_reflection", label="Reflection Descriptors", count=n_refl
            )
        )
    if n_wit > 0:
        badges.append(
            StratumSummaryBadge(
                key="binary_witnesses", label="Unverified String Witnesses", count=n_wit
            )
        )
    if n_caps > 0:
        badges.append(
            StratumSummaryBadge(
                key="binary_capabilities", label="Signed Capabilities", count=n_caps
            )
        )
    return badges


def _build_drift_findings_and_notes(
    repo_root: Path,
    report: TruthAtlasReport,
    items: Sequence[InspectedBinaryBundleItem],
) -> tuple[list[RawCandidateFinding], list[str]]:
    findings: list[RawCandidateFinding] = []
    notes: list[str] = []
    node_by_file = {n.source_file: n.id for n in report.nodes}
    fallback_nid = next(
        (n.id for n in report.nodes if n.subkind == "entitlement_spec"),
        next((n.id for n in report.nodes if n.tier == "manipulate"), None),
    )

    for item in items:
        drift = item.drift
        for wn in drift.warning_notes:
            if wn not in notes:
                notes.append(wn)
        if drift.drift_status != "exceeded" or not drift.undeclared_privileges:
            continue

        src_file = drift.matched_source_file
        if not src_file:
            try:
                src_file = Path(item.resolved_path).relative_to(repo_root.resolve()).as_posix()
            except ValueError:
                src_file = item.display_name
        nid = node_by_file.get(src_file) or fallback_nid
        priv_str = ", ".join(f"`{p}`" for p in drift.undeclared_privileges[:8])
        decl_label = f"`{drift.matched_source_file}`" if drift.matched_source_file else "repository `.entitlements`"
        findings.append(
            RawCandidateFinding(
                rule_code="BIN-ENT-001",
                node_id=nid,
                source_file=src_file,
                line=1,
                title=(
                    f"Signed binary `{item.display_name}` holds undeclared privilege(s) "
                    f"exceeding {decl_label}"
                ),
                detail=(
                    f"Passive binary inspection of `{item.display_name}` detected signed "
                    f"entitlement/capability grant(s) [{priv_str}] that exceed declared "
                    f"source capabilities in {decl_label}."
                ),
                remediation=(
                    f"Remove undeclared privilege(s) from `{item.display_name}` build/signing "
                    f"flags or declare and review them explicitly in {decl_label}."
                ),
                confidence="confirmed",
                evidence_strength="structural_match",
            )
        )
    return findings, notes


def summarize_binary_zoom1_badges(
    repo_root: Path,
    report: TruthAtlasReport,
) -> dict[str, list[StratumSummaryBadge]]:
    """Attach compact Zoom-1 badges when `--binary` artifacts are active (digest-invariant)."""
    active_paths = get_active_binary_paths()
    if not active_paths:
        return {}
    items, _ = inspect_binary_artifacts(repo_root, active_paths, allow_external=True)
    badges_by_node: dict[str, list[StratumSummaryBadge]] = {}
    for node in report.nodes:
        matched = _select_artifacts_for_node(node, report, items)
        if matched:
            badges_by_node[node.id] = _badges_for_items(matched)
    return badges_by_node


def expand_binary_zoom3_stratum(
    repo_root: Path,
    report: TruthAtlasReport,
    node_id: str,
    zoom: Literal[2, 3],
) -> StratumExpansionResult:
    """Expand Zoom-3 library, symbol, reflection, capability, and `binary_string_witness` graph."""
    if zoom != 3:
        return StratumExpansionResult()
    active_paths = get_active_binary_paths()
    if not active_paths:
        return StratumExpansionResult(
            notes=["Pass `--binary <path>` to inspect compiled Mach-O or ELF64 Zoom-3 strata."]
        )

    parent = next((n for n in report.nodes if n.id == node_id), None)
    if parent is None:
        return StratumExpansionResult()

    items, _ = inspect_binary_artifacts(repo_root, active_paths, allow_external=True)
    matched_items = _select_artifacts_for_node(parent, report, items)
    if not matched_items:
        return StratumExpansionResult()

    micro_nodes: list[StratumMicroNode] = []
    micro_edges: list[StratumMicroEdge] = []
    notes: list[str] = []
    caller_toks = _caller_tokens_for_node(parent, report)

    for b_idx, item in enumerate(matched_items, start=1):
        cap = item.capture
        bin_id = f"z3:{node_id}:bin:{b_idx}:{_slug_token(item.display_name)}"
        arch_str = ", ".join(cap.architectures)
        micro_nodes.append(
            StratumMicroNode(
                id=bin_id,
                label=item.display_name,
                kind="macho_binary" if cap.binary_format == "macho" else "elf_binary",
                zoom=3,
                source_file=item.drift.matched_source_file or parent.source_file,
                line=parent.line,
                verification="verified",
                summary=f"{cap.binary_format.upper()} ({arch_str}, {cap.source_kind})",
            )
        )
        micro_edges.append(
            StratumMicroEdge(
                id=f"e:{node_id}->bin:{b_idx}",
                source_id=node_id,
                target_id=bin_id,
                label="compiled_artifact",
                kind="compiled_artifact",
                verification="verified",
                evidence_note=f"Passive Zoom-3 binary slice `{item.display_name}`",
            )
        )

        for l_idx, lib in enumerate(cap.linked_libraries, start=1):
            lib_id = f"z3:{node_id}:lib:{b_idx}:{l_idx}:{_slug_token(lib.short_name)}"
            rpath_note = (
                f", resolves via {', '.join(lib.resolved_rpath_candidates[:2])}"
                if lib.resolved_rpath_candidates
                else (f", rpath_token={lib.rpath_token}" if lib.rpath_token else "")
            )
            micro_nodes.append(
                StratumMicroNode(
                    id=lib_id,
                    label=lib.raw_path,
                    kind="dynamic_library",
                    zoom=3,
                    verification="declared",
                    summary=f"{lib.load_kind} dynamic dependency{rpath_note}",
                )
            )
            micro_edges.append(
                StratumMicroEdge(
                    id=f"e:{bin_id}->lib:{l_idx}",
                    source_id=bin_id,
                    target_id=lib_id,
                    label=f"links_{lib.load_kind}",
                    kind="links_dylib" if cap.binary_format == "macho" else "links_dt_needed",
                    verification="declared",
                    evidence_note=f"`{item.display_name}` depends on `{lib.raw_path}`",
                )
            )

        all_syms = [*cap.exported_symbols[:128], *cap.imported_symbols[:128]]
        for s_idx, sym in enumerate(all_syms, start=1):
            sym_id = f"z3:{node_id}:sym:{b_idx}:{s_idx}:{_slug_token(sym.demangled_name)}"
            verif: Literal["verified", "declared"] = (
                "verified" if sym.binding == "exported" else "declared"
            )
            micro_nodes.append(
                StratumMicroNode(
                    id=sym_id,
                    label=sym.demangled_name,
                    kind=f"{sym.binding}_symbol",
                    zoom=3,
                    verification=verif,
                    summary=f"{sym.binding} {sym.language} symbol `{sym.raw_name}`",
                )
            )
            micro_edges.append(
                StratumMicroEdge(
                    id=f"e:{bin_id}->sym:{s_idx}",
                    source_id=bin_id,
                    target_id=sym_id,
                    label=f"{sym.binding}_symbol",
                    kind=f"{sym.binding}s_symbol",
                    verification=verif,
                    evidence_note=f"`{sym.raw_name}` -> `{sym.demangled_name}`",
                )
            )
            if sym.binding == "exported" and _symbol_matches_caller_tokens(
                sym.demangled_name, caller_toks
            ):
                micro_edges.append(
                        StratumMicroEdge(
                            id=f"e:{node_id}->ffi_sym:{b_idx}:{s_idx}",
                            source_id=node_id,
                            target_id=sym_id,
                            label="resolves_ffi_symbol",
                            kind="resolves_ffi_symbol",
                            verification="verified",
                            evidence_note=(
                                f"Links Zoom-1 caller `{parent.label}` to compiled provider `{sym.demangled_name}`"
                            ),
                        )
                    )

        for r_idx, refl in enumerate(cap.reflection_descriptors[:128], start=1):
            refl_id = f"z3:{node_id}:refl:{b_idx}:{r_idx}:{_slug_token(refl.name)}"
            micro_nodes.append(
                StratumMicroNode(
                    id=refl_id,
                    label=refl.name,
                    kind=refl.kind,
                    zoom=3,
                    verification="verified",
                    summary=f"Reflection descriptor in `{refl.section}`",
                )
            )
            micro_edges.append(
                StratumMicroEdge(
                    id=f"e:{bin_id}->refl:{r_idx}",
                    source_id=bin_id,
                    target_id=refl_id,
                    label=refl.kind,
                    kind="declares_reflection",
                    verification="verified",
                    evidence_note=f"`{refl.section}` declares `{refl.name}`",
                )
            )

        undeclared_set = set(item.drift.undeclared_privileges)
        raw_cap_tokens = [
            *(f"{k}={v}" if not isinstance(v, bool) else k for k, v in sorted(cap.entitlements.items()) if v is not False),
            *cap.linux_capabilities,
            *item.drift.undeclared_privileges,
        ]
        cap_tokens = list(dict.fromkeys(raw_cap_tokens))
        for c_idx, c_tok in enumerate(cap_tokens[:64], start=1):
            stripped_tok = c_tok.split(": ", 1)[-1] if ": " in c_tok else c_tok
            is_drift = (
                c_tok in undeclared_set
                or c_tok.split("=", 1)[0] in undeclared_set
                or stripped_tok in undeclared_set
            )
            cap_id = f"z3:{node_id}:cap:{b_idx}:{c_idx}:{_slug_token(c_tok)}"
            c_verif: Literal["broken", "verified"] = "broken" if is_drift else "verified"
            micro_nodes.append(
                StratumMicroNode(
                    id=cap_id,
                    label=c_tok,
                    kind="signed_entitlement" if cap.binary_format == "macho" else "elf_capability",
                    zoom=3,
                    verification=c_verif,
                    summary="Undeclared privilege drift (BIN-ENT-001)" if is_drift else "Declared binary capability",
                )
            )
            micro_edges.append(
                StratumMicroEdge(
                    id=f"e:{bin_id}->cap:{c_idx}",
                    source_id=bin_id,
                    target_id=cap_id,
                    label="claims_capability",
                    kind="claims_capability",
                    verification=c_verif,
                    evidence_note=f"`{item.display_name}` claims `{c_tok}`",
                )
            )

        for w_idx, wit in enumerate(cap.string_witnesses, start=1):
            wit_id = f"z3:{node_id}:witness:{b_idx}:{w_idx}"
            micro_nodes.append(
                StratumMicroNode(
                    id=wit_id,
                    label=wit.value,
                    kind="binary_string_witness",
                    zoom=3,
                    verification="unverified",
                    summary=(
                        f"Uncorroborated `{wit.category}` string literal in `{wit.section}` "
                        "(never promoted to verified call edge)"
                    ),
                )
            )
            micro_edges.append(
                StratumMicroEdge(
                    id=f"e:{bin_id}->witness:{w_idx}",
                    source_id=bin_id,
                    target_id=wit_id,
                    label="binary_string_witness",
                    kind="binary_string_witness",
                    verification="unverified",
                    evidence_note=f"Read-only `{wit.section}` string witness ({wit.category})",
                )
            )

        notes.extend(w for w in item.drift.warning_notes if w not in notes)

    return StratumExpansionResult(
        summary_badges=_badges_for_items(matched_items),
        nodes=micro_nodes,
        edges=micro_edges,
        notes=notes,
    )


def check_binary_post_scan(
    repo_root: Path,
    report: TruthAtlasReport,
) -> dict[str, object]:
    """Run passive `BIN-ENT-001` checks when `--binary` artifacts are active in scope."""
    active_paths = get_active_binary_paths()
    if not active_paths:
        return {
            "binary_detected": False,
            "findings": [],
            "notes": [],
        }

    items, _ = inspect_binary_artifacts(repo_root, active_paths, allow_external=True)
    cand_findings, warn_notes = _build_drift_findings_and_notes(repo_root, report, items)
    existing_keys = {(f.rule_code, f.source_file, f.line) for f in report.findings}
    filtered = [
        cf for cf in cand_findings if (cf.rule_code, cf.source_file, cf.line) not in existing_keys
    ]
    return {
        "binary_detected": True,
        "artifact_count": len(items),
        "findings": filtered,
        "notes": warn_notes,
    }


def correlate_binary_companions(
    repo_root: Path | str,
    report: TruthAtlasReport,
    binary_paths: str | Path | Sequence[str | Path] | None = None,
    **extra: object,
) -> dict[str, object]:
    """Correlate passive Mach-O/ELF Zoom-3 artifacts against `repo_root` `.entitlements`."""
    root_p = Path(repo_root)
    explicit = (
        binary_paths
        or extra.get("binary")
        or extra.get("binaries")
        or extra.get("binary_path")
    )
    resolved_args = get_active_binary_paths(explicit)
    if not resolved_args:
        return {
            "plugin": "binary",
            "version": "0.1.0",
            "target_slug": getattr(report, "target_slug", "unknown"),
            "source_commit": getattr(report, "source_commit", "unknown"),
            "z0_content_digest": getattr(report, "content_digest", ""),
            "target_code_executed": False,
            "automated_security_audit": False,
            "subprocesses_invoked": 0,
            "non_certification_disclaimer": NON_CERTIFICATION_NOTICE,
            "present": False,
            "artifact_count": 0,
            "artifacts": [],
            "source_entitlements": [s.rel_path for s in discover_repo_entitlements(root_p)],
            "privilege_drift_count": 0,
            "omitted_capability_count": 0,
            "findings": [],
            "warnings": [],
            "wall_ties": [],
        }

    items, specs = inspect_binary_artifacts(root_p, resolved_args, allow_external=True)
    cand_findings, warn_notes = _build_drift_findings_and_notes(root_p, report, items)

    artifacts_out: list[dict[str, object]] = []
    wall_ties: list[dict[str, object]] = []
    node_by_file = {n.source_file: n.id for n in getattr(report, "nodes", ())}
    default_nid = next(
        (n.id for n in getattr(report, "nodes", ()) if n.tier == "manipulate"),
        "m:binary:default",
    )

    for idx, item in enumerate(items, start=1):
        cap = item.capture
        drift = item.drift
        artifacts_out.append(
            {
                "name": item.display_name,
                "path": item.resolved_path,
                "format": cap.binary_format,
                "source_kind": cap.source_kind,
                "architectures": list(cap.architectures),
                "is_universal": cap.is_universal,
                "linked_libraries": [asdict(lb) for lb in cap.linked_libraries],
                "rpaths": list(cap.rpaths),
                "runpaths": list(cap.runpaths),
                "soname": cap.soname,
                "exported_symbol_count": len(cap.exported_symbols),
                "imported_symbol_count": len(cap.imported_symbols),
                "exported_symbols": [asdict(s) for s in cap.exported_symbols[:64]],
                "imported_symbols": [asdict(s) for s in cap.imported_symbols[:64]],
                "reflection_descriptors": [asdict(r) for r in cap.reflection_descriptors],
                "string_witnesses": [asdict(w) for w in cap.string_witnesses],
                "entitlements": cap.entitlements,
                "slice_entitlements": {
                    k: dict(v) for k, v in sorted(cap.slice_entitlements.items())
                },
                "slice_has_entitlements_blob": dict(sorted(cap.slice_has_entitlements_blob.items())),
                "linux_capabilities": list(cap.linux_capabilities),
                "matched_source_entitlements": drift.matched_source_file,
                "drift_status": drift.drift_status,
                "undeclared_privileges": list(drift.undeclared_privileges),
                "omitted_capabilities": list(drift.omitted_capabilities),
                "categorized_privileges": drift.categorized_privileges,
                "slice_drift": {
                    k: asdict(v) for k, v in sorted(drift.slice_drift.items())
                },
            }
        )
        src_nid = (
            node_by_file.get(drift.matched_source_file or "")
            if drift.matched_source_file
            else None
        ) or default_nid
        has_drift = drift.drift_status == "exceeded"
        wall_ties.append(
            {
                "id": f"wt:binary:z0->z3:{idx}:{_slug_token(item.display_name)}",
                "logical_key": src_nid,
                "source_node_id": src_nid,
                "target_node_id": f"z3:{src_nid}:bin:{idx}",
                "from_wythe": 0,
                "to_wythe": 3,
                "status": "drift" if has_drift else "intact",
                "kind": "plugin_stratum_mismatch" if has_drift else "plugin_stratum_tie",
                "rule_code": "BIN-ENT-001" if has_drift else None,
                "label": (
                    f"Z=0->Z=3 `{item.display_name}` ({cap.binary_format}, drift={drift.drift_status})"
                ),
            }
        )

    serialized_findings = [
        {
            "rule_code": cf.rule_code,
            "severity": "blocking",
            "blocks_gate": True,
            "node_id": cf.node_id,
            "source_file": cf.source_file,
            "line": cf.line,
            "title": cf.title,
            "detail": cf.detail,
            "remediation": cf.remediation,
        }
        for cf in cand_findings
    ]

    return {
        "plugin": "binary",
        "version": "0.1.0",
        "target_slug": getattr(report, "target_slug", "unknown"),
        "source_commit": getattr(report, "source_commit", "unknown"),
        "z0_content_digest": getattr(report, "content_digest", ""),
        "target_code_executed": False,
        "automated_security_audit": False,
        "subprocesses_invoked": 0,
        "non_certification_disclaimer": NON_CERTIFICATION_NOTICE,
        "present": True,
        "artifact_count": len(items),
        "artifacts": artifacts_out,
        "source_entitlements": [s.rel_path for s in specs],
        "privilege_drift_count": len(serialized_findings),
        "omitted_capability_count": sum(len(i.drift.omitted_capabilities) for i in items),
        "findings": serialized_findings,
        "warnings": warn_notes,
        "wall_ties": wall_ties,
    }


BINARY_INSPECTION_PLUGIN = WythePluginSpec(
    name="binary",
    kind="stratum_inspector",
    origin="entry_point",
    version="0.1.0",
    description=(
        "Passive Zoom-3 static Mach-O and Linux ELF binary, reflection, string-witness, "
        "and signed entitlement privilege drift inspector."
    ),
    enabled_by_default=True,
    supported_zooms=(3,),
    post_scan_hook=check_binary_post_scan,
    stratum_badge_hook=summarize_binary_zoom1_badges,
    stratum_expand_hook=expand_binary_zoom3_stratum,
    rules=(BIN_ENT_001_RULE,),
    companion_handlers={"binary": correlate_binary_companions},
)

WYTHE_PLUGIN = BINARY_INSPECTION_PLUGIN


def register_wythe_plugin() -> WythePluginSpec:
    """Entry-point factory returning `BINARY_INSPECTION_PLUGIN`."""
    return BINARY_INSPECTION_PLUGIN
