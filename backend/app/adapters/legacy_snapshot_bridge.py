"""Bridge for curated legacy `truth_atlas_snapshot.json` receipts and cutover provenance.

Preserves mechanical static-signature receipt checks (`absent_is_cutover` /
`present_is_cutover`) and human `layman` / `cutover_note` provenance, while
keeping completed transitions `clean` rather than conflating history with status.
"""

from __future__ import annotations

import json
import re
from datetime import date
from pathlib import Path

from app.schemas.atlas import AtlasNode, LegacyBridgeSummary, LegacyReceiptItem

_LEGACY_STATUS_MAP = {
    "clean": "clean",
    "cutover": "clean",  # Completed transitions stay clean; provenance lives in cutover_history
    "red": "duplicated_truth",
    "orange": "policy_in_code",
    "yellow": "gray_zone",
    "fabricated": "duplicated_truth",
    "orphaned": "orphaned",
}


def _search_target(target: Path, pattern: re.Pattern[str]) -> bool:
    if target.is_file():
        return pattern.search(target.read_text(encoding="utf-8", errors="replace")) is not None
    if target.is_dir():
        for py_path in target.rglob("*.py"):
            if "__pycache__" in py_path.parts:
                continue
            if pattern.search(py_path.read_text(encoding="utf-8", errors="replace")) is not None:
                return True
        return False
    raise OSError(f"Missing target: {target}")


def apply_legacy_snapshot_bridge(
    repo_root: Path,
    legacy_relpath: str | None,
    nodes: list[AtlasNode],
) -> LegacyBridgeSummary:
    """Verify legacy snapshot receipts if configured and enrich matching nodes."""
    if not legacy_relpath:
        return LegacyBridgeSummary(present=False)

    snap_path = (repo_root / legacy_relpath).resolve()
    if not snap_path.is_file():
        return LegacyBridgeSummary(present=False)

    try:
        raw = json.loads(snap_path.read_text(encoding="utf-8"))
    except (OSError, UnicodeError, json.JSONDecodeError):
        return LegacyBridgeSummary(present=False)

    meta = raw.get("meta") or {}
    audited_raw = meta.get("audited_at")
    audited_date = date.fromisoformat(audited_raw) if isinstance(audited_raw, str) else None

    receipt_items: list[LegacyReceiptItem] = []
    verified_cnt = 0
    changed_cnt = 0
    error_cnt = 0

    for spec in raw.get("evidence") or []:
        nid = str(spec.get("node_id", ""))
        rel_p = str(spec.get("path", ""))
        pat_str = str(spec.get("pattern", ""))
        mode = str(spec.get("mode", "absent_is_cutover"))
        target = (repo_root / rel_p).resolve()
        try:
            if repo_root.resolve() not in target.parents and target != repo_root.resolve():
                raise OSError("Escaped repo root")
            present = _search_target(target, re.compile(pat_str))
            if mode == "absent_is_cutover":
                res = "verified_present" if present else "changed"
                note = (
                    "Audited source signature remains present."
                    if present
                    else "Audited signature changed or vanished; human review needed."
                )
            else:
                res = "changed" if present else "verified_absent"
                note = (
                    "Replacement signature appeared; human review needed."
                    if present
                    else "Replacement signature remains absent."
                )
        except (OSError, re.error):
            res = "error"
            note = "Evidence target could not be checked."

        if res in ("verified_present", "verified_absent"):
            verified_cnt += 1
        elif res == "changed":
            changed_cnt += 1
        else:
            error_cnt += 1

        if len(receipt_items) < 40 or res in ("changed", "error"):
            receipt_items.append(
                LegacyReceiptItem(node_id=nid, result=res, path=rel_p, note=note)  # type: ignore[arg-type]
            )

    nodes_by_table_label = {n.label.lower(): n for n in nodes if n.tier == "truth"}
    nodes_by_source = {n.source_file: n for n in nodes}

    matched_cnt = 0
    cutover_reclassified = 0

    for tbl in raw.get("tables") or []:
        lbl = str(tbl.get("label", "")).lower()
        node = nodes_by_table_label.get(lbl)
        if node is None:
            continue
        matched_cnt += 1
        layman = tbl.get("layman")
        if isinstance(layman, str) and layman:
            node.summary = layman
        cut_note = tbl.get("cutover_note")
        if isinstance(cut_note, str) and cut_note:
            node.cutover_history = cut_note
        raw_st = str(tbl.get("status", "clean"))
        if raw_st == "cutover":
            cutover_reclassified += 1
        mapped_st = _LEGACY_STATUS_MAP.get(raw_st, "clean")
        if node.status == "clean" and mapped_st != "clean":
            node.status = mapped_st  # type: ignore[assignment]

    for comp in raw.get("components") or []:
        raw_st = str(comp.get("status", "clean"))
        if raw_st == "cutover":
            cutover_reclassified += 1
        comp_file = str(comp.get("file", ""))
        cand_path = comp_file if comp_file.startswith("backend/") else f"backend/{comp_file}"
        node = nodes_by_source.get(cand_path)
        if node is None:
            continue
        matched_cnt += 1
        layman = comp.get("layman")
        if isinstance(layman, str) and layman:
            node.summary = layman
        cut_note = comp.get("cutover_note")
        if isinstance(cut_note, str) and cut_note:
            node.cutover_history = cut_note
        mapped_st = _LEGACY_STATUS_MAP.get(raw_st, "clean")
        if node.status == "clean" and mapped_st != "clean":
            node.status = mapped_st  # type: ignore[assignment]

    return LegacyBridgeSummary(
        present=True,
        snapshot_title=str(meta.get("title", "Curated Truth Atlas Snapshot")),
        audited_at=audited_date,
        snapshot_commit=str(meta.get("snapshot_commit", "")) or None,
        receipts_checked=verified_cnt + changed_cnt + error_cnt,
        receipts_verified=verified_cnt,
        receipts_changed=changed_cnt,
        receipts_error=error_cnt,
        curated_nodes_matched=matched_cnt,
        cutover_reclassified_count=cutover_reclassified,
        sample_receipts=receipt_items[:50],
    )
