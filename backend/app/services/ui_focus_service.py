"""Zero-copy-paste Human <-> Vision/MCP Bridge service (`ui-focus` & `wythe_what_is_this`)."""

from __future__ import annotations

import base64
import json
import re
import tempfile
from collections import Counter
from pathlib import Path

from sqlalchemy.orm import Session

from app.core.clock import utc_now
from app.core.config import load_settings
from app.schemas.atlas import (
    AtlasNode,
    BoundaryFinding,
    DistrictXraySummary,
    LlmNodePointer,
    TruthAtlasReport,
    UiFocusExplainRead,
    UiFocusStatePayload,
    UiFocusSyncAck,
)
from app.services.diff_and_sarif_service import compute_diff_and_blast_radius
from app.services.governance_service import get_target_by_slug, list_targets
from app.services.scanner_service import run_target_scan

_GENERIC_PATH_SEGMENTS = {
    "backend",
    "frontend",
    "src",
    "app",
    "api",
    "v1",
    "routes",
    "services",
    "models",
    "schemas",
    "components",
    "hooks",
    "pages",
    "lib",
    "db",
    "migrations",
    "alembic",
    "versions",
}
_DATA_IMAGE_RE = re.compile(r"^data:image/(png|webp|jpeg);base64,", re.IGNORECASE)


def _resolve_focus_paths() -> tuple[Path, Path]:
    db_url = load_settings().database_url
    if db_url.startswith("sqlite:///") and ":memory:" not in db_url:
        db_file = Path(db_url.removeprefix("sqlite:///")).resolve()
        base_dir = db_file.parent
    else:
        base_dir = Path(tempfile.gettempdir()) / "wythe-ephemeral-focus"
    base_dir.mkdir(parents=True, exist_ok=True)
    return base_dir / "ui_focus_state.json", base_dir / "ui_focus_latest.png"


def derive_node_district(node: AtlasNode) -> str:
    """Mirror `deriveDomainCluster` from `wytheSceneLenses.ts` 1:1."""
    if node.cluster and node.cluster != "core":
        return node.cluster
    segs = [s for s in node.source_file.replace("\\", "/").split("/") if s]
    for s in segs:
        if s not in _GENERIC_PATH_SEGMENTS and "." not in s:
            return s[:18]
    raw_tail = segs[-1] if segs else node.label
    stem = re.sub(r"\.[a-z0-9]+$", "", raw_tail, flags=re.IGNORECASE)
    stem = re.sub(r"(_service|_router|_route|Service|View|Panel|Page)$", "", stem)
    parts = [p for p in re.split(r"[_/-]", stem) if p]
    return (parts[0].lower()[:16] if parts else "core") or "core"


def record_ui_focus(payload: UiFocusStatePayload) -> UiFocusSyncAck:
    """Persist the live browser viewport state + optional annotated WebGL PNG atomically."""
    state_file, png_file = _resolve_focus_paths()
    now = utc_now()
    saved_png: str | None = None
    if payload.snapshot_data_url:
        m = _DATA_IMAGE_RE.match(payload.snapshot_data_url)
        if m:
            raw_b64 = payload.snapshot_data_url[m.end() :]
            img_bytes = base64.b64decode(raw_b64, validate=False)
            tmp_png = png_file.with_suffix(".img.tmp")
            tmp_png.write_bytes(img_bytes)
            tmp_png.replace(png_file)
            saved_png = str(png_file)
    elif png_file.is_file():
        saved_png = str(png_file)

    serialized = payload.model_dump(exclude={"snapshot_data_url"})
    serialized["observed_at"] = now.isoformat()
    serialized["snapshot_path"] = saved_png
    tmp_json = state_file.with_suffix(".json.tmp")
    tmp_json.write_text(json.dumps(serialized, indent=2), encoding="utf-8")
    tmp_json.replace(state_file)
    return UiFocusSyncAck(
        active_slug=payload.active_slug,
        observed_at=now,
        has_snapshot=saved_png is not None,
        snapshot_path=saved_png,
    )


def load_latest_snapshot_png() -> Path | None:
    """Return path to latest annotated 3D viewport PNG if captured."""
    _, png_file = _resolve_focus_paths()
    return png_file if png_file.is_file() else None


def _summarize_district(
    district: str,
    report: TruthAtlasReport,
    crimson_ids: set[str],
) -> DistrictXraySummary:
    d_nodes = [n for n in report.nodes if derive_node_district(n) == district]
    d_ids = {n.id for n in d_nodes}
    d_findings = [f for f in report.findings if f.node_id in d_ids]
    flagged_ids = {n.id for n in d_nodes if n.status != "clean"} | {
        f.node_id for f in d_findings if f.node_id
    }
    rule_counts = Counter(f.rule_code for f in d_findings)
    top_code = rule_counts.most_common(1)[0][0] if rule_counts else None
    top_title = next((f.title for f in d_findings if f.rule_code == top_code), None)
    sample_files = sorted({n.source_file for n in d_nodes})[:4]
    return DistrictXraySummary(
        district=district,
        node_count=len(d_nodes),
        flagged_node_count=len(flagged_ids),
        crimson_diff_count=len(d_ids & crimson_ids),
        top_rule_code=top_code,
        top_rule_title=top_title,
        sample_nodes=[n.label for n in d_nodes[:8]],
        sample_files=sample_files,
    )


def explain_ui_focus(
    session: Session,
    *,
    target_override: str | None = None,
) -> UiFocusExplainRead:
    """Join live GUI viewport state against AST/diff truth to answer 'what is this?'."""
    state_file, png_file = _resolve_focus_paths()
    saved: dict = {}
    if state_file.is_file():
        try:
            saved = json.loads(state_file.read_text(encoding="utf-8"))
        except (OSError, ValueError):
            saved = {}

    slug = target_override or str(saved.get("active_slug") or "")
    target = get_target_by_slug(session, slug) if slug else None
    if target is None:
        all_targets = list_targets(session)
        if not all_targets:
            raise ValueError("No registered Wythe targets available.")
        target = all_targets[0]
        slug = target.slug

    report = run_target_scan(session, target, strict_gate=True, persist_snapshot=False)
    blast_mode = str(saved.get("blast_mode") or "off")
    diff_base_ref = str(saved.get("diff_base_ref") or "HEAD~1")
    lens = str(saved.get("lens") or "status")
    layout_mode = str(saved.get("layout_mode") or "cluster")
    active_tab = str(saved.get("active_tab") or "3d")

    crimson_ids: set[str] = set()
    touched_ids: set[str] = set()
    impacted_ids: set[str] = set()
    if blast_mode == "git":
        diff_rep = compute_diff_and_blast_radius(
            Path(target.repo_path).resolve(), report, base_ref=diff_base_ref
        )
        crimson_ids = {f.node_id for f in diff_rep.new_findings if f.node_id}
        touched_ids = set(diff_rep.touched_node_ids)
        impacted_ids = (
            set(diff_rep.impacted_display_nodes)
            | set(diff_rep.impacted_manipulator_nodes)
            | set(diff_rep.impacted_truth_nodes)
        )

    nodes_by_id = {n.id: n for n in report.nodes}
    selected_nid = saved.get("selected_node_id")
    hovered_nid = saved.get("hovered_node_id")
    focus_nid = selected_nid or hovered_nid
    focus_node = nodes_by_id.get(str(focus_nid)) if focus_nid else None
    secondary_hover_node = (
        nodes_by_id.get(str(hovered_nid))
        if (hovered_nid and selected_nid and hovered_nid != selected_nid)
        else None
    )

    district = str(saved.get("focused_district") or "")
    if not district and focus_node is not None:
        district = derive_node_district(focus_node)
    if not district:
        # Pick dominant crimson/flagged district currently in view
        flagged_by_dist = Counter(
            derive_node_district(nodes_by_id[nid])
            for nid in (crimson_ids or {f.node_id for f in report.findings if f.node_id in nodes_by_id})
            if nid in nodes_by_id
        )
        if flagged_by_dist:
            district = flagged_by_dist.most_common(1)[0][0]

    dist_summary = _summarize_district(district, report, crimson_ids) if district else None
    active_findings: list[BoundaryFinding] = []
    cone_edges: list[str] = []
    ptr: LlmNodePointer | None = None

    if focus_node is not None:
        ptr = LlmNodePointer(
            id=focus_node.id,
            tier=focus_node.tier,
            subkind=focus_node.subkind,
            label=focus_node.label,
            pointer=f"{focus_node.source_file}:{focus_node.line}",
            status=focus_node.status,
            columns=list(focus_node.columns[:8]),
            http_paths=list(focus_node.http_paths[:6]),
        )
        active_findings = [
            f
            for f in report.findings
            if f.node_id == focus_node.id or f.target_node_id == focus_node.id
        ][:12]
        cone_edges = [
            f"{e.source_id} --[{e.kind} | {e.verification}]--> {e.target_id}"
            + (f" @ {e.evidence_path}" if e.evidence_path else "")
            + (f" — {e.evidence_note}" if e.evidence_note else "")
            for e in report.edges
            if e.source_id == focus_node.id or e.target_id == focus_node.id
        ][:16]
    elif dist_summary is not None:
        d_ids = {n.id for n in report.nodes if derive_node_district(n) == district}
        active_findings = [
            f
            for f in report.findings
            if f.node_id in d_ids or f.target_node_id in d_ids
        ][:12]

    if focus_node and focus_node.id in crimson_ids and active_findings:
        f0 = active_findings[0]
        origin = (
            f" triggered by writer `{f0.node_id}` at `{f0.source_file}:{f0.line}`"
            if f0.target_node_id == focus_node.id and f0.node_id != focus_node.id
            else ""
        )
        color_reason = (
            f"Glowing crimson in 3D Blast ({diff_base_ref}) because `{focus_node.label}` has "
            f"`{f0.rule_code}` ({f0.severity}){origin}: {f0.title}."
        )
    elif focus_node and active_findings:
        f0 = active_findings[0]
        if f0.target_node_id == focus_node.id and f0.node_id != focus_node.id:
            color_reason = (
                f"Flagged by causal writer finding `{f0.rule_code}` ({f0.severity}) at "
                f"`{f0.source_file}:{f0.line}` (`{f0.node_id}`): {f0.title}."
            )
        else:
            color_reason = f"Flagged by `{f0.rule_code}` ({f0.severity}): {f0.title}."
    elif focus_node and focus_node.id in touched_ids:
        color_reason = f"Glowing amber in 3D Blast ({diff_base_ref}) because `{focus_node.source_file}` changed."
    elif focus_node and focus_node.id in impacted_ids:
        color_reason = f"Glowing sky-blue in 3D Blast ({diff_base_ref}) because it sits in the transitive blast cone."
    elif dist_summary and dist_summary.top_rule_code:
        color_reason = (
            f"District `{dist_summary.district}` has {dist_summary.flagged_node_count}/{dist_summary.node_count} "
            f"flagged nodes dominated by `{dist_summary.top_rule_code}` ({dist_summary.top_rule_title})."
        )
    else:
        color_reason = f"Viewing `{target.name}` under lens `{lens}` ({layout_mode} layout)."

    headline = (
        f"{focus_node.tier.upper()} {focus_node.subkind} `{focus_node.label}` in district `{district}`"
        if focus_node
        else f"District `{district}` in `{target.slug}`" if district else f"Overview of `{target.slug}`"
    )
    has_snap = png_file.is_file()
    snap_path = str(png_file) if has_snap else None

    md_lines = [
        f"# Wythe Live Focus X-Ray :: `{target.slug}` @ `{report.source_commit[:10]}`",
        f"> Tab: `{active_tab}` | Lens: `{lens}` | Layout: `{layout_mode}` | Blast: `{blast_mode}` ({diff_base_ref})",
        f"> Connected only: `{saved.get('connected_only', False)}` | Neighborhood hops: `{saved.get('neighborhood_hops', 0)}`",
        f"> **Headline**: {headline}",
        f"> **Why It Looks Like This**: {color_reason}",
    ]
    if ptr is not None:
        md_lines.append(
            f"- **Focused Node**: `{ptr.id}` (discovery pointer `{ptr.pointer}`) — status=`{ptr.status}`"
        )
    if focus_node is not None and focus_node.store_purpose is not None:
        sp = focus_node.store_purpose
        src_desc = sp.authoritative_source or "unspecified"
        pol_desc = sp.refresh_policy or "unspecified"
        rec_desc = sp.recovery_expectation or "unspecified"
        ks_desc = f" · keyspace_scope=`{sp.keyspace_scope}`" if sp.keyspace_scope else ""
        md_lines.append(
            f"- **Declared Purpose**: `{sp.intended_use}` (source=`{src_desc}`, refresh=`{pol_desc}`, "
            f"recovery=`{rec_desc}`{ks_desc})"
        )
        md_lines.append(
            f"- **Verification**: {sp.verification_summary or focus_node.verification_note or 'not verified'}"
        )
    elif focus_node is not None and focus_node.verification_note:
        md_lines.append(f"- **Verification**: {focus_node.verification_note}")
    if focus_node is not None and (
        focus_node.subkind == "cache_store" or focus_node.status in ("gray_zone", "duplicated_truth")
    ):
        md_lines.append(
            "- **Evidence Guardrail**: Color/status or `default:*` grouping alone does not prove "
            "duplicate contents, shared keys, or safe deletion; check causal findings and source edges."
        )
    if secondary_hover_node is not None:
        md_lines.append(
            f"- **Cursor Also Hovering**: `{secondary_hover_node.id}` "
            f"(`{secondary_hover_node.source_file}:{secondary_hover_node.line}`, status=`{secondary_hover_node.status}`)"
        )
    if dist_summary is not None:
        md_lines.append(
            f"- **District `{dist_summary.district}`**: {dist_summary.node_count} nodes "
            f"({dist_summary.flagged_node_count} flagged, {dist_summary.crimson_diff_count} crimson in diff) "
            f"across {', '.join(f'`{p}`' for p in dist_summary.sample_files)}"
        )
        md_lines.append(f"  - Sample nodes: {', '.join(f'`{n}`' for n in dist_summary.sample_nodes)}")
    live_vp = str(saved.get("live_viewport_brief") or "").strip()
    if live_vp:
        md_lines.append("\n" + live_vp)
    if active_findings:
        md_lines.append("\n## Active Findings Explaining Highlight (Requires Review)")
        for f in active_findings[:8]:
            writer_tag = (
                f" (causal writer `{f.node_id}` -> `{f.target_node_id}`)"
                if f.target_node_id and f.target_node_id != f.node_id
                else ""
            )
            md_lines.append(
                f"- **{f.rule_code}** [{f.severity} | {f.confidence} | {f.evidence_strength}] "
                f"`{f.source_file}:{f.line}`{writer_tag} — "
                f"{f.title} | Suggested remediation (unverified): {f.remediation}"
            )
    if cone_edges:
        md_lines.append("\n## Immediate Connected Edges (Static Scope)")
        md_lines.append(
            "- Scope: static AST/route/config links (`verified`, `declared`, `unverified`, `broken`); does not prove runtime behavior."
        )
        for ce in cone_edges[:10]:
            md_lines.append(f"- `{ce}`")
    if snap_path:
        md_lines.append(f"\n> Annotated Viewport PNG: `{snap_path}`")

    return UiFocusExplainRead(
        active_slug=target.slug,
        target_name=target.name,
        source_commit=report.source_commit,
        observed_at=utc_now(),
        active_tab=active_tab,
        lens=lens,
        layout_mode=layout_mode,
        blast_mode=blast_mode,
        diff_base_ref=diff_base_ref,
        headline=headline,
        color_reason=color_reason,
        focused_node=ptr,
        focused_district=dist_summary,
        active_findings=active_findings,
        cone_edges=cone_edges,
        has_snapshot=has_snap,
        snapshot_path=snap_path,
        markdown_brief="\n".join(md_lines),
    )
