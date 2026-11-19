"""Zero-copy-paste Human <-> Vision/MCP Bridge service (`ui-focus` & `wythe_what_is_this`)."""

from __future__ import annotations

import base64
import difflib
import json
import os
import re
import tempfile
from collections import Counter
from pathlib import Path
from typing import Any

from sqlalchemy.orm import Session

from app.core.clock import utc_now
from app.core.config import load_settings
from app.models import TargetProject
from app.schemas.atlas import (
    AtlasNode,
    BoundaryFinding,
    ContextBudgetSummary,
    DistrictXraySummary,
    FollowState,
    InvestigationActor,
    LlmNodePointer,
    TruthAtlasReport,
    UiFocusExplainRead,
    UiFocusStatePayload,
    UiFocusSyncAck,
)
from app.services.diff_and_sarif_service import compute_diff_and_blast_radius, run_target_diff
from app.services.governance_service import get_target_by_slug, list_targets
from app.services.investigation_service import (
    build_evidence_identity,
    build_pinned_index,
    get_active_session_ids_for_target,
    get_investigation_session,
    get_or_run_cached_scan,
    get_session_raw_focus_state,
    list_session_corrections,
    sanitize_session_file_token,
    sync_session_focus,
)

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
_DATA_IMAGE_RE = re.compile(r"^data:image/(png|webp|jpeg|jpg);base64,", re.IGNORECASE)
_MIME_TO_EXT: dict[str, str] = {
    "image/webp": ".webp",
    "image/png": ".png",
    "image/jpeg": ".jpg",
}
_EXT_TO_MIME: dict[str, str] = {
    ".webp": "image/webp",
    ".png": "image/png",
    ".jpg": "image/jpeg",
    ".jpeg": "image/jpeg",
}


_ALLOWED_SNAPSHOT_NAMES = frozenset(
    {"ui_focus_latest.webp", "ui_focus_latest.png", "ui_focus_latest.jpg"}
)
_SESSION_SNAP_NAME_RE = re.compile(r"^ui_focus_session_[A-Za-z0-9_-]{1,64}\.(?:webp|png|jpg)$")


def _is_allowed_snapshot_name(name: str) -> bool:
    return name in _ALLOWED_SNAPSHOT_NAMES or bool(_SESSION_SNAP_NAME_RE.match(name))


def _resolve_focus_dir() -> Path:
    explicit_state = os.getenv("WYTHE_STATE_DIR") or os.getenv("TRUTH_ATLAS_STATE_DIR")
    if explicit_state:
        base_dir = Path(explicit_state).expanduser()
        if base_dir.is_symlink():
            raise RuntimeError(f"Refusing symlinked focus directory: {base_dir}")
        resolved_dir = base_dir.resolve()
        resolved_dir.mkdir(parents=True, exist_ok=True)
        return resolved_dir

    db_url = load_settings().database_url
    if db_url.startswith("sqlite:///") and ":memory:" not in db_url:
        db_file = Path(db_url.removeprefix("sqlite:///")).resolve()
        base_dir = db_file.parent
        base_dir.mkdir(parents=True, exist_ok=True)
        return base_dir

    uid_suffix = str(os.getuid()) if hasattr(os, "getuid") else "local"
    base_dir = Path(tempfile.gettempdir()) / f"wythe-ephemeral-focus-{uid_suffix}"
    if base_dir.is_symlink():
        raise RuntimeError(f"Refusing symlinked ephemeral focus directory: {base_dir}")
    base_dir.mkdir(parents=True, exist_ok=True, mode=0o700)
    try:
        base_dir.chmod(0o700)
    except OSError:
        pass
    if hasattr(os, "getuid"):
        st = base_dir.lstat()
        if st.st_uid != os.getuid():
            raise RuntimeError(f"Refusing foreign-owned ephemeral focus directory: {base_dir}")
    return base_dir


def _resolve_focus_paths() -> tuple[Path, Path]:
    base_dir = _resolve_focus_dir()
    return base_dir / "ui_focus_state.json", base_dir / "ui_focus_latest.png"


def sniff_snapshot_mime(snap_file: Path) -> str:
    try:
        head = snap_file.read_bytes()[:16]
        if len(head) >= 12 and head[:4] == b"RIFF" and head[8:12] == b"WEBP":
            return "image/webp"
        if head.startswith(b"\x89PNG\r\n\x1a\n"):
            return "image/png"
        if head.startswith(b"\xff\xd8\xff"):
            return "image/jpeg"
    except OSError:
        pass
    return _EXT_TO_MIME.get(snap_file.suffix.lower(), "image/png")


_sniff_snapshot_mime = sniff_snapshot_mime


def read_saved_ui_focus_state() -> dict[str, Any]:
    """Read persisted `ui_focus_state.json` safely without raising on missing/corrupt files."""
    state_file, _ = _resolve_focus_paths()
    if state_file.is_symlink() or not state_file.is_file():
        return {}
    try:
        parsed = json.loads(state_file.read_text(encoding="utf-8"))
        return parsed if isinstance(parsed, dict) else {}
    except (OSError, ValueError):
        return {}


def _is_contained_snapshot_file(cand: Path, real_base: Path) -> bool:
    if not _is_allowed_snapshot_name(cand.name) or cand.is_symlink():
        return False
    try:
        resolved = cand.resolve()
    except OSError:
        return False
    return resolved.parent == real_base and resolved.is_relative_to(real_base) and resolved.is_file()


def _find_existing_snapshot(
    base_dir: Path,
    saved: dict[str, Any],
    *,
    stem_prefix: str = "ui_focus_latest",
) -> tuple[Path | None, str | None]:
    if base_dir.is_symlink():
        return None, None
    real_base = base_dir.resolve()
    raw_saved_path = saved.get("snapshot_path")
    if isinstance(raw_saved_path, str) and raw_saved_path.strip():
        raw_cand = Path(raw_saved_path)
        if (
            not raw_cand.is_symlink()
            and _is_allowed_snapshot_name(raw_cand.name)
            and raw_cand.exists()
            and _is_contained_snapshot_file(base_dir / raw_cand.name, real_base)
        ):
            try:
                if raw_cand.resolve() == (base_dir / raw_cand.name).resolve():
                    safe_cand = base_dir / raw_cand.name
                    return safe_cand, sniff_snapshot_mime(safe_cand)
            except OSError:
                pass

    existing = [
        p
        for ext in (".webp", ".png", ".jpg")
        if _is_contained_snapshot_file((p := base_dir / f"{stem_prefix}{ext}"), real_base)
    ]
    if not existing:
        return None, None
    newest = max(existing, key=lambda p: p.stat().st_mtime_ns)
    return newest, sniff_snapshot_mime(newest)


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


def record_ui_focus(
    payload: UiFocusStatePayload,
    db_session: Session | None = None,
) -> UiFocusSyncAck:
    """Persist live browser viewport state + per-session isolated WebP/PNG/JPEG snapshot."""
    base_dir = _resolve_focus_dir()
    state_file = base_dir / "ui_focus_state.json"
    now = utc_now()
    explicit_fields = set(payload.model_fields_set)
    sid = (payload.session_id or "").strip() or None

    if sid is not None:
        raw_sess = get_session_raw_focus_state(sid)
        prev = raw_sess[0] if raw_sess is not None else {}
        snap_stem = f"ui_focus_session_{sanitize_session_file_token(sid)}"
    else:
        prev = read_saved_ui_focus_state()
        snap_stem = "ui_focus_latest"

    same_slug_prev = prev if (prev and prev.get("active_slug") == payload.active_slug) else {}

    def _eff_field(name: str) -> Any:
        val = getattr(payload, name)
        if name in explicit_fields or name not in same_slug_prev:
            return val
        return same_slug_prev[name]

    prev_cam_rev = prev.get("camera_revision")
    effective_cam_rev: int | None = (
        payload.camera_revision
        if payload.camera_revision is not None
        else (int(prev_cam_rev) if isinstance(prev_cam_rev, int) else None)
    )
    saved_snap: str | None = None
    saved_mime: str | None = None
    snap_stale = False
    snap_cam_rev: int | None = (
        int(prev["snapshot_camera_revision"])
        if isinstance(prev.get("snapshot_camera_revision"), int)
        else (int(prev_cam_rev) if isinstance(prev_cam_rev, int) else None)
    )

    wrote_fresh_image = False
    img_bytes: bytes | None = None
    ext = ".webp"
    if payload.snapshot_data_url:
        m = _DATA_IMAGE_RE.match(payload.snapshot_data_url)
        if m:
            raw_fmt = m.group(1).lower()
            saved_mime = "image/jpeg" if raw_fmt in ("jpeg", "jpg") else f"image/{raw_fmt}"
            ext = _MIME_TO_EXT[saved_mime]
            snap_file = base_dir / f"{snap_stem}{ext}"
            raw_b64 = payload.snapshot_data_url[m.end() :]
            img_bytes = base64.b64decode(raw_b64, validate=False)
            tmp_img = base_dir / f"{snap_stem}{ext}.img.tmp"
            tmp_img.write_bytes(img_bytes)
            tmp_img.replace(snap_file)
            for other_ext in _MIME_TO_EXT.values():
                if other_ext != ext:
                    (base_dir / f"{snap_stem}{other_ext}").unlink(missing_ok=True)
            saved_snap = str(snap_file)
            snap_stale = False
            snap_cam_rev = effective_cam_rev
            wrote_fresh_image = True

    if not wrote_fresh_image:
        existing_file, existing_mime = _find_existing_snapshot(
            base_dir, prev, stem_prefix=snap_stem
        )
        if existing_file is not None:
            saved_snap = str(existing_file)
            saved_mime = existing_mime
            already_stale = bool(prev.get("snapshot_stale", False))
            newer_cam = payload.camera_revision is not None and (
                snap_cam_rev is None or payload.camera_revision > snap_cam_rev
            )
            scene_changed = bool(prev) and (
                payload.active_slug != prev.get("active_slug")
                or _eff_field("selected_node_id") != prev.get("selected_node_id")
                or _eff_field("selected_edge_id") != prev.get("selected_edge_id")
                or _eff_field("selected_finding_id") != prev.get("selected_finding_id")
                or _eff_field("lens") != prev.get("lens", "status")
                or _eff_field("layout_mode") != prev.get("layout_mode", "cluster")
                or _eff_field("in_frustum_count") != prev.get("in_frustum_count", 0)
                or _eff_field("camera_position") != prev.get("camera_position")
                or _eff_field("camera_target") != prev.get("camera_target")
                or _eff_field("tier_filter") != prev.get("tier_filter", "all")
                or _eff_field("subkind_filter") != prev.get("subkind_filter", "all")
                or _eff_field("edge_filter") != prev.get("edge_filter", "all")
                or _eff_field("only_flagged") != prev.get("only_flagged", False)
                or _eff_field("isolate_cone") != prev.get("isolate_cone", False)
                or _eff_field("connected_only") != prev.get("connected_only", False)
                or _eff_field("neighborhood_hops") != prev.get("neighborhood_hops", 0)
                or _eff_field("search_query") != prev.get("search_query", "")
                or _eff_field("blast_mode") != prev.get("blast_mode", "off")
                or _eff_field("diff_base_ref") != prev.get("diff_base_ref", "HEAD~1")
                or _eff_field("working_set_only") != prev.get("working_set_only", False)
                or _eff_field("compact_visible") != prev.get("compact_visible", False)
                or _eff_field("flatten_2d") != prev.get("flatten_2d", False)
                or _eff_field("group_by") != prev.get("group_by", "none")
                or _eff_field("z_wythe_slice") != prev.get("z_wythe_slice", "all")
                or _eff_field("zoom_stratum") != prev.get("zoom_stratum", 1)
            )
            snap_stale = already_stale or newer_cam or scene_changed

    serialized = {
        k: _eff_field(k)
        for k in UiFocusStatePayload.model_fields
        if k != "snapshot_data_url"
    }
    serialized["camera_revision"] = effective_cam_rev
    serialized["snapshot_camera_revision"] = snap_cam_rev
    serialized["observed_at"] = now.isoformat()
    serialized["snapshot_path"] = saved_snap
    serialized["snapshot_mime_type"] = saved_mime
    serialized["snapshot_stale"] = snap_stale

    ev_identity = None
    pinned_idx = None
    if db_session is not None:
        target = get_target_by_slug(db_session, payload.active_slug)
        if target is not None:
            rep = get_or_run_cached_scan(db_session, target)
            ev_identity = build_evidence_identity(rep)
            pinned_idx = build_pinned_index(rep)

    if sid is not None:
        if wrote_fresh_image:
            serialized["wrote_fresh_snapshot"] = True
        focus_rev, cur_follow, eff_ev_id = sync_session_focus(
            session_id=sid,
            target_slug=payload.active_slug,
            serialized_focus=serialized,
            client_id=payload.client_id,
            actor=payload.actor,
            follow_state_override=payload.follow_state,
            evidence_identity=ev_identity,
            pinned_index=pinned_idx,
        )
        sibling_sids = get_active_session_ids_for_target(payload.active_slug)
        if len(sibling_sids) <= 1:
            if wrote_fresh_image and img_bytes is not None:
                latest_img = base_dir / f"ui_focus_latest{ext}"
                tmp_latest = base_dir / f"ui_focus_latest{ext}.img.tmp"
                tmp_latest.write_bytes(img_bytes)
                tmp_latest.replace(latest_img)
                for other_ext in _MIME_TO_EXT.values():
                    if other_ext != ext:
                        (base_dir / f"ui_focus_latest{other_ext}").unlink(missing_ok=True)
            tmp_json = state_file.with_suffix(".json.tmp")
            tmp_json.write_text(json.dumps(serialized, indent=2), encoding="utf-8")
            tmp_json.replace(state_file)
        else:
            # Update `active_slug` without leaking per-tab selection or shared snapshot files
            tmp_json = state_file.with_suffix(".json.tmp")
            tmp_json.write_text(
                json.dumps(
                    {
                        "active_slug": payload.active_slug,
                        "observed_at": now.isoformat(),
                    },
                    indent=2,
                ),
                encoding="utf-8",
            )
            tmp_json.replace(state_file)
        snap_f_rev = serialized.get("snapshot_focus_revision")
        snap_ev_rev = serialized.get("snapshot_evidence_revision")
    else:
        focus_rev = int(prev.get("focus_revision") or 0) + 1
        eff_ev_id = (
            ev_identity.evidence_revision_id
            if ev_identity is not None
            else payload.evidence_revision_id
        )
        cur_follow = payload.follow_state or "following"
        snap_f_rev = focus_rev if wrote_fresh_image else prev.get("snapshot_focus_revision")
        snap_ev_rev = eff_ev_id if wrote_fresh_image else prev.get("snapshot_evidence_revision")
        serialized["focus_revision"] = focus_rev
        serialized["evidence_revision_id"] = eff_ev_id
        serialized["snapshot_focus_revision"] = snap_f_rev
        serialized["snapshot_evidence_revision"] = snap_ev_rev
        tmp_json = state_file.with_suffix(".json.tmp")
        tmp_json.write_text(json.dumps(serialized, indent=2), encoding="utf-8")
        tmp_json.replace(state_file)

    return UiFocusSyncAck(
        active_slug=payload.active_slug,
        session_id=sid,
        client_id=payload.client_id,
        actor=payload.actor,
        follow_state=cur_follow,
        focus_revision=focus_rev,
        evidence_revision_id=eff_ev_id,
        observed_at=now,
        has_snapshot=saved_snap is not None,
        snapshot_path=saved_snap,
        snapshot_mime_type=saved_mime,
        camera_revision=effective_cam_rev,
        snapshot_focus_revision=snap_f_rev if isinstance(snap_f_rev, int) else None,
        snapshot_evidence_revision=str(snap_ev_rev) if snap_ev_rev else None,
        snapshot_stale=snap_stale,
    )


def load_latest_snapshot_png(session_id: str | None = None) -> Path | None:
    """Return path to latest annotated 3D viewport snapshot (per-session when isolated)."""
    base_dir = _resolve_focus_dir()
    sid = (session_id or "").strip() or None
    if sid is not None:
        raw_sess = get_session_raw_focus_state(sid)
        if raw_sess is None:
            return None
        stem = f"ui_focus_session_{sanitize_session_file_token(sid)}"
        snap_file, _ = _find_existing_snapshot(base_dir, raw_sess[0], stem_prefix=stem)
        return snap_file

    saved = read_saved_ui_focus_state()
    slug = str(saved.get("active_slug") or "").strip()
    if slug:
        active_sids = get_active_session_ids_for_target(slug)
        if len(active_sids) >= 2:
            return None
        if len(active_sids) == 1:
            raw_one = get_session_raw_focus_state(active_sids[0])
            if raw_one is not None:
                stem_one = f"ui_focus_session_{sanitize_session_file_token(active_sids[0])}"
                snap_one, _ = _find_existing_snapshot(
                    base_dir, raw_one[0], stem_prefix=stem_one
                )
                if snap_one is not None:
                    return snap_one
    snap_file, _ = _find_existing_snapshot(base_dir, saved)
    return snap_file


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
    target_project: TargetProject | None = None,
    precomputed_report: TruthAtlasReport | None = None,
    session_id: str | None = None,
) -> UiFocusExplainRead:
    """Join live GUI viewport state against cached AST/diff truth with multi-tab isolation."""
    base_dir = _resolve_focus_dir()
    explicit_sid = (session_id or "").strip() or None
    saved_legacy = read_saved_ui_focus_state()

    resolved_sid: str | None = None
    focus_rev = 0
    follow_state: FollowState = "following"
    ambiguous_session_ids: list[str] = []
    saved: dict[str, Any] = saved_legacy

    if explicit_sid is not None:
        raw_sess = get_session_raw_focus_state(explicit_sid)
        if raw_sess is None:
            raise ValueError(f"Unknown investigation session `{explicit_sid}`.")
        resolved_sid = explicit_sid
        saved, focus_rev, follow_state, _ = raw_sess

    if target_project is not None:
        target = target_project
    elif target_override is not None and target_override.strip():
        ovr = target_override.strip()
        target = get_target_by_slug(session, ovr)
        if target is None:
            registered = [t.slug for t in list_targets(session)]
            close = difflib.get_close_matches(ovr.lower(), registered, n=4, cutoff=0.4)
            known_str = ", ".join(f"`{s}`" for s in registered) if registered else "none"
            close_str = f" Closest match(es): {', '.join(f'`{c}`' for c in close)}." if close else ""
            raise ValueError(
                f"Unknown target `{ovr}`.{close_str} Registered target slugs: {known_str}."
            )
    else:
        slug = str(saved.get("active_slug") or "")
        if not slug and explicit_sid is not None:
            inv_obj = get_investigation_session(explicit_sid)
            if inv_obj is not None:
                slug = inv_obj.target_slug
        target = get_target_by_slug(session, slug) if slug else None
        if target is None:
            all_targets = list_targets(session)
            if not all_targets:
                raise ValueError("No registered Wythe targets available.")
            target = all_targets[0]

    if explicit_sid is None:
        active_sids = get_active_session_ids_for_target(target.slug)
        if len(active_sids) >= 2:
            ambiguous_session_ids = active_sids
            saved = {"active_slug": target.slug}
            focus_rev = 0
        elif len(active_sids) == 1:
            resolved_sid = active_sids[0]
            raw_one = get_session_raw_focus_state(resolved_sid)
            if raw_one is not None:
                saved, focus_rev, follow_state, _ = raw_one
        else:
            focus_rev = int(saved_legacy.get("focus_revision") or 0)
            follow_state = (
                saved_legacy["follow_state"]
                if saved_legacy.get("follow_state") in ("following", "paused")
                else "following"
            )

    report = precomputed_report or get_or_run_cached_scan(
        session, target, strict_gate=True
    )
    ev_identity = build_evidence_identity(report)
    corrections = list_session_corrections(resolved_sid)
    blast_mode = str(saved.get("blast_mode") or "off")
    diff_base_ref = str(saved.get("diff_base_ref") or "HEAD~1")
    lens = str(saved.get("lens") or "status")
    layout_mode = str(saved.get("layout_mode") or "cluster")
    active_tab = str(saved.get("active_tab") or "3d")
    actor: InvestigationActor = (
        saved["actor"] if saved.get("actor") in ("human", "agent", "system") else "human"
    )
    client_id = saved.get("client_id")
    selected_edge_id = saved.get("selected_edge_id")
    selected_finding_id = saved.get("selected_finding_id")

    crimson_ids: set[str] = set()
    touched_ids: set[str] = set()
    impacted_ids: set[str] = set()
    if blast_mode == "git":
        try:
            diff_rep = run_target_diff(session, target, report, diff_base_ref)
        except ValueError:
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
    findings_by_id = {f.id: f for f in report.findings}
    selected_nid = saved.get("selected_node_id")
    hovered_nid = saved.get("hovered_node_id")
    matched_sel_finding = findings_by_id.get(str(selected_finding_id)) if selected_finding_id else None
    focus_nid = selected_nid or hovered_nid or (
        matched_sel_finding.node_id if matched_sel_finding and matched_sel_finding.node_id else None
    )
    focus_node = nodes_by_id.get(str(focus_nid)) if focus_nid else None
    secondary_hover_node = (
        nodes_by_id.get(str(hovered_nid))
        if (hovered_nid and selected_nid and hovered_nid != selected_nid)
        else None
    )

    district = str(saved.get("focused_district") or "")
    if not district and focus_node is not None:
        district = derive_node_district(focus_node)
    if not district and not ambiguous_session_ids:
        flagged_by_dist = Counter(
            derive_node_district(nodes_by_id[nid])
            for nid in (crimson_ids or {f.node_id for f in report.findings if f.node_id in nodes_by_id})
            if nid in nodes_by_id
        )
        if flagged_by_dist:
            district = flagged_by_dist.most_common(1)[0][0]

    dist_summary = _summarize_district(district, report, crimson_ids) if district else None
    eligible_findings: list[BoundaryFinding] = []
    eligible_edges: list[str] = []
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
        eligible_findings = [
            f
            for f in report.findings
            if f.node_id == focus_node.id or f.target_node_id == focus_node.id
        ]
        if matched_sel_finding and matched_sel_finding not in eligible_findings:
            eligible_findings.insert(0, matched_sel_finding)
        eligible_edges = [
            f"{e.source_id} --[{e.kind} | {e.verification}]--> {e.target_id}"
            + (f" @ {e.evidence_path}" if e.evidence_path else "")
            + (f" — {e.evidence_note}" if e.evidence_note else "")
            for e in report.edges
            if e.source_id == focus_node.id or e.target_id == focus_node.id
        ]
    elif matched_sel_finding is not None:
        eligible_findings = [matched_sel_finding]
    elif dist_summary is not None:
        d_ids = {n.id for n in report.nodes if derive_node_district(n) == district}
        eligible_findings = [
            f
            for f in report.findings
            if f.node_id in d_ids or f.target_node_id in d_ids
        ]

    active_findings = eligible_findings[:12]
    cone_edges = eligible_edges[:16]

    if ambiguous_session_ids:
        color_reason = (
            f"Multiple active browser sessions ({', '.join(f'`{s}`' for s in ambiguous_session_ids)}) "
            f"are open on `{target.slug}`; pass `session_id` explicitly so Wythe never guesses another tab's view."
        )
        headline = f"Ambiguous focus across {len(ambiguous_session_ids)} active sessions on `{target.slug}`"
    elif focus_node and focus_node.id in crimson_ids and active_findings:
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
        headline = f"{focus_node.tier.upper()} {focus_node.subkind} `{focus_node.label}` in district `{district}`"
    elif focus_node and active_findings:
        f0 = active_findings[0]
        if f0.target_node_id == focus_node.id and f0.node_id != focus_node.id:
            color_reason = (
                f"Flagged by causal writer finding `{f0.rule_code}` ({f0.severity}) at "
                f"`{f0.source_file}:{f0.line}` (`{f0.node_id}`): {f0.title}."
            )
        else:
            color_reason = f"Flagged by `{f0.rule_code}` ({f0.severity}): {f0.title}."
        headline = f"{focus_node.tier.upper()} {focus_node.subkind} `{focus_node.label}` in district `{district}`"
    elif focus_node and focus_node.id in touched_ids:
        color_reason = f"Glowing amber in 3D Blast ({diff_base_ref}) because `{focus_node.source_file}` changed."
        headline = f"{focus_node.tier.upper()} {focus_node.subkind} `{focus_node.label}` in district `{district}`"
    elif focus_node and focus_node.id in impacted_ids:
        color_reason = f"Glowing sky-blue in 3D Blast ({diff_base_ref}) because it sits in the transitive blast cone."
        headline = f"{focus_node.tier.upper()} {focus_node.subkind} `{focus_node.label}` in district `{district}`"
    elif focus_node:
        color_reason = f"Viewing `{target.name}` under lens `{lens}` ({layout_mode} layout)."
        headline = f"{focus_node.tier.upper()} {focus_node.subkind} `{focus_node.label}` in district `{district}`"
    elif dist_summary and dist_summary.top_rule_code:
        color_reason = (
            f"District `{dist_summary.district}` has {dist_summary.flagged_node_count}/{dist_summary.node_count} "
            f"flagged nodes dominated by `{dist_summary.top_rule_code}` ({dist_summary.top_rule_title})."
        )
        headline = f"District `{district}` in `{target.slug}`"
    else:
        color_reason = f"Viewing `{target.name}` under lens `{lens}` ({layout_mode} layout)."
        headline = f"District `{district}` in `{target.slug}`" if district else f"Overview of `{target.slug}`"

    if ambiguous_session_ids:
        snap_file, detected_mime = None, None
    elif resolved_sid is not None:
        stem = f"ui_focus_session_{sanitize_session_file_token(resolved_sid)}"
        snap_file, detected_mime = _find_existing_snapshot(base_dir, saved, stem_prefix=stem)
    else:
        snap_file, detected_mime = _find_existing_snapshot(base_dir, saved)

    has_snap = snap_file is not None and snap_file.is_file()
    snap_path = str(snap_file) if has_snap else None
    snap_mime = detected_mime if has_snap else None
    raw_cam_rev = saved.get("camera_revision")
    camera_rev = int(raw_cam_rev) if isinstance(raw_cam_rev, int) else None
    snap_f_rev = saved.get("snapshot_focus_revision")
    snap_ev_rev = saved.get("snapshot_evidence_revision")
    saved_slug = str(saved.get("active_slug") or "")
    snap_stale = (
        bool(saved.get("snapshot_stale", False)) or (bool(saved_slug) and saved_slug != target.slug)
    ) if has_snap else False

    tier_filter = str(saved.get("tier_filter") or "all")
    subkind_filter = str(saved.get("subkind_filter") or "all")
    edge_filter = str(saved.get("edge_filter") or "all")
    only_flagged = bool(saved.get("only_flagged", False))
    isolate_cone = bool(saved.get("isolate_cone", False))
    connected_only = bool(saved.get("connected_only", False))
    raw_hops = saved.get("neighborhood_hops", 0)
    neighborhood_hops = raw_hops if raw_hops in (0, 1, 2) and not isinstance(raw_hops, bool) else 0
    search_query = str(saved.get("search_query") or "")
    working_set_only = bool(saved.get("working_set_only", False))
    compact_visible = bool(saved.get("compact_visible", False))
    flatten_2d = bool(saved.get("flatten_2d", False))
    group_by = str(saved.get("group_by") or "none")
    z_wythe_slice = str(saved.get("z_wythe_slice") or "all")
    raw_zoom = saved.get("zoom_stratum", 1)
    zoom_stratum = raw_zoom if raw_zoom in (1, 2, 3) and not isinstance(raw_zoom, bool) else 1
    visible_node_count = max(0, int(saved.get("visible_node_count") or 0))
    in_frustum_count = max(0, int(saved.get("in_frustum_count") or 0))

    md_lines = [
        f"# Wythe Live Focus X-Ray :: `{target.slug}` @ `{ev_identity.source_commit[:16]}`",
        (
            f"> Session: `{resolved_sid or 'default'}` | Focus rev: `{focus_rev}` | "
            f"Evidence: `{ev_identity.evidence_revision_id}` | Follow: `{follow_state}`"
        ),
        f"> Tab: `{active_tab}` | Lens: `{lens}` | Layout: `{layout_mode}` | Blast: `{blast_mode}` ({diff_base_ref})",
        (
            f"> Connected only: `{connected_only}` | Neighborhood hops: `{neighborhood_hops}` | "
            f"tier=`{tier_filter}` | subkind=`{subkind_filter}` | edge=`{edge_filter}` | "
            f"only_flagged=`{only_flagged}` | isolate_cone=`{isolate_cone}` | search=`{search_query}`"
        ),
        (
            f"> Scene Controls: working_set_only=`{working_set_only}` | compact_visible=`{compact_visible}` | "
            f"flatten_2d=`{flatten_2d}` | group_by=`{group_by}` | z_wythe_slice=`{z_wythe_slice}` | "
            f"zoom_stratum=`{zoom_stratum}` | visible_nodes=`{visible_node_count}` (in_frustum=`{in_frustum_count}`)"
        ),
        f"> **Headline**: {headline}",
        f"> **Why It Looks Like This**: {color_reason}",
    ]
    if ambiguous_session_ids:
        md_lines.append("\n## Ambiguous Active Sessions Warning")
        md_lines.append(
            f"- `{len(ambiguous_session_ids)}` independent browser sessions are active on `{target.slug}`. "
            "Pass `session_id` explicitly to inspect a specific tab without cross-tab interference:"
        )
        for amb_sid in ambiguous_session_ids[:8]:
            amb_raw = get_session_raw_focus_state(amb_sid)
            amb_sel = (amb_raw[0].get("selected_node_id") or amb_raw[0].get("selected_finding_id") or "none") if amb_raw else "none"
            md_lines.append(f"  - `session_id=\"{amb_sid}\"` (selection=`{amb_sel}`)")
    if ptr is not None:
        md_lines.append(
            f"- **Focused Node**: `{ptr.id}` (discovery pointer `{ptr.pointer}`) — status=`{ptr.status}`"
        )
    if selected_edge_id:
        md_lines.append(f"- **Selected Edge**: `{selected_edge_id}`")
    if selected_finding_id:
        md_lines.append(f"- **Selected Finding**: `{selected_finding_id}`")
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
    if corrections:
        md_lines.append("\n## Human Investigation Corrections (Active Context)")
        for corr in corrections[-8:]:
            ref_tag = f" on `{corr.target_ref_id}`" if corr.target_ref_id else ""
            md_lines.append(
                f"- **[{corr.kind}]**{ref_tag} (`{corr.correction_id}`, promoted_to_ruling=`False`): {corr.note}"
            )
    live_vp = str(saved.get("live_viewport_brief") or "").strip()
    if live_vp:
        md_lines.append("\n" + live_vp)
    shown_findings = active_findings[:8]
    if shown_findings:
        md_lines.append("\n## Active Findings Explaining Highlight (Requires Review)")
        for f in shown_findings:
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
    shown_edges = cone_edges[:10]
    if shown_edges:
        md_lines.append("\n## Immediate Connected Edges (Static Scope)")
        md_lines.append(
            "- Scope: static AST/route/config links (`verified`, `declared`, `unverified`, `broken`); does not prove runtime behavior."
        )
        for ce in shown_edges:
            md_lines.append(f"- `{ce}`")
    if snap_path:
        freshness = (
            "stale — newer camera/focus telemetry arrived without a frame"
            if snap_stale
            else "fresh"
        )
        rev_tag = f" · camera_revision={camera_rev}" if camera_rev is not None else ""
        md_lines.append(
            f"\n> Annotated Viewport Snapshot ({snap_mime or 'image/png'} · {freshness}{rev_tag}): `{snap_path}`"
        )

    full_md = "\n".join(md_lines)
    omitted_f = max(0, len(eligible_findings) - len(shown_findings))
    omitted_e = max(0, len(eligible_edges) - len(shown_edges))
    trunc_secs = [
        name
        for name, cnt in (("findings", omitted_f), ("cone_edges", omitted_e))
        if cnt > 0
    ]
    budget = ContextBudgetSummary(
        included_counts={
            "findings": len(shown_findings),
            "cone_edges": len(shown_edges),
            "corrections": min(len(corrections), 8),
        },
        omitted_counts={
            "findings": omitted_f,
            "cone_edges": omitted_e,
            "corrections": max(0, len(corrections) - 8),
        },
        truncated_sections=trunc_secs,
        prompt_chars=len(full_md),
        max_prompt_chars=16000,
        expand_hint=(
            f"Call `wythe_lineage_cone(target='{target.slug}', query='{ptr.id if ptr else target.slug}', full=True)` for omitted items."
            if trunc_secs
            else "All eligible focus items included."
        ),
    )

    return UiFocusExplainRead(
        active_slug=target.slug,
        target_name=target.name,
        source_commit=ev_identity.source_commit,
        observed_at=utc_now(),
        session_id=resolved_sid,
        client_id=client_id,
        actor=actor,
        follow_state=follow_state,
        focus_revision=focus_rev,
        evidence_revision_id=ev_identity.evidence_revision_id,
        active_tab=active_tab,
        lens=lens,
        layout_mode=layout_mode,
        blast_mode=blast_mode,
        diff_base_ref=diff_base_ref,
        tier_filter=tier_filter,
        subkind_filter=subkind_filter,
        edge_filter=edge_filter,
        only_flagged=only_flagged,
        isolate_cone=isolate_cone,
        connected_only=connected_only,
        neighborhood_hops=neighborhood_hops,  # type: ignore[arg-type]
        search_query=search_query,
        working_set_only=working_set_only,
        compact_visible=compact_visible,
        flatten_2d=flatten_2d,
        group_by=group_by,
        z_wythe_slice=z_wythe_slice,
        zoom_stratum=zoom_stratum,  # type: ignore[arg-type]
        visible_node_count=visible_node_count,
        in_frustum_count=in_frustum_count,
        headline=headline,
        color_reason=color_reason,
        focused_node=ptr,
        selected_node_id=str(selected_nid) if selected_nid else None,
        selected_edge_id=selected_edge_id,
        selected_finding_id=selected_finding_id,
        focused_district=dist_summary,
        active_findings=active_findings,
        cone_edges=cone_edges,
        has_snapshot=has_snap,
        snapshot_path=snap_path,
        snapshot_mime_type=snap_mime,
        camera_revision=camera_rev,
        snapshot_focus_revision=snap_f_rev if isinstance(snap_f_rev, int) else None,
        snapshot_evidence_revision=str(snap_ev_rev) if snap_ev_rev else None,
        snapshot_stale=snap_stale,
        ambiguous_session_ids=ambiguous_session_ids,
        corrections=corrections,
        evidence_identity=ev_identity,
        context_budget=budget,
        markdown_brief=full_md,
    )
