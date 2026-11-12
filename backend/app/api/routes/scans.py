"""Routes executing 3-tier Truth Atlas scans, history queries, and ratchet captures."""

from __future__ import annotations

from pathlib import Path
from typing import Annotated, Any

from fastapi import APIRouter, Depends, HTTPException, Query
from fastapi.responses import PlainTextResponse
from sqlalchemy.orm import Session

from app.db.session import get_db
from app.schemas.atlas import (
    DiffBlastRadiusReport,
    LlmBriefRead,
    LlmContextConeReport,
    RatchetBaselineRead,
    RatchetCaptureRequest,
    ScanSnapshotSummary,
    SnapshotComparisonReport,
    SourceSnippetRead,
    TruthAtlasReport,
)
from app.services.diff_and_sarif_service import (
    build_sarif_log,
    compare_recorded_snapshots,
    compute_diff_and_blast_radius,
)
from app.services.gate_service import list_recent_snapshots
from app.services.governance_service import (
    capture_ratchet_baselines,
    get_target_by_slug,
    list_ratchet_baselines,
)
from app.services.llm_context_service import (
    DEFAULT_BRIEF_TOKENS,
    DEFAULT_CONE_NODES,
    build_lineage_cone_slice,
    build_llms_txt_brief,
)
from app.services.scanner_service import run_target_scan
from app.services.source_peek_service import (
    SourcePeekPermissionError,
    read_target_source_snippet,
)

router = APIRouter()
DbSession = Annotated[Session, Depends(get_db)]
BoolFlag = Annotated[bool, Query()]


@router.get("/{target_slug}", response_model=TruthAtlasReport)
def inspect_target(
    target_slug: str,
    db: DbSession,
    strict: BoolFlag = False,
    persist: BoolFlag = False,
) -> TruthAtlasReport:
    target = get_target_by_slug(db, target_slug)
    if target is None:
        raise HTTPException(status_code=404, detail=f"Target '{target_slug}' not found")
    return run_target_scan(db, target, strict_gate=strict, persist_snapshot=persist)


@router.post("/{target_slug}", response_model=TruthAtlasReport)
def execute_recorded_scan(
    target_slug: str,
    db: DbSession,
    strict: BoolFlag = False,
) -> TruthAtlasReport:
    target = get_target_by_slug(db, target_slug)
    if target is None:
        raise HTTPException(status_code=404, detail=f"Target '{target_slug}' not found")
    return run_target_scan(db, target, strict_gate=strict, persist_snapshot=True)


@router.get("/{target_slug}/history", response_model=list[ScanSnapshotSummary])
def get_scan_history(
    target_slug: str,
    db: DbSession,
) -> list[ScanSnapshotSummary]:
    target = get_target_by_slug(db, target_slug)
    if target is None:
        raise HTTPException(status_code=404, detail=f"Target '{target_slug}' not found")
    return list_recent_snapshots(db, target.id)


@router.get("/{target_slug}/compare", response_model=SnapshotComparisonReport)
def compare_snapshots_route(
    target_slug: str,
    db: DbSession,
    base_id: Annotated[int, Query(ge=1)],
    head_id: Annotated[int, Query(ge=1)],
) -> SnapshotComparisonReport:
    target = get_target_by_slug(db, target_slug)
    if target is None:
        raise HTTPException(status_code=404, detail=f"Target '{target_slug}' not found")
    comparison = compare_recorded_snapshots(
        db, target.id, target.slug, base_snapshot_id=base_id, head_snapshot_id=head_id
    )
    if comparison is None:
        raise HTTPException(
            status_code=404,
            detail=f"One or both snapshots ({base_id}, {head_id}) not found for '{target_slug}'",
        )
    return comparison


@router.get("/{target_slug}/baselines", response_model=list[RatchetBaselineRead])
def get_ratchet_baselines(
    target_slug: str,
    db: DbSession,
) -> list[RatchetBaselineRead]:
    target = get_target_by_slug(db, target_slug)
    if target is None:
        raise HTTPException(status_code=404, detail=f"Target '{target_slug}' not found")
    return list_ratchet_baselines(db, target.id)


@router.post("/{target_slug}/baselines", response_model=list[RatchetBaselineRead])
def save_ratchet_baselines(
    target_slug: str,
    payload: RatchetCaptureRequest,
    db: DbSession,
) -> list[RatchetBaselineRead]:
    target = get_target_by_slug(db, target_slug)
    if target is None:
        raise HTTPException(status_code=404, detail=f"Target '{target_slug}' not found")
    report = run_target_scan(db, target, strict_gate=True, persist_snapshot=True)
    return capture_ratchet_baselines(db, target.id, report, payload)


@router.get("/{target_slug}/diff", response_model=DiffBlastRadiusReport)
def inspect_target_diff(
    target_slug: str,
    db: DbSession,
    base_ref: Annotated[str, Query(min_length=1, max_length=128)] = "HEAD~1",
) -> DiffBlastRadiusReport:
    target = get_target_by_slug(db, target_slug)
    if target is None:
        raise HTTPException(status_code=404, detail=f"Target '{target_slug}' not found")
    report = run_target_scan(db, target, strict_gate=True, persist_snapshot=False)
    return compute_diff_and_blast_radius(
        Path(target.repo_path).resolve(), report, base_ref=base_ref
    )


@router.get("/{target_slug}/sarif")
def export_target_sarif(
    target_slug: str,
    db: DbSession,
    base_ref: Annotated[str | None, Query(max_length=128)] = None,
) -> dict[str, Any]:
    target = get_target_by_slug(db, target_slug)
    if target is None:
        raise HTTPException(status_code=404, detail=f"Target '{target_slug}' not found")
    report = run_target_scan(db, target, strict_gate=True, persist_snapshot=False)
    if base_ref:
        diff_report = compute_diff_and_blast_radius(
            Path(target.repo_path).resolve(), report, base_ref=base_ref
        )
        return build_sarif_log(report, findings_override=diff_report.new_findings)
    return build_sarif_log(report)


@router.get("/{target_slug}/llms", response_model=LlmBriefRead)
def export_target_llms_brief(
    target_slug: str,
    db: DbSession,
    max_tokens: Annotated[int, Query(ge=400, le=12000)] = DEFAULT_BRIEF_TOKENS,
) -> LlmBriefRead:
    target = get_target_by_slug(db, target_slug)
    if target is None:
        raise HTTPException(status_code=404, detail=f"Target '{target_slug}' not found")
    report = run_target_scan(db, target, strict_gate=True, persist_snapshot=False)
    return build_llms_txt_brief(report, max_tokens=max_tokens)


@router.get("/{target_slug}/llms.txt", response_class=PlainTextResponse)
def export_target_llms_plaintext(
    target_slug: str,
    db: DbSession,
    max_tokens: Annotated[int, Query(ge=400, le=12000)] = DEFAULT_BRIEF_TOKENS,
) -> PlainTextResponse:
    target = get_target_by_slug(db, target_slug)
    if target is None:
        raise HTTPException(status_code=404, detail=f"Target '{target_slug}' not found")
    report = run_target_scan(db, target, strict_gate=True, persist_snapshot=False)
    brief = build_llms_txt_brief(report, max_tokens=max_tokens)
    return PlainTextResponse(content=brief.markdown + "\n")


@router.get("/{target_slug}/context", response_model=LlmContextConeReport)
def export_target_lineage_cone_context(
    target_slug: str,
    db: DbSession,
    q: Annotated[str, Query(min_length=1, max_length=256)],
    max_nodes: Annotated[int, Query(ge=5, le=150)] = DEFAULT_CONE_NODES,
) -> LlmContextConeReport:
    target = get_target_by_slug(db, target_slug)
    if target is None:
        raise HTTPException(status_code=404, detail=f"Target '{target_slug}' not found")
    report = run_target_scan(db, target, strict_gate=True, persist_snapshot=False)
    return build_lineage_cone_slice(report, q, max_nodes=max_nodes)


@router.get("/{target_slug}/source", response_model=SourceSnippetRead)
def read_target_source_route(
    target_slug: str,
    db: DbSession,
    rel_path: Annotated[str, Query(min_length=1, max_length=512)],
    line: Annotated[int, Query(ge=1, le=500000)] = 1,
    context: Annotated[int, Query(ge=3, le=45)] = 12,
) -> SourceSnippetRead:
    target = get_target_by_slug(db, target_slug)
    if target is None:
        raise HTTPException(status_code=404, detail=f"Target '{target_slug}' not found")
    try:
        return read_target_source_snippet(
            Path(target.repo_path).resolve(),
            target.slug,
            rel_path,
            focus_line=line,
            context_lines=context,
        )
    except SourcePeekPermissionError as exc:
        raise HTTPException(status_code=403, detail=str(exc)) from exc
    except FileNotFoundError as exc:
        raise HTTPException(status_code=404, detail=str(exc)) from exc
