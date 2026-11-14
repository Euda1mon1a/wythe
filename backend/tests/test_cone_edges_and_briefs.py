"""Regression tests for cone truncation (#46), 4-state edge semantics (#47), and brief epistemics (#48)."""

from __future__ import annotations

import json
import subprocess
from datetime import UTC, datetime, timedelta
from pathlib import Path

from fastapi.testclient import TestClient
from sqlalchemy.orm import Session

from app.adapters.base import RawCandidateFinding
from app.cli import main as cli_main
from app.main import create_app
from app.schemas.atlas import (
    AtlasEdge,
    AtlasNode,
    AtlasSummaryStats,
    BoundaryFinding,
    GateEvaluation,
    LegacyBridgeSummary,
    PortableGovernanceBundle,
    PortableReferenceExemplar,
    TargetProjectCreate,
    TruthAtlasReport,
    UiFocusStatePayload,
)
from app.services.gate_service import evaluate_findings_and_gate
from app.services.governance_service import register_target
from app.services.llm_context_service import build_lineage_cone_slice
from app.services.portable_config_service import build_portable_bundle
from app.services.scanner_service import run_target_scan
from app.services.ui_focus_service import explain_ui_focus, record_ui_focus


def _synthetic_crowded_report() -> TruthAtlasReport:
    now = datetime(2026, 11, 13, 12, 0, tzinfo=UTC)
    nodes: list[AtlasNode] = [
        AtlasNode(
            id="manip:svc:orders",
            label="orders_service",
            tier="manipulate",
            subkind="service",
            status="policy_in_code",
            source_file="backend/services/orders.py",
            line=10,
            role="Order coordinator",
            cluster="orders",
            summary="Synthetic service hub with 39 downstream tables and 1 upstream caller.",
        ),
        AtlasNode(
            id="disp:page:orders",
            label="OrdersPage",
            tier="display",
            subkind="page",
            status="clean",
            source_file="frontend/src/app/orders/page.tsx",
            line=5,
            role="Orders page",
            cluster="orders",
            summary="Upstream display caller.",
        ),
    ]
    edges: list[AtlasEdge] = [
        AtlasEdge(
            id="edge-up-1",
            source_id="disp:page:orders",
            target_id="manip:svc:orders",
            kind="queries_endpoint",
            verification="verified",
            evidence_path="frontend/src/app/orders/page.tsx:12",
            evidence_note="Calls orders service endpoint",
        )
    ]
    for i in range(1, 40):
        tid = f"truth:table:t{i:02d}"
        nodes.append(
            AtlasNode(
                id=tid,
                label=f"table_{i:02d}",
                tier="truth",
                subkind="table",
                status="clean",
                source_file=f"backend/models/t{i:02d}.py",
                line=1,
                role="Table",
                cluster="orders",
                summary="Downstream table.",
            )
        )
        ver = ("verified", "declared", "unverified", "broken")[(i - 1) % 4]
        edges.append(
            AtlasEdge(
                id=f"edge-down-{i:02d}",
                source_id="manip:svc:orders",
                target_id=tid,
                kind="writes_truth",
                verification=ver,  # type: ignore[arg-type]
                evidence_path=f"backend/services/orders.py:{20 + i}",
                evidence_note=f"Downstream link #{i} ({ver})",
            )
        )

    findings = [
        BoundaryFinding(
            id=f"f:seed:{i:02d}",
            rule_code="MANIP-001",
            tier="manipulate",
            severity="blocking",
            blocks_gate=True,
            confidence="confirmed",
            evidence_strength="ast_exact",
            node_id="manip:svc:orders",
            source_file="backend/services/orders.py",
            line=100 + i,
            title=f"Hardcoded policy #{i}",
            detail="Policy threshold literal in code.",
            remediation="Move threshold to DB policy table.",
        )
        for i in range(1, 31)
    ]

    return TruthAtlasReport(
        target_slug="synthetic-crowded",
        target_name="Synthetic Crowded",
        repo_path="/tmp/synthetic-crowded",
        stack_profile="fastapi-sqlalchemy-nextjs",
        source_commit="deadbeef12345678",
        worktree_dirty=True,
        dirty_path_count=3,
        observed_at=now,
        valid_until=now + timedelta(hours=1),
        observation_source="unit-test",
        content_digest="sha256:abc1234567890def",
        summary=AtlasSummaryStats(
            truth_tables=39,
            sql_functions=0,
            manipulator_routes=0,
            manipulator_services=1,
            display_pages=1,
            display_hooks_and_clients=0,
            verified_edges=11,
            end_to_end_chains=0,
            clean_nodes=40,
            flagged_nodes=1,
            blocking_findings=30,
            warning_findings=0,
        ),
        nodes=nodes,
        edges=edges,
        chains=[],
        findings=findings,
        gate=GateEvaluation(
            verdict="FAIL",
            mode="strict",
            blocking_violations=30,
            evaluated_at=now,
        ),
        legacy_bridge=LegacyBridgeSummary(present=False),
    )


def test_cone_truncation_balanced_bfs_full_export_and_4_edge_states() -> None:
    report = _synthetic_crowded_report()

    bounded = build_lineage_cone_slice(report, "manip:svc:orders", max_nodes=40)
    assert bounded.worktree_dirty is True
    assert bounded.dirty_path_count == 3
    assert bounded.content_digest == "sha256:abc1234567890def"
    assert [p.id for p in bounded.upstream_display_nodes] == ["disp:page:orders"]
    assert bounded.completeness is not None
    comp = bounded.completeness
    assert comp.is_complete is False
    assert comp.full_export is False
    assert comp.nodes.included == 40
    assert comp.nodes.eligible == 41
    assert comp.nodes.omitted == 1
    assert comp.upstream_nodes.included == 1
    assert comp.upstream_nodes.omitted == 0
    assert comp.downstream_nodes.included == 38
    assert comp.downstream_nodes.eligible == 39
    assert comp.seed_findings.included == 25
    assert comp.seed_findings.eligible == 30
    assert comp.seed_findings.omitted == 5
    assert comp.markdown_edges.included == 35
    assert comp.edges.eligible == 40
    assert "## Cone Connections (showing 35 of 40; 5 omitted)" in bounded.markdown
    assert "## Verified Cone Edges" not in bounded.markdown
    assert "worktree=dirty(3 paths)" in bounded.markdown
    assert 'wythe context synthetic-crowded "manip:svc:orders" --full' in bounded.markdown
    assert "Verified End-to-End" not in bounded.markdown
    states = {item.verification for item in bounded.cone_edge_items}
    assert states == {"verified", "declared", "unverified", "broken"}
    assert "[writes_truth | declared]" in bounded.markdown
    assert "[writes_truth | unverified]" in bounded.markdown
    assert "[writes_truth | broken]" in bounded.markdown

    full_rep = build_lineage_cone_slice(report, "manip:svc:orders", full=True)
    assert full_rep.completeness is not None
    assert full_rep.completeness.is_complete is True
    assert full_rep.completeness.full_export is True
    assert full_rep.completeness.nodes.included == 41
    assert full_rep.completeness.nodes.omitted == 0
    assert full_rep.completeness.edges.included == 40
    assert full_rep.completeness.markdown_edges.included == 40
    assert full_rep.completeness.seed_findings.included == 30
    assert len(full_rep.cone_findings) == 30
    assert len(full_rep.cone_edge_items) == 40
    assert "## Cone Connections (40)" in full_rep.markdown


def test_gate_epistemics_and_reference_exemplars_preserved(
    db_session: Session,
    tmp_path: Path,
) -> None:
    repo = tmp_path / "gov-exemplar-repo"
    (repo / ".wythe").mkdir(parents=True)
    bundle = PortableGovernanceBundle(
        target_slug="gov-exemplar",
        exported_at=datetime(2026, 11, 13, 12, 0, tzinfo=UTC),
        reference_exemplars=[
            PortableReferenceExemplar(
                title="Canonical Scheduling Service",
                node_id="manip:svc:canon",
                pointer="backend/app/services/canon.py:1",
                applies_to_tiers=["manipulate"],
                applies_to_subkinds=["service"],
                rationale="Approved transactional pattern.",
                approved_by="aaron",
            )
        ],
    )
    (repo / ".wythe" / "governance.json").write_text(bundle.model_dump_json(indent=2), encoding="utf-8")

    raw = [
        RawCandidateFinding(
            rule_code="MANIP-002",
            node_id="manip:svc:clock",
            source_file="backend/svc/clock.py",
            line=12,
            title="Host clock call",
            detail="Calls date.today()",
            remediation="Use DB clock.",
        ),
        RawCandidateFinding(
            rule_code="TRUTH-004",
            node_id="truth:cache:c1",
            source_file="backend/svc/cache.py",
            line=24,
            title="Redis SET without TTL",
            detail="No explicit TTL parsed.",
            remediation="Declare purpose or add TTL.",
        ),
        RawCandidateFinding(
            rule_code="DISP-004",
            node_id="disp:hook:h1",
            source_file="frontend/src/hooks/h1.ts",
            line=8,
            title="Unbacked endpoint",
            detail="Static probe override check.",
            remediation="Verify route exists.",
            confidence="candidate",
            evidence_strength="heuristic",
        ),
    ]
    materialized, _ = evaluate_findings_and_gate(db_session, raw, strict=True)
    by_code = {f.rule_code: f for f in materialized}
    assert by_code["MANIP-002"].confidence == "confirmed"
    assert by_code["MANIP-002"].evidence_strength == "ast_exact"
    assert by_code["TRUTH-004"].severity == "warning"
    assert by_code["TRUTH-004"].confidence == "candidate"
    assert by_code["TRUTH-004"].evidence_strength == "heuristic"
    assert by_code["DISP-004"].severity == "blocking"
    assert by_code["DISP-004"].confidence == "candidate"
    assert by_code["DISP-004"].evidence_strength == "heuristic"

    target = register_target(
        db_session,
        TargetProjectCreate(
            slug="gov-exemplar",
            name="Gov Exemplar",
            repo_path=str(repo),
            stack_profile_slug="fastapi-sqlalchemy-nextjs",
        ),
    )
    exported = build_portable_bundle(db_session, target)
    assert len(exported.reference_exemplars) == 1
    assert exported.reference_exemplars[0].title == "Canonical Scheduling Service"


def test_cli_context_full_and_ui_focus_edge_labels(
    db_session: Session,
    tmp_path: Path,
    capsys: object,
) -> None:
    repo = tmp_path / "mini-repo"
    (repo / "backend/app/models").mkdir(parents=True)
    (repo / "backend/app/services").mkdir(parents=True)
    (repo / "backend/schema.sql").write_text("CREATE TABLE items (id INT PRIMARY KEY);\n", encoding="utf-8")
    (repo / "backend/app/models/items.py").write_text(
        "class Item:\n    __tablename__ = 'items'\n",
        encoding="utf-8",
    )
    (repo / "backend/app/services/item_svc.py").write_text(
        "def list_items():\n    return 'items'\n",
        encoding="utf-8",
    )
    subprocess.run(["git", "init"], cwd=repo, check=True, capture_output=True)
    subprocess.run(["git", "add", "."], cwd=repo, check=True, capture_output=True)
    subprocess.run(
        ["git", "-c", "user.name=Wythe", "-c", "user.email=w@example.com", "commit", "-m", "init"],
        cwd=repo,
        check=True,
        capture_output=True,
    )

    rc = cli_main(["context", str(repo), "items", "--full", "--json"])
    assert rc == 0
    captured = json.loads(capsys.readouterr().out)  # type: ignore[attr-defined]
    assert captured["completeness"]["full_export"] is True
    assert captured["completeness"]["is_complete"] is True
    assert captured["worktree_dirty"] is False

    target = register_target(
        db_session,
        TargetProjectCreate(
            slug="mini-ui-focus",
            name="Mini UI Focus",
            repo_path=str(repo),
            stack_profile_slug="fastapi-sqlalchemy-nextjs",
        ),
    )
    rep = run_target_scan(db_session, target, strict_gate=True, persist_snapshot=False)
    node_id = rep.nodes[0].id
    record_ui_focus(UiFocusStatePayload(active_slug="mini-ui-focus", selected_node_id=node_id))
    explained = explain_ui_focus(db_session, target_override="mini-ui-focus")
    assert "Immediate Verified Edges" not in explained.markdown_brief

    with TestClient(create_app()) as client:
        http_resp = client.get("/api/v1/scans/mini-ui-focus/context?q=items&full=true")
        assert http_resp.status_code == 200
        http_data = http_resp.json()
        assert http_data["completeness"]["full_export"] is True
        assert http_data["completeness"]["is_complete"] is True
