"""3-tier syntax-tree scanner, boundary detector, and self-dogfooding verification tests."""

from __future__ import annotations

from pathlib import Path

from sqlalchemy.orm import Session

from app.adapters.base import (
    AdapterRegistry,
    DisplayExtractionResult,
    FrontendHttpCall,
    ManipulatorExtractionResult,
    RouteDescriptor,
    TruthExtractionResult,
)
from app.adapters.legacy_snapshot_bridge import apply_legacy_snapshot_bridge
from app.schemas.atlas import AtlasEdge, AtlasNode, TargetProjectCreate
from app.services.governance_service import get_target_by_slug, register_target
from app.services.scanner_service import _solve_cross_tier_lineage, run_target_scan


def _build_synthetic_three_tier_repo(root: Path) -> Path:
    """Create a synthetic repo exercising every 3-tier boundary violation + comment immunity."""
    repo = root / "synthetic_triad"
    (repo / "backend" / "app" / "models").mkdir(parents=True)
    (repo / "backend" / "app" / "services").mkdir(parents=True)
    (repo / "backend" / "app" / "api").mkdir(parents=True)
    (repo / "frontend" / "src" / "api").mkdir(parents=True)
    (repo / "frontend" / "src" / "app").mkdir(parents=True)

    # schema.sql omits `drift_only_in_orm` to trigger TRUTH-002.
    (repo / "backend" / "schema.sql").write_text(
        "CREATE TABLE active_policies (id INTEGER PRIMARY KEY, cap INTEGER NOT NULL);\n"
        "CREATE TABLE orphan_rules (id INTEGER PRIMARY KEY, name TEXT NOT NULL);\n",
        encoding="utf-8",
    )

    (repo / "backend" / "app" / "models" / "domain.py").write_text(
        "from sqlalchemy.orm import DeclarativeBase, Mapped, mapped_column\n"
        "class Base(DeclarativeBase): pass\n"
        "class ActivePolicy(Base):\n"
        "    __tablename__ = 'active_policies'\n"
        "    id: Mapped[int] = mapped_column(primary_key=True)\n"
        "    cap: Mapped[int]\n"
        "class OrphanRule(Base):\n"
        "    __tablename__ = 'orphan_rules'\n"
        "    id: Mapped[int] = mapped_column(primary_key=True)\n"
        "    name: Mapped[str]\n"
        "class DriftOnlyInOrm(Base):\n"
        "    __tablename__ = 'drift_only_in_orm'\n"
        "    id: Mapped[int] = mapped_column(primary_key=True)\n",
        encoding="utf-8",
    )

    # Service mentioning OrphanRule ONLY in a docstring & TYPE_CHECKING must NOT count as reading it!
    # Also triggers MANIP-001 (MAX_SHIFT_CAP) and MANIP-002 (date.today()).
    (repo / "backend" / "app" / "services" / "policy_service.py").write_text(
        '"""Service layer; note OrphanRule and orphan_rules are mentioned only in prose."""\n'
        "from datetime import date\n"
        "from typing import TYPE_CHECKING\n"
        "from sqlalchemy import select\n"
        "from app.models.domain import ActivePolicy\n"
        "if TYPE_CHECKING:\n"
        "    from app.models.domain import OrphanRule\n"
        "MAX_SHIFT_CAP = 12\n"
        "def fetch_policies(db):\n"
        "    _today = date.today()\n"
        "    return db.scalars(select(ActivePolicy)).all()\n",
        encoding="utf-8",
    )

    # Route mutates ActivePolicy directly via db.add(...) -> triggers TRUTH-003.
    (repo / "backend" / "app" / "api" / "routes.py").write_text(
        "from fastapi import APIRouter\n"
        "from app.models.domain import ActivePolicy\n"
        "from app.services.policy_service import fetch_policies\n"
        "router = APIRouter()\n"
        "@router.get('/policies')\n"
        "def list_policies(db=None):\n"
        "    return fetch_policies(db)\n"
        "@router.post('/policies')\n"
        "def create_policy_directly(db=None):\n"
        "    row = ActivePolicy(cap=5)\n"
        "    db.add(row)\n"
        "    db.commit()\n"
        "    return row\n",
        encoding="utf-8",
    )
    (repo / "backend" / "app" / "main.py").write_text(
        "from fastapi import FastAPI\n"
        "from app.api.routes import router\n"
        "app = FastAPI()\n"
        "app.include_router(router, prefix='/api/v1')\n",
        encoding="utf-8",
    )

    # API client omits `api-generated` (DISP-003) and calls `/missing-endpoint` (DISP-004).
    (repo / "frontend" / "src" / "api" / "client.ts").write_text(
        "export async function loadPolicies() {\n"
        "  return fetch('/api/v1/policies');\n"
        "}\n"
        "export async function loadGhost() {\n"
        "  return fetch('/api/v1/missing-endpoint');\n"
        "}\n",
        encoding="utf-8",
    )

    # Page defines MAX_HOURS_LIMIT (DISP-001) and slices UTC ISO date (DISP-002).
    (repo / "frontend" / "src" / "app" / "page.tsx").write_text(
        "import { loadPolicies, loadGhost } from '../api/client';\n"
        "const MAX_HOURS_LIMIT = 80;\n"
        "export default function Page() {\n"
        "  const badDay = new Date().toISOString().slice(0, 10);\n"
        "  void loadPolicies();\n"
        "  void loadGhost();\n"
        "  return <div>{MAX_HOURS_LIMIT} {badDay}</div>;\n"
        "}\n",
        encoding="utf-8",
    )
    return repo


def test_detects_all_three_tier_boundary_violations_and_ignores_prose(
    db_session: Session, tmp_path: Path
) -> None:
    """Verify TRUTH-001..003, MANIP-001..002, DISP-001..004, and comment/TYPE_CHECKING immunity."""
    repo = _build_synthetic_three_tier_repo(tmp_path)
    register_target(
        db_session,
        TargetProjectCreate(slug="synthetic-triad", name="Synthetic Triad", repo_path=str(repo)),
    )
    target = get_target_by_slug(db_session, "synthetic-triad")
    assert target is not None

    report = run_target_scan(db_session, target, strict_gate=True)
    rule_codes = {f.rule_code for f in report.findings}

    assert "TRUTH-001" in rule_codes, "orphan_rules should be flagged as unread despite prose/TYPE_CHECKING"
    assert "TRUTH-002" in rule_codes, "drift_only_in_orm missing from schema.sql should trigger TRUTH-002"
    assert "TRUTH-003" in rule_codes, "direct db.add(ActivePolicy) in route should trigger TRUTH-003"
    assert "MANIP-001" in rule_codes, "MAX_SHIFT_CAP in Python service should trigger MANIP-001"
    assert "MANIP-002" in rule_codes, "date.today() in Python service should trigger MANIP-002"
    assert "DISP-001" in rule_codes, "MAX_HOURS_LIMIT in TSX page should trigger DISP-001"
    assert "DISP-002" in rule_codes, "toISOString().slice(0, 10) in TSX should trigger DISP-002"
    assert "DISP-003" in rule_codes, "API client without api-generated import should trigger DISP-003"
    assert "DISP-004" in rule_codes, "/missing-endpoint call should trigger DISP-004"

    # Also verify valid chain `/ -> GET /policies -> active_policies` IS traced!
    assert len(report.chains) >= 1
    valid_chain = next(c for c in report.chains if c.http_path.endswith("/policies") and c.http_method == "GET")
    assert "active_policies" in valid_chain.truth_table_labels
    assert valid_chain.verified is True

    # Confirm orphan_rules read_by_count stayed 0 (docstring + TYPE_CHECKING did not create false read edge).
    orphan_node = next(n for n in report.nodes if n.label == "orphan_rules")
    assert orphan_node.read_by_count == 0


def test_wythe_self_dogfood_passes_strict_gate_with_deterministic_digest(
    db_session: Session,
) -> None:
    """Wythe itself obeys all 3-tier contracts with 0 blocking and 0 warning findings."""
    target = get_target_by_slug(db_session, "wythe")
    assert target is not None

    first = run_target_scan(db_session, target, strict_gate=True)
    second = run_target_scan(db_session, target, strict_gate=True)

    assert first.gate.verdict == "PASS"
    assert first.summary.blocking_findings == 0
    assert first.summary.warning_findings == 0
    assert first.summary.truth_tables == 7
    assert first.summary.sql_functions == 1
    assert len(first.chains) >= 20
    assert all(c.verified for c in first.chains)
    assert first.content_digest == second.content_digest


def test_pluggable_adapter_protocol_synthesizes_non_python_lineage() -> None:
    """Prove language generalizability: a stub Go/sqlc manipulator links cleanly into 3-tier chains."""

    class GoChiStubAdapter:
        name = "go-chi"

        def extract(
            self, repo_root: Path, backend_subdir: str, truth: TruthExtractionResult
        ) -> ManipulatorExtractionResult:
            _ = (repo_root, backend_subdir, truth)
            return ManipulatorExtractionResult(
                nodes=[
                    AtlasNode(
                        id="m:route:handlers.ledger",
                        tier="manipulate",
                        subkind="route",
                        label="handlers.ledger",
                        source_file="backend/internal/handlers/ledger.go",
                        summary="Go chi HTTP handler.",
                    )
                ],
                edges=[
                    AtlasEdge(
                        id="e:m:route:handlers.ledger->t:table:ledger_entries:reads_truth",
                        source_id="m:route:handlers.ledger",
                        target_id="t:table:ledger_entries",
                        kind="reads_truth",
                        verification="verified",
                        evidence_note="sqlc query ListLedgerEntries",
                    )
                ],
                routes=[
                    RouteDescriptor(
                        node_id="m:route:handlers.ledger",
                        http_method="GET",
                        full_path="/api/v1/ledger",
                        path_regex="^/api/v1/ledger$",
                        source_file="backend/internal/handlers/ledger.go",
                        line=12,
                        called_symbols=frozenset(),
                        imported_modules=frozenset(),
                    )
                ],
            )

    registry = AdapterRegistry()
    registry.register_manipulator(GoChiStubAdapter())
    go_adapter = registry.get_manipulator("go-chi")

    truth_res = TruthExtractionResult(
        nodes=[
            AtlasNode(
                id="t:table:ledger_entries",
                tier="truth",
                subkind="table",
                label="ledger_entries",
                source_file="backend/schema.sql",
                summary="Postgres ledger table.",
            )
        ],
        table_symbol_map={"ledger_entries": "t:table:ledger_entries"},
        function_symbol_map={},
    )
    manip_res = go_adapter.extract(Path("."), "backend", truth_res)
    disp_res = DisplayExtractionResult(
        nodes=[
            AtlasNode(
                id="d:page:ledger",
                tier="display",
                subkind="page",
                label="/ledger",
                source_file="frontend/src/app/ledger/page.tsx",
                summary="Ledger view.",
            )
        ],
        edges=[],
        http_calls=[
            FrontendHttpCall(
                caller_node_id="d:page:ledger",
                http_method="GET",
                raw_path="/api/v1/ledger",
                normalized_path="/api/v1/ledger",
                source_file="frontend/src/app/ledger/page.tsx",
                line=8,
            )
        ],
    )
    cross_edges, chains, extra_findings = _solve_cross_tier_lineage(truth_res, manip_res, disp_res)
    assert len(extra_findings) == 0
    assert len(cross_edges) == 1
    assert len(chains) == 1
    assert chains[0].truth_table_labels == ["ledger_entries"]
    assert chains[0].verified is True


def test_legacy_snapshot_bridge_normalizes_completed_cutover_to_clean(tmp_path: Path) -> None:
    """Verify completed legacy 'cutover' status normalizes to 'clean' with cutover_history preserved."""
    target_file = tmp_path / "backend" / "app" / "services" / "gate.py"
    target_file.parent.mkdir(parents=True)
    target_file.write_text("def check_write_perimeter():\n    return True\n", encoding="utf-8")

    snap_file = tmp_path / "backend" / "app" / "data" / "truth_atlas_snapshot.json"
    snap_file.parent.mkdir(parents=True)
    snap_file.write_text(
        '{"meta": {"title": "Test Atlas", "audited_at": "2026-11-10", "snapshot_commit": "deadbeef"}, '
        '"evidence": [{"node_id": "c_write_perimeter", "mode": "absent_is_cutover", '
        '"path": "backend/app/services/gate.py", "pattern": "def check_write_perimeter"}], '
        '"components": [{"id": "c_write_perimeter", "status": "cutover", '
        '"file": "app/services/gate.py", "layman": "Guard service.", '
        '"cutover_note": "Completed migration to Postgres trigger."}]}',
        encoding="utf-8",
    )
    node = AtlasNode(
        id="m:service:services.gate",
        tier="manipulate",
        subkind="service",
        label="services.gate",
        source_file="backend/app/services/gate.py",
        status="clean",
        summary="Gate service.",
    )
    summary = apply_legacy_snapshot_bridge(
        tmp_path, "backend/app/data/truth_atlas_snapshot.json", [node]
    )
    assert summary.present is True
    assert summary.receipts_verified == 1
    assert summary.cutover_reclassified_count == 1
    assert node.status == "clean"
    assert node.cutover_history == "Completed migration to Postgres trigger."
