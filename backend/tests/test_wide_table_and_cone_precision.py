"""Regression tests for cone finding fan-in isolation and wide-table policy precision."""

from __future__ import annotations

import json
from pathlib import Path

from sqlalchemy.orm import Session

from app.adapters.postgres_sqlalchemy import PostgresSqlAlchemyAdapter
from app.adapters.python_fastapi import PythonFastApiAdapter
from app.schemas.atlas import BoundaryFinding, TargetProjectCreate
from app.services.governance_service import register_target
from app.services.llm_context_service import build_lineage_cone_slice
from app.services.scanner_service import run_target_scan


def _seed_minimal_repo(root: Path, models_py: str, services: dict[str, str], routes_py: str) -> Path:
    (root / "backend/app/models").mkdir(parents=True, exist_ok=True)
    (root / "backend/app/services").mkdir(parents=True, exist_ok=True)
    (root / "backend/app/api/routes").mkdir(parents=True, exist_ok=True)
    (root / "frontend/src/app").mkdir(parents=True, exist_ok=True)

    (root / "backend/app/__init__.py").write_text("", encoding="utf-8")
    (root / "backend/app/models/__init__.py").write_text(
        "from app.models.entities import *\n",
        encoding="utf-8",
    )
    (root / "backend/app/models/entities.py").write_text(models_py, encoding="utf-8")
    (root / "backend/app/services/__init__.py").write_text("", encoding="utf-8")
    for rel_name, body in services.items():
        (root / "backend/app/services" / rel_name).write_text(body, encoding="utf-8")

    (root / "backend/app/api/__init__.py").write_text("", encoding="utf-8")
    (root / "backend/app/api/routes/__init__.py").write_text("", encoding="utf-8")
    (root / "backend/app/api/routes/items.py").write_text(routes_py, encoding="utf-8")
    (root / "backend/app/main.py").write_text(
        "from fastapi import FastAPI\n"
        "from app.api.routes import items\n\n"
        "app = FastAPI()\n"
        "app.include_router(items.router)\n",
        encoding="utf-8",
    )
    (root / "frontend/package.json").write_text(
        json.dumps({"name": "synthetic-wide-ui", "dependencies": {"next": "15.0.0"}}),
        encoding="utf-8",
    )
    (root / "frontend/src/app/page.tsx").write_text(
        "export default async function HomePage() {\n"
        "  const res = await fetch('/api/items/a');\n"
        "  return <pre>{JSON.stringify(await res.json())}</pre>;\n"
        "}\n",
        encoding="utf-8",
    )
    return root


def test_cone_finding_isolation_blocks_out_of_cone_reader_fan_in_leak(
    tmp_path: Path, db_session: Session
) -> None:
    """Service A cone reaching `t:members` excludes out-of-cone Service B `MANIP-001`s while preserving `t:members` seed & `TRUTH-*`."""
    repo = _seed_minimal_repo(
        tmp_path / "cone_fan_in_repo",
        models_py=(
            "from sqlalchemy.orm import DeclarativeBase, Mapped, mapped_column\n\n"
            "class Base(DeclarativeBase):\n"
            "    pass\n\n"
            "class Member(Base):\n"
            "    __tablename__ = 'members'\n"
            "    id: Mapped[int] = mapped_column(primary_key=True)\n"
            "    name: Mapped[str]\n"
            "    max_hours: Mapped[int]\n"
        ),
        services={
            "service_a.py": (
                "from app.models.entities import Member\n\n"
                "def get_member_label(db, member_id: int) -> str:\n"
                "    row = db.get(Member, member_id)\n"
                "    return row.name if row is not None else 'unknown'\n"
            ),
            "service_b.py": (
                "from sqlalchemy import select\n"
                "from app.models.entities import Member\n\n"
                "def override_member_hours(db) -> list[dict[str, object]]:\n"
                "    rows = db.scalars(select(Member)).all()\n"
                "    return [{'id': r.id, 'name': r.name, 'max_hours': 60} for r in rows]\n"
            ),
        },
        routes_py=(
            "from fastapi import APIRouter\n"
            "from app.services.service_a import get_member_label\n"
            "from app.services.service_b import override_member_hours\n\n"
            "router = APIRouter(prefix='/api/items')\n\n"
            "@router.get('/a')\n"
            "def route_a(member_id: int = 1, db=None):\n"
            "    return {'label': get_member_label(db, member_id)}\n\n"
            "@router.get('/b')\n"
            "def route_b(db=None):\n"
            "    return override_member_hours(db)\n"
        ),
    )

    target = register_target(
        db_session,
        TargetProjectCreate(
            slug="cone-fan-in-test",
            name="Cone Fan-In Test",
            repo_path=str(repo),
            stack_profile_slug="fastapi-sqlalchemy-nextjs",
        ),
    )
    report = run_target_scan(db_session, target, persist_snapshot=True, strict_gate=True)

    b_manip = [
        f
        for f in report.findings
        if f.rule_code == "MANIP-001"
        and f.node_id == "m:service:services.service_b"
        and f.target_node_id == "t:members"
    ]
    assert len(b_manip) == 1

    cone_a = build_lineage_cone_slice(report, "m:service:services.service_a", full=True)
    assert any(p.id == "t:members" for p in cone_a.downstream_truth_nodes)
    assert cone_a.cone_findings == []
    assert cone_a.completeness.findings.eligible == 0

    cone_tbl = build_lineage_cone_slice(report, "t:members", full=True)
    assert any(
        f.rule_code == "MANIP-001" and f.node_id == "m:service:services.service_b"
        for f in cone_tbl.cone_findings
    )

    # External write-conflict (`TRUTH-*`) targeting a truth store in Service A's cone stays visible
    report_with_truth_conflict = report.model_copy(
        update={
            "findings": [
                *report.findings,
                BoundaryFinding(
                    id="f:truth-conflict-ext",
                    rule_code="TRUTH-004",
                    tier="truth",
                    severity="blocking",
                    blocks_gate=True,
                    node_id="m:service:services.external_writer",
                    target_node_id="t:members",
                    source_file="backend/app/services/external_writer.py",
                    line=12,
                    title="Competing writer on `members`",
                    detail="External writer mutates `members` outside primary door.",
                    remediation="Consolidate writes through single transactional service.",
                ),
            ]
        }
    )
    cone_a_with_truth = build_lineage_cone_slice(
        report_with_truth_conflict, "m:service:services.service_a", full=True
    )
    assert [f.rule_code for f in cone_a_with_truth.cone_findings] == ["TRUTH-004"]


def test_wide_entity_table_narrow_orm_read_and_untruncated_columns(tmp_path: Path) -> None:
    """Wide 45-column entity ORM narrow read (`db.get(Member, id).name`) + pagination constant stay clean."""
    extra_cols = "\n".join(f"    attr_col_{idx}: Mapped[str]" for idx in range(1, 43))
    repo = _seed_minimal_repo(
        tmp_path / "wide_entity_repo",
        models_py=(
            "from sqlalchemy.orm import DeclarativeBase, Mapped, mapped_column\n\n"
            "class Base(DeclarativeBase):\n"
            "    pass\n\n"
            "class Member(Base):\n"
            "    __tablename__ = 'members'\n"
            "    id: Mapped[int] = mapped_column(primary_key=True)\n"
            f"{extra_cols}\n"
            "    display_name: Mapped[str]\n"
            "    max_hours: Mapped[int]\n\n"
            "class TaskEntry(Base):\n"
            "    __tablename__ = 'task_entries'\n"
            "    id: Mapped[int] = mapped_column(primary_key=True)\n"
            "    member_id: Mapped[int]\n"
            "    title: Mapped[str]\n"
        ),
        services={
            "directory_service.py": (
                "from dataclasses import dataclass\n"
                "from sqlalchemy import select\n"
                "from app.models.entities import Member, TaskEntry\n\n"
                "FEED_SCAN_LIMIT = 50\n\n"
                "@dataclass(frozen=True)\n"
                "class MemberBadge:\n"
                "    member_id: int\n"
                "    label: str\n\n"
                "def read_member_name(db, member_id: int) -> MemberBadge:\n"
                "    member = db.get(Member, member_id)\n"
                "    name = member.display_name if member is not None else 'none'\n"
                "    return MemberBadge(member_id=member_id, label=name)\n\n"
                "def list_recent_tasks_with_member_join(db) -> dict[str, object]:\n"
                "    stmt = select(Member).limit(FEED_SCAN_LIMIT)\n"
                "    names = [m.display_name for m in db.scalars(stmt).all()][:FEED_SCAN_LIMIT]\n"
                "    stmt = select(TaskEntry.title).join(Member, Member.id == TaskEntry.member_id)\n"
                "    titles = list(db.scalars(stmt).all())\n"
                "    return {'names': names, 'titles': titles, 'page_limit': FEED_SCAN_LIMIT}\n"
            ),
            "bypassing_service.py": (
                "from sqlalchemy import select\n"
                "from app.models.entities import Member\n\n"
                "MAX_MEMBER_HOURS = 48\n\n"
                "def hardcode_member_hours(db) -> list[dict[str, object]]:\n"
                "    rows = db.scalars(select(Member)).all()\n"
                "    return [{'name': r.display_name, 'hours': MAX_MEMBER_HOURS} for r in rows]\n"
            ),
        },
        routes_py=(
            "from fastapi import APIRouter\n"
            "from app.services.directory_service import (\n"
            "    list_recent_tasks_with_member_join,\n"
            "    read_member_name,\n"
            ")\n"
            "from app.services.bypassing_service import hardcode_member_hours\n\n"
            "router = APIRouter(prefix='/api/items')\n\n"
            "@router.get('/a')\n"
            "def get_dir(member_id: int = 1, db=None):\n"
            "    return {'badge': read_member_name(db, member_id), 'feed': list_recent_tasks_with_member_join(db)}\n\n"
            "@router.get('/byp')\n"
            "def get_byp(db=None):\n"
            "    return hardcode_member_hours(db)\n"
        ),
    )

    truth = PostgresSqlAlchemyAdapter().extract(repo, "backend")
    manip = PythonFastApiAdapter().extract(repo, "backend", truth)

    t_members = next(n for n in truth.nodes if n.id == "t:members")
    assert len(t_members.columns) == 45
    assert "display_name" in t_members.columns
    assert "max_hours" in t_members.policy_columns

    dir_node = next(n for n in manip.nodes if n.id == "m:service:services.directory_service")
    assert dir_node.status == "clean"
    dir_edge = next(
        e
        for e in manip.edges
        if e.source_id == dir_node.id and e.target_id == "t:members" and e.kind == "reads_truth"
    )
    assert dir_edge.policy_field_consumption is None
    assert [f for f in manip.findings if f.node_id == dir_node.id and f.rule_code == "MANIP-001"] == []

    # Genuine domain-stem policy constant (`MAX_MEMBER_HOURS`) on `Member` STILL fires `bypassed`
    byp_node = next(n for n in manip.nodes if n.id == "m:service:services.bypassing_service")
    assert byp_node.status == "policy_in_code"
    byp_edge = next(
        e
        for e in manip.edges
        if e.source_id == byp_node.id and e.target_id == "t:members" and e.kind == "reads_truth"
    )
    assert byp_edge.policy_field_consumption is not None
    assert byp_edge.policy_field_consumption.state == "bypassed"
    assert "MAX_MEMBER_HOURS" in byp_edge.policy_field_consumption.substituted_constants


def test_singleton_settings_raw_sql_timezone_and_scalar_weekday_fallback_clean(
    tmp_path: Path,
) -> None:
    """Raw SQL `SELECT s.timezone_name ...`, `__table__.c.timezone_name.server_default`, and guarded `DEFAULT_START_WEEKDAY` fallback emit 0 `MANIP-001`."""
    repo = _seed_minimal_repo(
        tmp_path / "settings_clock_repo",
        models_py=(
            "from sqlalchemy.orm import DeclarativeBase, Mapped, mapped_column\n\n"
            "class Base(DeclarativeBase):\n"
            "    pass\n\n"
            "class WorkspaceSettings(Base):\n"
            "    __tablename__ = 'workspace_settings'\n"
            "    id: Mapped[int] = mapped_column(primary_key=True)\n"
            "    timezone_name: Mapped[str] = mapped_column(server_default='UTC')\n"
            "    start_weekday: Mapped[int] = mapped_column(default=0)\n"
            "    max_weekly_hours: Mapped[int] = mapped_column(default=80)\n"
            "    min_rest_hours: Mapped[int] = mapped_column(default=8)\n"
        ),
        services={
            "timezone_clock.py": (
                "from sqlalchemy import select, text\n"
                "from app.models.entities import WorkspaceSettings\n\n"
                "_CLOCK_SQL = text(\n"
                "    'SELECT s.timezone_name, clock_timestamp() FROM workspace_settings AS s LIMIT 1'\n"
                ")\n"
                "DEFAULT_START_WEEKDAY = 0\n\n"
                "def default_configured_tz() -> str:\n"
                "    sd = WorkspaceSettings.__table__.c.timezone_name.server_default\n"
                "    return str(sd.arg) if sd is not None else 'UTC'\n\n"
                "def fetch_clock_snapshot(db) -> tuple[str, object]:\n"
                "    row = db.execute(_CLOCK_SQL).fetchone()\n"
                "    if row and row[0]:\n"
                "        return str(row[0]), row[1]\n"
                "    inline = db.execute(\n"
                "        text('SELECT s.timezone_name, clock_timestamp() FROM workspace_settings AS s')\n"
                "    ).first()\n"
                "    return (str(inline[0]), inline[1]) if inline else (default_configured_tz(), None)\n\n"
                "def resolve_start_weekday(db) -> int:\n"
                "    stored = db.execute(select(WorkspaceSettings.start_weekday).limit(1)).scalar_one_or_none()\n"
                "    if isinstance(stored, int) and 0 <= stored <= 6:\n"
                "        return stored\n"
                "    return DEFAULT_START_WEEKDAY\n"
            ),
        },
        routes_py=(
            "from fastapi import APIRouter\n"
            "from app.services.timezone_clock import fetch_clock_snapshot, resolve_start_weekday\n\n"
            "router = APIRouter(prefix='/api/items')\n\n"
            "@router.get('/a')\n"
            "def get_clock(db=None):\n"
            "    tz, ts = fetch_clock_snapshot(db)\n"
            "    return {'tz': tz, 'ts': str(ts), 'weekday': resolve_start_weekday(db)}\n"
        ),
    )

    truth = PostgresSqlAlchemyAdapter().extract(repo, "backend")
    manip = PythonFastApiAdapter().extract(repo, "backend", truth)

    t_ws = next(n for n in truth.nodes if n.id == "t:workspace_settings")
    assert set(t_ws.policy_columns) == {"max_weekly_hours", "min_rest_hours"}
    assert t_ws.policy_field_consumption is None

    clk_node = next(n for n in manip.nodes if n.id == "m:service:services.timezone_clock")
    assert clk_node.status == "clean"
    clk_edge = next(
        e
        for e in manip.edges
        if e.source_id == clk_node.id
        and e.target_id == "t:workspace_settings"
        and e.kind == "reads_truth"
    )
    assert clk_edge.policy_field_consumption is None
    assert [f for f in manip.findings if f.rule_code == "MANIP-001"] == []


def test_entity_existence_and_count_queries_clean_while_policy_table_id_only_bypassed(
    tmp_path: Path,
) -> None:
    """`count(*)`/`exists()`/`select(Member.id)` on entity tables emit 0 `MANIP-001`, whereas `SELECT id FROM active_policies` stays `bypassed`."""
    repo = _seed_minimal_repo(
        tmp_path / "existence_vs_policy_repo",
        models_py=(
            "from sqlalchemy.orm import DeclarativeBase, Mapped, mapped_column\n\n"
            "class Base(DeclarativeBase):\n"
            "    pass\n\n"
            "class Member(Base):\n"
            "    __tablename__ = 'members'\n"
            "    id: Mapped[int] = mapped_column(primary_key=True)\n"
            "    name: Mapped[str]\n"
            "    max_hours: Mapped[int]\n\n"
            "class ActivePolicy(Base):\n"
            "    __tablename__ = 'active_policies'\n"
            "    id: Mapped[int] = mapped_column(primary_key=True)\n"
            "    cap: Mapped[int]\n"
        ),
        services={
            "member_probe.py": (
                "from sqlalchemy import exists, func, select\n"
                "from app.models.entities import Member\n\n"
                "def count_and_list_member_ids(db, target_id: int) -> dict[str, object]:\n"
                "    total = db.scalar(select(func.count()).select_from(Member))\n"
                "    ids = list(db.scalars(select(Member.id)).all())\n"
                "    present = bool(db.scalar(select(exists().where(Member.id == target_id))))\n"
                "    return {'total': total, 'ids': ids, 'present': present}\n"
            ),
            "policy_id_only.py": (
                "from sqlalchemy import text\n\n"
                "def list_policy_ids_ignoring_cap(db) -> list[int]:\n"
                "    rows = db.execute(text('SELECT id FROM active_policies')).all()\n"
                "    return [r[0] for r in rows]\n"
            ),
        },
        routes_py=(
            "from fastapi import APIRouter\n"
            "from app.services.member_probe import count_and_list_member_ids\n"
            "from app.services.policy_id_only import list_policy_ids_ignoring_cap\n\n"
            "router = APIRouter(prefix='/api/items')\n\n"
            "@router.get('/a')\n"
            "def probe_members(target_id: int = 1, db=None):\n"
            "    return count_and_list_member_ids(db, target_id)\n\n"
            "@router.get('/pol-ids')\n"
            "def probe_pols(db=None):\n"
            "    return list_policy_ids_ignoring_cap(db)\n"
        ),
    )

    truth = PostgresSqlAlchemyAdapter().extract(repo, "backend")
    manip = PythonFastApiAdapter().extract(repo, "backend", truth)

    probe_node = next(n for n in manip.nodes if n.id == "m:service:services.member_probe")
    assert probe_node.status == "clean"
    probe_edge = next(
        e
        for e in manip.edges
        if e.source_id == probe_node.id and e.target_id == "t:members" and e.kind == "reads_truth"
    )
    assert probe_edge.policy_field_consumption is None
    assert [
        f for f in manip.findings if f.node_id == probe_node.id and f.rule_code == "MANIP-001"
    ] == []

    pol_node = next(n for n in manip.nodes if n.id == "m:service:services.policy_id_only")
    assert pol_node.status == "policy_in_code"
    pol_edge = next(
        e
        for e in manip.edges
        if e.source_id == pol_node.id
        and e.target_id == "t:active_policies"
        and e.kind == "reads_truth"
    )
    assert pol_edge.policy_field_consumption is not None
    assert pol_edge.policy_field_consumption.state == "bypassed"
    pol_bypasses = [
        f
        for f in manip.findings
        if f.node_id == pol_node.id
        and f.target_node_id == "t:active_policies"
        and f.rule_code == "MANIP-001"
    ]
    assert len(pol_bypasses) == 1


def test_mixed_rule_table_narrow_witness_and_two_hop_callers_stay_clean(tmp_path: Path) -> None:
    """Mixed `*_rules` table narrow non-policy projection + 1-hop `preview` + 2-hop `apply` (`default_weight: 0.0`) emit 0 `MANIP-001`."""
    repo = _seed_minimal_repo(
        tmp_path / "mixed_rule_witness_repo",
        models_py=(
            "from sqlalchemy.orm import DeclarativeBase, Mapped, mapped_column\n\n"
            "class Base(DeclarativeBase):\n"
            "    pass\n\n"
            "class ScheduleRule(Base):\n"
            "    __tablename__ = 'schedule_rules'\n"
            "    id: Mapped[int] = mapped_column(primary_key=True)\n"
            "    level: Mapped[int]\n"
            "    name: Mapped[str]\n"
            "    sort_order: Mapped[int]\n"
            "    active: Mapped[bool]\n"
            "    allowed_blocks: Mapped[str]\n"
            "    blocked_blocks: Mapped[str]\n"
            "    updated_at: Mapped[str]\n\n"
            "class RunSnapshot(Base):\n"
            "    __tablename__ = 'run_snapshots'\n"
            "    id: Mapped[int] = mapped_column(primary_key=True)\n"
            "    meta_json: Mapped[str]\n"
        ),
        services={
            "solver_inputs_loader.py": (
                "from sqlalchemy import select\n"
                "from app.models.entities import RunSnapshot, ScheduleRule\n\n"
                "def _load_rule_witness(db, names: list[str], levels: list[int]):\n"
                "    stmt = select(\n"
                "        ScheduleRule.id,\n"
                "        ScheduleRule.name,\n"
                "        ScheduleRule.updated_at,\n"
                "    ).where(\n"
                "        ScheduleRule.active.is_(True),\n"
                "        ScheduleRule.name.in_(names),\n"
                "        ScheduleRule.level.in_(levels),\n"
                "    )\n"
                "    return [(r[0], r[1], r[2]) for r in db.execute(stmt).all()]\n\n"
                "def preview_inputs(db, names: list[str], levels: list[int]) -> dict[str, object]:\n"
                "    witness = _load_rule_witness(db, names, levels)\n"
                "    return {'count': len(witness), 'witness': witness}\n\n"
                "def apply_inputs(db, names: list[str], levels: list[int]) -> dict[str, object]:\n"
                "    prev = preview_inputs(db, names, levels)\n"
                "    meta = {'default_weight': 0.0, 'witness_count': prev['count']}\n"
                "    snap = RunSnapshot(meta_json=str(meta))\n"
                "    db.add(snap)\n"
                "    return {'applied': True, 'meta': meta}\n"
            ),
        },
        routes_py=(
            "from fastapi import APIRouter\n"
            "from app.services.solver_inputs_loader import apply_inputs, preview_inputs\n\n"
            "router = APIRouter(prefix='/api/items')\n\n"
            "@router.get('/a')\n"
            "def get_prev(db=None):\n"
            "    return preview_inputs(db, ['std'], [1])\n\n"
            "@router.post('/apply')\n"
            "def post_app(db=None):\n"
            "    return apply_inputs(db, ['std'], [1])\n"
        ),
    )

    truth = PostgresSqlAlchemyAdapter().extract(repo, "backend")
    manip = PythonFastApiAdapter().extract(repo, "backend", truth)

    loader_node = next(n for n in manip.nodes if n.id == "m:service:services.solver_inputs_loader")
    assert loader_node.status == "clean"
    rule_edge = next(
        e
        for e in manip.edges
        if e.source_id == loader_node.id
        and e.target_id == "t:schedule_rules"
        and e.kind == "reads_truth"
    )
    assert rule_edge.policy_field_consumption is None
    assert [f for f in manip.findings if f.rule_code == "MANIP-001"] == []


def test_wide_table_trivial_unit_zero_and_count_kwargs_never_false_positive(
    tmp_path: Path,
) -> None:
    """`affected_blocks_count=1` and `weeks_past_cutoff=0` on wide `Member` read stay clean while real `cutoff_days=14` fires."""
    repo = _seed_minimal_repo(
        tmp_path / "trivial_kwargs_repo",
        models_py=(
            "from sqlalchemy.orm import DeclarativeBase, Mapped, mapped_column\n\n"
            "class Base(DeclarativeBase):\n"
            "    pass\n\n"
            "class Member(Base):\n"
            "    __tablename__ = 'members'\n"
            "    id: Mapped[int] = mapped_column(primary_key=True)\n"
            "    name: Mapped[str]\n"
            "    target_blocks: Mapped[int]\n"
            "    cutoff_days: Mapped[int]\n"
        ),
        services={
            "notice_sender.py": (
                "from dataclasses import dataclass\n"
                "from app.models.entities import Member\n\n"
                "@dataclass(frozen=True)\n"
                "class NoticePayload:\n"
                "    recipient: str\n"
                "    weeks_past_cutoff: int\n"
                "    affected_blocks_count: int\n\n"
                "def emit_notice(db, member_id: int) -> NoticePayload:\n"
                "    member = db.get(Member, member_id)\n"
                "    past = 0\n"
                "    return NoticePayload(\n"
                "        recipient=member.name if member is not None else 'unknown',\n"
                "        weeks_past_cutoff=past,\n"
                "        affected_blocks_count=1,\n"
                "    )\n"
            ),
            "hardcoded_cutoff.py": (
                "from app.models.entities import Member\n\n"
                "def force_cutoff_days(db, member_id: int) -> dict[str, object]:\n"
                "    member = db.get(Member, member_id)\n"
                "    return {'name': member.name if member else '', 'cutoff_days': 14}\n"
            ),
        },
        routes_py=(
            "from fastapi import APIRouter\n"
            "from app.services.notice_sender import emit_notice\n"
            "from app.services.hardcoded_cutoff import force_cutoff_days\n\n"
            "router = APIRouter(prefix='/api/items')\n\n"
            "@router.get('/a')\n"
            "def get_notice(member_id: int = 1, db=None):\n"
            "    return emit_notice(db, member_id)\n\n"
            "@router.get('/force')\n"
            "def get_force(member_id: int = 1, db=None):\n"
            "    return force_cutoff_days(db, member_id)\n"
        ),
    )

    truth = PostgresSqlAlchemyAdapter().extract(repo, "backend")
    manip = PythonFastApiAdapter().extract(repo, "backend", truth)

    notice_node = next(n for n in manip.nodes if n.id == "m:service:services.notice_sender")
    assert notice_node.status == "clean"
    notice_edge = next(
        e
        for e in manip.edges
        if e.source_id == notice_node.id and e.target_id == "t:members" and e.kind == "reads_truth"
    )
    assert notice_edge.policy_field_consumption is None
    assert [
        f for f in manip.findings if f.node_id == notice_node.id and f.rule_code == "MANIP-001"
    ] == []

    force_node = next(n for n in manip.nodes if n.id == "m:service:services.hardcoded_cutoff")
    assert force_node.status == "policy_in_code"
    force_bypasses = [
        f for f in manip.findings if f.node_id == force_node.id and f.rule_code == "MANIP-001"
    ]
    assert len(force_bypasses) == 1
