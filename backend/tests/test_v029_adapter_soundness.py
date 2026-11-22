"""Adversarial soundness and fail-closed regression tests for v0.2.9 adapter fixes."""

from __future__ import annotations

from datetime import UTC, date, datetime, timedelta
from pathlib import Path

import pytest

from app.adapters.base import ManipulatorExtractionResult, RawCandidateFinding
from app.adapters.dockerfile_sources import _compile_dockerignore_glob, augment_dockerfile_sources
from app.adapters.postgres_sqlalchemy import PostgresSqlAlchemyAdapter
from app.adapters.python_ast_inspect import parse_python_module
from app.adapters.python_fastapi import PythonFastApiAdapter, _compile_route_regex
from app.adapters.python_policy_consumption import (
    _strip_sql_literals_and_comments,
    analyze_module_policy_table_read,
    is_algorithmic_or_protocol_constant,
)
from app.adapters.redis_ephemeral import augment_redis_ephemeral_lineage
from app.adapters.tach_bridge import augment_tach_boundaries
from app.adapters.typescript_nextjs import TypeScriptNextJsAdapter, _extract_ts_http_calls
from app.core.clock import utc_today
from app.core.policy_context import policy_tokens_scope
from app.schemas.atlas import (
    AtlasEdge,
    AtlasNode,
    AuditRulingRead,
    StorePurposeDeclaration,
)
from app.services.ruling_metadata import apply_rulings_and_store_purpose_checks


def _write(root: Path, rel: str, text: str) -> Path:
    fp = root / rel
    fp.parent.mkdir(parents=True, exist_ok=True)
    fp.write_text(text, encoding="utf-8")
    return fp


def test_strip_sql_literals_respects_ansi_vs_pg_escape_strings() -> None:
    standard = _strip_sql_literals_and_comments(
        "SELECT '\\', max_cap FROM policy_table WHERE prefix = '\\' AND note = 'max_cap'"
    )
    assert "max_cap" in standard.split("FROM")[0]
    assert "max_cap" not in standard.split("WHERE")[1]

    pg_escape = _strip_sql_literals_and_comments(
        "SELECT E'it\\'s ok', max_cap FROM policy_table WHERE note = e'done\\\\'"
    )
    assert "max_cap" in pg_escape
    assert "ok" not in pg_escape
    assert "done" not in pg_escape


def test_isinstance_and_issubclass_do_not_trigger_policy_query_manip001(tmp_path: Path) -> None:
    _write(
        tmp_path,
        "backend/app/models/policy.py",
        "from sqlalchemy import Column, Integer\n"
        "from sqlalchemy.orm import declarative_base\n"
        "Base = declarative_base()\n"
        "class PolicyConfig(Base):\n"
        "    __tablename__ = 'policy_configs'\n"
        "    id = Column(Integer, primary_key=True)\n"
        "    max_cap = Column(Integer, nullable=False)\n",
    )
    _write(
        tmp_path,
        "backend/app/services/type_guard.py",
        "from app.models.policy import PolicyConfig\n"
        "FALLBACK_CAP = 50\n"
        "def classify_obj(obj: object) -> int:\n"
        "    if isinstance(obj, PolicyConfig):\n"
        "        return FALLBACK_CAP\n"
        "    return 0\n"
        "def classify_cls(cls: type) -> bool:\n"
        "    return issubclass(cls, PolicyConfig)\n",
    )

    with policy_tokens_scope(("CAP", "POLICY", "FALLBACK", "DEFAULT", "HARDCODED")):
        analyses = analyze_module_policy_table_read(
            (tmp_path / "backend/app/services/type_guard.py").read_text(encoding="utf-8"),
            table_label="policy_configs",
            table_columns=("id", "max_cap"),
            policy_columns=("max_cap",),
            active_scopes=("classify_obj", "classify_cls"),
            write_scopes=set(),
            func_calls={},
            model_symbols={"PolicyConfig"},
            sql_table_names={"policy_configs"},
        )
        assert analyses == []

        truth = PostgresSqlAlchemyAdapter().extract(tmp_path, "backend")
        manip = PythonFastApiAdapter().extract(tmp_path, "backend", truth)
        bypass_findings = [
            f for f in manip.findings if f.rule_code == "MANIP-001" and f.target_node_id is not None
        ]
        assert bypass_findings == []
        for edge in manip.edges:
            if edge.kind == "reads_truth":
                assert edge.policy_field_consumption is None

    _write(
        tmp_path,
        "backend/app/services/type_guard.py",
        "from app.models.policy import PolicyConfig\n"
        "def classify_obj(obj: object) -> bool:\n"
        "    return isinstance(obj, PolicyConfig)\n"
        "def classify_cls(cls: type) -> bool:\n"
        "    return issubclass(cls, PolicyConfig)\n",
    )
    with policy_tokens_scope(("CAP", "POLICY", "FALLBACK", "DEFAULT", "HARDCODED")):
        truth_clean = PostgresSqlAlchemyAdapter().extract(tmp_path, "backend")
        manip_clean = PythonFastApiAdapter().extract(tmp_path, "backend", truth_clean)
        assert [f for f in manip_clean.findings if f.rule_code == "MANIP-001"] == []


def test_discarded_pure_casts_do_not_consume_policy_while_live_casts_do() -> None:
    src = (
        "DEFAULT_CAP = 25\n"
        "def discarded(session):\n"
        "    row = session.get(PolicyConfig, 1)\n"
        "    str(row.max_cap)\n"
        "    int(row.max_cap)\n"
        "    float(row.max_cap)\n"
        "    bool(row.max_cap)\n"
        "    len(row.label)\n"
        "    repr(row.max_cap)\n"
        "    return DEFAULT_CAP\n\n"
        "def live_return(session):\n"
        "    row = session.get(PolicyConfig, 1)\n"
        "    return int(row.max_cap)\n"
    )
    with policy_tokens_scope(("CAP", "POLICY", "DEFAULT", "HARDCODED")):
        res = analyze_module_policy_table_read(
            src,
            table_label="policy_configs",
            table_columns=("id", "label", "max_cap"),
            policy_columns=("max_cap",),
            active_scopes=("discarded", "live_return"),
            write_scopes=set(),
            func_calls={},
            model_symbols={"PolicyConfig"},
            sql_table_names={"policy_configs"},
        )
    by_scope = {r.scope_name: r for r in res}
    assert by_scope["discarded"].state == "bypassed"
    assert "max_cap" not in by_scope["discarded"].consumed_columns
    assert by_scope["live_return"].state == "consumed"
    assert "max_cap" in by_scope["live_return"].consumed_columns


def test_attribute_chain_telemetry_does_not_count_as_policy_consumption() -> None:
    src = (
        "HARDCODED_CAP = 99\n"
        "class Worker:\n"
        "    def run(self, session, app):\n"
        "        row = session.get(PolicyConfig, 1)\n"
        "        self.logger.info('max_cap=%s', row.max_cap)\n"
        "        type(self)._log.debug('cap=%s', row.max_cap)\n"
        "        app.logger.warning('policy=%s', row.max_cap)\n"
        "        return HARDCODED_CAP\n"
        "class ClsWorker:\n"
        "    @classmethod\n"
        "    def check(cls, session):\n"
        "        row = session.get(PolicyConfig, 1)\n"
        "        cls._log.debug('max_cap=%s', row.max_cap)\n"
        "        return HARDCODED_CAP\n"
    )
    with policy_tokens_scope(("CAP", "POLICY", "HARDCODED", "DEFAULT")):
        res = analyze_module_policy_table_read(
            src,
            table_label="policy_configs",
            table_columns=("id", "max_cap"),
            policy_columns=("max_cap",),
            active_scopes=("run", "check"),
            write_scopes=set(),
            func_calls={},
            model_symbols={"PolicyConfig"},
            sql_table_names={"policy_configs"},
        )
    by_scope = {r.scope_name: r for r in res}
    assert by_scope["Worker.run"].state == "bypassed"
    assert by_scope["ClsWorker.check"].state == "bypassed"


def test_cross_class_same_method_names_do_not_collide() -> None:
    src = (
        "HARDCODED_MAX_CAP = 42\n"
        "class BypassingService:\n"
        "    def _limit(self, row):\n"
        "        return HARDCODED_MAX_CAP\n"
        "    def enforce(self, session):\n"
        "        row = session.get(PolicyConfig, 1)\n"
        "        return self._limit(row)\n\n"
        "class CompliantService:\n"
        "    def _limit(self, row):\n"
        "        return row.max_cap\n"
        "    def enforce(self, session):\n"
        "        row = session.get(PolicyConfig, 1)\n"
        "        return self._limit(row)\n"
    )
    with policy_tokens_scope(("CAP", "POLICY", "HARDCODED", "DEFAULT")):
        res = analyze_module_policy_table_read(
            src,
            table_label="policy_configs",
            table_columns=("id", "max_cap"),
            policy_columns=("max_cap",),
            active_scopes=("enforce",),
            write_scopes=set(),
            func_calls={"enforce": frozenset({"_limit"})},
            model_symbols={"PolicyConfig"},
            sql_table_names={"policy_configs"},
        )
    by_scope = {r.scope_name: r for r in res}
    assert by_scope["BypassingService.enforce"].state == "bypassed"
    assert by_scope["CompliantService.enforce"].state == "consumed"


def test_multicolumn_policy_partial_consumption_reports_bypassed_column() -> None:
    src = (
        "HARDCODED_MAX_CAP = 100\n"
        "def partial_const(session):\n"
        "    row = session.get(PolicyLimits, 1)\n"
        "    return {'min': row.min_cap, 'max': HARDCODED_MAX_CAP}\n\n"
        "def partial_override(session):\n"
        "    row = session.get(PolicyLimits, 1)\n"
        "    return {'min_cap': row.min_cap, 'max_cap': 50}\n\n"
        "def partial_cmp(session, count):\n"
        "    row = session.get(PolicyLimits, 1)\n"
        "    if count < row.min_cap:\n"
        "        return False\n"
        "    if count > 80:\n"
        "        return False\n"
        "    return True\n\n"
        "def full_consume(session):\n"
        "    row = session.get(PolicyLimits, 1)\n"
        "    return (row.min_cap, row.max_cap)\n"
    )
    with policy_tokens_scope(("CAP", "POLICY", "HARDCODED", "DEFAULT")):
        res = analyze_module_policy_table_read(
            src,
            table_label="policy_limits",
            table_columns=("id", "min_cap", "max_cap"),
            policy_columns=("min_cap", "max_cap"),
            active_scopes=("partial_const", "partial_override", "partial_cmp", "full_consume"),
            write_scopes=set(),
            func_calls={},
            model_symbols={"PolicyLimits"},
            sql_table_names={"policy_limits"},
        )
    by_scope = {r.scope_name: r for r in res}
    for name in ("partial_const", "partial_override", "partial_cmp"):
        assert by_scope[name].state == "bypassed"
        assert "max_cap" in by_scope[name].unconsumed_policy_columns
        assert "min_cap" in by_scope[name].consumed_columns
    assert by_scope["full_consume"].state == "consumed"
    assert by_scope["full_consume"].unconsumed_policy_columns == ()


def test_prefix_graph_constants_are_recognized_as_algorithmic() -> None:
    assert is_algorithmic_or_protocol_constant("CONTAINER_NODE_PREFIXES") is True
    assert is_algorithmic_or_protocol_constant("CONTAINER_EDGE_PREFIXES") is True
    assert is_algorithmic_or_protocol_constant("NODE_PREFIXES") is True
    assert is_algorithmic_or_protocol_constant("EDGE_PREFIXES") is True


def test_adapters_dir_is_scanned_for_manip_and_redis(tmp_path: Path) -> None:
    _write(
        tmp_path,
        "backend/app/models/policy.py",
        "from sqlalchemy import Column, Integer\n"
        "from sqlalchemy.orm import declarative_base\n"
        "Base = declarative_base()\n"
        "class PolicyConfig(Base):\n"
        "    __tablename__ = 'policy_configs'\n"
        "    id = Column(Integer, primary_key=True)\n"
        "    max_cap = Column(Integer, nullable=False)\n",
    )
    _write(
        tmp_path,
        "backend/app/adapters/policy_bypass.py",
        "from app.models.policy import PolicyConfig\n"
        "HARDCODED_MAX_CAP = 75\n"
        "def resolve_cap(session):\n"
        "    _row = session.get(PolicyConfig, 1)\n"
        "    return HARDCODED_MAX_CAP\n",
    )
    _write(
        tmp_path,
        "backend/app/adapters/cache_writer.py",
        "import redis\n"
        "redis_client = redis.Redis()\n"
        "def write_session(user_id: str, payload: str) -> None:\n"
        "    redis_client.set(f'session:{user_id}', payload)\n",
    )

    with policy_tokens_scope(("CAP", "POLICY", "HARDCODED", "DEFAULT")):
        truth = PostgresSqlAlchemyAdapter().extract(tmp_path, "backend")
        manip = PythonFastApiAdapter().extract(tmp_path, "backend", truth)
        augment_redis_ephemeral_lineage(tmp_path, "backend", truth, manip)

    manip001_files = {f.source_file for f in manip.findings if f.rule_code == "MANIP-001"}
    assert "backend/app/adapters/policy_bypass.py" in manip001_files
    redis_paths = {e.evidence_path for e in manip.edges if e.target_id.startswith("t:redis:")}
    assert "backend/app/adapters/cache_writer.py" in redis_paths


def test_truth003_outside_routes_chained_session_and_sa_dml(tmp_path: Path) -> None:
    _write(
        tmp_path,
        "backend/app/models/order.py",
        "from sqlalchemy import Column, Integer, String\n"
        "from sqlalchemy.orm import declarative_base\n"
        "Base = declarative_base()\n"
        "class Order(Base):\n"
        "    __tablename__ = 'orders'\n"
        "    id = Column(Integer, primary_key=True)\n"
        "    code = Column(String, nullable=False)\n",
    )
    _write(
        tmp_path,
        "backend/app/endpoints/orders_ep.py",
        "import sqlalchemy as sa\n"
        "from fastapi import APIRouter\n"
        "from app.models.order import Order\n"
        "router = APIRouter()\n"
        "@router.post('/orders')\n"
        "def create_order(ctx):\n"
        "    ctx.db.execute(sa.insert(Order).values(code='A'))\n"
        "    ctx.db.commit()\n",
    )
    _write(
        tmp_path,
        "backend/app/main.py",
        "import sqlalchemy\n"
        "from sqlalchemy import sql\n"
        "from fastapi import FastAPI\n"
        "from app.models.order import Order\n"
        "app = FastAPI()\n"
        "@app.post('/direct-main')\n"
        "def update_direct(uow):\n"
        "    uow.session.execute(sqlalchemy.update(Order).values(code='B'))\n"
        "    uow.session.execute(sql.delete(Order))\n"
        "    uow.session.add(Order(code='C'))\n"
        "    uow.session.commit()\n",
    )

    pm_ep = parse_python_module(
        (tmp_path / "backend/app/endpoints/orders_ep.py").read_text(encoding="utf-8"),
        "backend/app/endpoints/orders_ep.py",
        "app.endpoints.orders_ep",
    )
    pm_main = parse_python_module(
        (tmp_path / "backend/app/main.py").read_text(encoding="utf-8"),
        "backend/app/main.py",
        "app.main",
    )
    assert pm_ep is not None and pm_ep.has_session_writes is True and "Order" in pm_ep.writes
    assert pm_main is not None and pm_main.has_session_writes is True and "Order" in pm_main.writes

    truth = PostgresSqlAlchemyAdapter().extract(tmp_path, "backend")
    manip = PythonFastApiAdapter().extract(tmp_path, "backend", truth)
    t3_files = {f.source_file for f in manip.findings if f.rule_code == "TRUTH-003"}
    assert "backend/app/endpoints/orders_ep.py" in t3_files
    assert "backend/app/main.py" in t3_files


def test_compile_route_regex_and_colliding_router_mounts(tmp_path: Path) -> None:
    import re

    broken = re.compile(_compile_route_regex("/api/(broken"))
    assert broken.match("/api/(broken") is not None

    ver_pat = re.compile(_compile_route_regex("/api/v1.0/items/{item_id}"))
    assert ver_pat.match("/api/v1.0/items/42") is not None
    assert ver_pat.match("/api/v1X0/items/42") is None

    _write(
        tmp_path,
        "backend/app/api/v1/items.py",
        "from fastapi import APIRouter\n"
        "router = APIRouter()\n"
        "@router.get('/items')\n"
        "def list_v1():\n"
        "    return []\n",
    )
    _write(
        tmp_path,
        "backend/app/api/v2/items.py",
        "from fastapi import APIRouter\n"
        "router = APIRouter()\n"
        "@router.get('/items')\n"
        "def list_v2():\n"
        "    return []\n",
    )
    _write(
        tmp_path,
        "backend/app/main.py",
        "from fastapi import FastAPI\n"
        "from app.api.v1 import items as v1_items\n"
        "from app.api.v2 import items as v2_items\n"
        "app = FastAPI()\n"
        "app.include_router(v1_items.router, prefix='/api/v1')\n"
        "app.include_router(v2_items.router, prefix='/api/v2')\n",
    )
    truth = PostgresSqlAlchemyAdapter().extract(tmp_path, "backend")
    manip = PythonFastApiAdapter().extract(tmp_path, "backend", truth)
    v1_paths = sorted(r.full_path for r in manip.routes if r.source_file.endswith("v1/items.py"))
    v2_paths = sorted(r.full_path for r in manip.routes if r.source_file.endswith("v2/items.py"))
    assert v1_paths == ["/api/v1/items"]
    assert v2_paths == ["/api/v2/items"]


def test_nextjs_scans_lib_api_layout_non_barrel_index_and_dynamic_method(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    _write(
        tmp_path,
        "frontend/src/lib/api.ts",
        "export async function loadOrders() { return fetch('/api/orders'); }\n",
    )
    _write(
        tmp_path,
        "frontend/src/app/layout.tsx",
        "import { loadOrders } from '@/lib/api';\n"
        "export default function RootLayout({ children }: { children: any }) {\n"
        "  void fetch('/api/boot');\n"
        "  void loadOrders();\n"
        "  return <html><body>{children}</body></html>;\n"
        "}\n",
    )
    _write(
        tmp_path,
        "frontend/src/features/billing/types.ts",
        "export interface Invoice { id: string; }\n",
    )
    _write(
        tmp_path,
        "frontend/src/features/billing/index.ts",
        "export type { Invoice } from './types';\n"
        "export async function fetchBilling() { return fetch('/api/billing'); }\n",
    )
    _write(
        tmp_path,
        "frontend/src/features/pure/helper.ts",
        "export const helperVal = 1;\n",
    )
    _write(
        tmp_path,
        "frontend/src/features/pure/index.ts",
        "export * from './helper';\n",
    )
    _write(
        tmp_path,
        "frontend/src/app/dyn/page.tsx",
        "export default function DynPage({ dynMethod }: { dynMethod: string }) {\n"
        "  void fetch('/api/dyn-items', { method: dynMethod });\n"
        "  void fetch({ url: '/api/dyn-obj', method: `${dynMethod}` });\n"
        "  return <main>Dyn</main>;\n"
        "}\n",
    )

    disp = TypeScriptNextJsAdapter().extract(tmp_path, "frontend")
    src_files = {n.source_file for n in disp.nodes}
    assert "frontend/src/lib/api.ts" in src_files
    assert "frontend/src/app/layout.tsx" in src_files
    assert "frontend/src/features/billing/index.ts" in src_files
    assert "frontend/src/features/pure/index.ts" not in src_files

    calls_by_path = {c.normalized_path: c.http_method for c in disp.http_calls}
    assert calls_by_path["/api/orders"] == "GET"
    assert calls_by_path["/api/boot"] == "GET"
    assert calls_by_path["/api/billing"] == "GET"
    assert calls_by_path["/api/dyn-items"] == "DYNAMIC"
    assert calls_by_path["/api/dyn-obj"] == "DYNAMIC"

    import app.adapters.treesitter_engine as ts_eng

    monkeypatch.setattr(ts_eng, "has_treesitter", lambda: False)
    fb_src = (
        "const m = 'POST';\n"
        "fetch('/api/fb-items', { method: m });\n"
        "fetch('/api/fb-tpl', { method: `${m}` });\n"
        "fetch({ url: '/api/fb-obj', method: m });\n"
    )
    fb_calls = {url: verb for verb, url, _ln in _extract_ts_http_calls(fb_src)}
    assert fb_calls["/api/fb-items"] == "DYNAMIC"
    assert fb_calls["/api/fb-tpl"] == "DYNAMIC"
    assert fb_calls["/api/fb-obj"] == "DYNAMIC"


def _make_ruling(
    rid: int,
    *,
    node_id: str,
    disposition: str,
    effective_from: date,
    effective_until: date | None = None,
    created_at: datetime,
    store_purpose: StorePurposeDeclaration | None = None,
) -> AuditRulingRead:
    return AuditRulingRead(
        id=rid,
        target_id=1,
        node_id=node_id,
        disposition=disposition,
        summary=f"Ruling {rid}: {disposition}",
        store_purpose=store_purpose,
        audited_commit="deadbeef",
        audited_at=created_at.date(),
        effective_from=effective_from,
        effective_until=effective_until,
        recorded_by="reviewer",
        created_at=created_at,
    )


def test_ruling_metadata_date_windows_and_newest_revokes_older_clean() -> None:
    today = utc_today()
    now_dt = datetime(today.year, today.month, today.day, 12, 0, tzinfo=UTC)
    cache_node = AtlasNode(
        id="t:redis:session",
        tier="truth",
        subkind="cache_store",
        label="session",
        source_file="backend/app/services/session.py",
        summary="Redis store",
    )
    sql_node = AtlasNode(
        id="t:sessions",
        tier="truth",
        subkind="table",
        label="sessions",
        source_file="backend/app/models/session.py",
        summary="SQL table",
    )
    second_auth_finding = RawCandidateFinding(
        rule_code="TRUTH-004",
        node_id="m:service:session",
        target_node_id="t:redis:session",
        source_file="backend/app/services/session.py",
        line=12,
        title="Redis acts as second authority",
        detail="backend/app/services/session.py:12 writes cache `session` acting as second authority.",
        remediation="Declare store purpose.",
    )
    manip_finding = RawCandidateFinding(
        rule_code="MANIP-001",
        node_id="t:redis:session",
        source_file="backend/app/services/session.py",
        line=18,
        title="Constant bypass",
        detail="bypasses policy",
        remediation="Consume column.",
    )

    # Older accepted_clean must be revoked by newer needs_fix (both finding waiver and store_purpose).
    older_clean = _make_ruling(
        1,
        node_id="t:redis:session",
        disposition="accepted_clean",
        effective_from=today - timedelta(days=5),
        created_at=now_dt - timedelta(days=2),
        store_purpose=StorePurposeDeclaration(
            intended_use="derived_cache",
            authoritative_source="t:sessions",
        ),
    )
    newer_fix = _make_ruling(
        2,
        node_id="t:redis:session",
        disposition="needs_fix",
        effective_from=today - timedelta(days=1),
        created_at=now_dt - timedelta(hours=1),
    )
    res_revoked = apply_rulings_and_store_purpose_checks(
        [cache_node.model_copy(deep=True), sql_node],
        [
            AtlasEdge(
                id="e:w",
                source_id="m:service:session",
                target_id="t:sessions",
                kind="writes_truth",
                verification="verified",
                evidence_path="backend/app/services/session.py",
                evidence_note="writes",
            )
        ],
        [second_auth_finding, manip_finding],
        [older_clean, newer_fix],
    )
    assert {f.rule_code for f in res_revoked} == {"TRUTH-004", "MANIP-001"}

    # Future or expired accepted_clean waivers must NOT apply.
    future_clean = _make_ruling(
        3,
        node_id="t:redis:session",
        disposition="accepted_clean",
        effective_from=today + timedelta(days=1),
        created_at=now_dt,
    )
    expired_clean = _make_ruling(
        4,
        node_id="t:redis:session",
        disposition="accepted_clean",
        effective_from=today - timedelta(days=10),
        effective_until=today - timedelta(days=1),
        created_at=now_dt,
    )
    res_inactive = apply_rulings_and_store_purpose_checks(
        [cache_node.model_copy(deep=True)],
        [],
        [manip_finding],
        [future_clean, expired_clean],
    )
    assert len(res_inactive) == 1 and res_inactive[0].rule_code == "MANIP-001"


def test_fail_closed_dockerignore_tach_and_adapter_parse_coverage(tmp_path: Path) -> None:
    assert _compile_dockerignore_glob("[!]") is None
    assert _compile_dockerignore_glob("[z-a]") is None

    _write(tmp_path, ".dockerignore", "[!]\n[z-a]\n*.pyc\n")
    _write(
        tmp_path,
        "Dockerfile",
        "FROM python:3.12-slim\nCOPY . /app\nCMD [\"python\", \"-m\", \"app.main\"]\n",
    )
    docker_res = ManipulatorExtractionResult(nodes=[], edges=[], routes=[], findings=[])
    augment_dockerfile_sources(tmp_path, "backend", docker_res)
    assert any(n.id.startswith("m:dockerfile:") for n in docker_res.nodes)

    # TYPE_CHECKING imports in tach must not emit MANIP-006; malformed tach.toml or SyntaxError -> coverage_complete=False.
    tach_repo = tmp_path / "tach_ok"
    _write(
        tach_repo,
        "tach.toml",
        'source_roots = ["backend"]\n'
        '[[modules]]\npath = "app.a"\ndepends_on = []\n'
        '[[modules]]\npath = "app.b"\ndepends_on = []\n',
    )
    _write(
        tach_repo,
        "backend/app/a.py",
        "from typing import TYPE_CHECKING\n"
        "import typing\n"
        "if TYPE_CHECKING:\n"
        "    from app import b\n"
        "if typing.TYPE_CHECKING:\n"
        "    import app.b\n",
    )
    _write(tach_repo, "backend/app/b.py", "X = 1\n")
    tach_res = ManipulatorExtractionResult(nodes=[], edges=[], routes=[], findings=[])
    augment_tach_boundaries(tach_repo, "backend", tach_res)
    assert [f for f in tach_res.findings if f.rule_code == "MANIP-006"] == []
    assert tach_res.coverage_complete is True

    bad_toml = tmp_path / "tach_bad_toml"
    _write(bad_toml, "tach.toml", "modules = 123\n")
    bad_toml_res = ManipulatorExtractionResult(nodes=[], edges=[], routes=[], findings=[])
    augment_tach_boundaries(bad_toml, "backend", bad_toml_res)
    assert bad_toml_res.coverage_complete is False

    bad_py = tmp_path / "tach_bad_py"
    _write(bad_py, "tach.toml", 'source_roots = ["backend"]\n')
    _write(bad_py, "backend/app/broken.py", "def oops(:\n")
    bad_py_res = ManipulatorExtractionResult(nodes=[], edges=[], routes=[], findings=[])
    augment_tach_boundaries(bad_py, "backend", bad_py_res)
    assert bad_py_res.coverage_complete is False

    truth = PostgresSqlAlchemyAdapter().extract(bad_py, "backend")
    fa_res = PythonFastApiAdapter().extract(bad_py, "backend", truth)
    assert fa_res.coverage_complete is False

    missing_fe = TypeScriptNextJsAdapter().extract(tmp_path, "missing_frontend")
    assert missing_fe.coverage_complete is False

    bad_ts_repo = tmp_path / "bad_ts"
    _write(bad_ts_repo, "frontend/src/app/page.tsx", "export default function P( { return <div\n")
    bad_ts_res = TypeScriptNextJsAdapter().extract(bad_ts_repo, "frontend")
    assert bad_ts_res.coverage_complete is False

    import app.adapters.typescript_nextjs as ts_mod

    orig_get_parser = ts_mod._get_parser
    try:
        ts_mod._get_parser = lambda _lang: None  # type: ignore[assignment]
        assert (
            ts_mod._check_ts_syntax_complete(
                "export function View() {\n"
                "  const rx = /[({]/g;\n"
                "  const msg = `item ${1 + 2} (ok)`;\n"
                "  return <div title={msg}>What's This?</div>;\n"
                "}\n",
                ".tsx",
            )
            is True
        )
        assert (
            ts_mod._check_ts_syntax_complete(
                "export default function P( { return <div\n",
                ".tsx",
            )
            is False
        )
    finally:
        ts_mod._get_parser = orig_get_parser  # type: ignore[assignment]
