"""Tests for Wythe v0.2.2 tach symbol_links, /adapters/plugins, /openlineage, and MCP tools."""

from __future__ import annotations

import importlib.metadata
from datetime import UTC, datetime
from pathlib import Path

import pytest
from fastapi.testclient import TestClient

from app import __version__
from app.adapters.base import ManipulatorExtractionResult
from app.adapters.plugin_registry import ENTRY_POINT_GROUP, WythePluginSpec
from app.adapters.tach_bridge import augment_tach_boundaries
from app.main import create_app
from app.schemas.atlas import (
    AtlasEdge,
    AtlasNode,
    AtlasSummaryStats,
    GateEvaluation,
    LegacyBridgeSummary,
    OpenLineageBundleResponse,
    PluginListResponse,
    TruthAtlasReport,
)
from app.services.llm_context_service import build_lineage_cone_slice
from app.services.mcp_service import dispatch_mcp_request


def _write_synthetic_target_repo(repo_dir: Path) -> Path:
    """Create a compact 3-tier FastAPI + SQL + Next.js repository for fast API/MCP tests."""
    (repo_dir / "backend" / "app").mkdir(parents=True)
    (repo_dir / "frontend" / "src" / "app").mkdir(parents=True)
    (repo_dir / "backend" / "schema.sql").write_text(
        "CREATE TABLE invoices (\n"
        "  id SERIAL PRIMARY KEY,\n"
        "  customer_ref TEXT NOT NULL,\n"
        "  amount_cents INTEGER NOT NULL\n"
        ");\n",
        encoding="utf-8",
    )
    (repo_dir / "backend" / "app" / "service.py").write_text(
        "def create_invoice(db):\n"
        '    db.execute("SELECT id FROM invoices")\n'
        '    db.execute("INSERT INTO invoices (customer_ref, amount_cents) VALUES (\'c1\', 500)")\n',
        encoding="utf-8",
    )
    (repo_dir / "backend" / "app" / "main.py").write_text(
        "from fastapi import FastAPI\n"
        "from app.service import create_invoice\n\n"
        "app = FastAPI()\n\n"
        '@app.post("/api/v1/invoices")\n'
        "def post_invoice():\n"
        "    return create_invoice(None)\n",
        encoding="utf-8",
    )
    (repo_dir / "frontend" / "src" / "app" / "page.tsx").write_text(
        "export default function InvoicesPage() {\n"
        "  async function submit() {\n"
        "    await fetch('/api/v1/invoices', { method: 'POST' });\n"
        "  }\n"
        "  return <button type=\"button\" onClick={submit}>Create invoice</button>;\n"
        "}\n",
        encoding="utf-8",
    )
    return repo_dir


def test_tach_bridge_populates_symbol_links_and_narrows_lineage_cone(tmp_path: Path) -> None:
    """Verify tach_bridge emits sorted `*->sym` links on symbol imports and `[]` on module imports."""
    (tmp_path / "tach.toml").write_text(
        'source_roots = ["src"]\n\n'
        '[[modules]]\npath = "api"\ndepends_on = ["orders", "audit", "billing"]\n\n'
        '[[modules]]\npath = "orders"\ndepends_on = []\n\n'
        '[[modules]]\npath = "audit"\ndepends_on = []\n\n'
        '[[modules]]\npath = "billing"\ndepends_on = []\n',
        encoding="utf-8",
    )
    src = tmp_path / "src"
    for pkg in ("api", "orders", "audit", "billing"):
        (src / pkg).mkdir(parents=True)
        (src / pkg / "__init__.py").write_text("", encoding="utf-8")

    (src / "orders" / "__init__.py").write_text(
        "from .service import validate_order, create_order\n",
        encoding="utf-8",
    )
    (src / "orders" / "service.py").write_text(
        "def create_order() -> dict:\n    return {}\n\n"
        "def validate_order() -> bool:\n    return True\n\n"
        "def archive_stale_orders() -> int:\n    return 0\n",
        encoding="utf-8",
    )
    (src / "audit" / "logger.py").write_text(
        "def emit_audit_line(msg: str) -> None:\n    pass\n",
        encoding="utf-8",
    )
    (src / "billing" / "ledger.py").write_text(
        "def post_charge() -> None:\n    pass\n\n"
        "def reverse_charge() -> None:\n    pass\n",
        encoding="utf-8",
    )
    (src / "api" / "routes.py").write_text(
        "import audit.logger\n"
        "from orders import validate_order, create_order, create_order as alias_create\n"
        "from billing.ledger import post_charge\n",
        encoding="utf-8",
    )

    api_node = AtlasNode(
        id="m:route:api_routes",
        tier="manipulate",
        subkind="route",
        label="POST /orders",
        source_file="src/api/routes.py",
        line=1,
        summary="Orders route.",
    )
    orders_node = AtlasNode(
        id="m:service:orders_service",
        tier="manipulate",
        subkind="service",
        label="orders.service",
        source_file="src/orders/service.py",
        line=1,
        summary="Orders service.",
    )
    audit_node = AtlasNode(
        id="m:service:audit_logger",
        tier="manipulate",
        subkind="service",
        label="audit.logger",
        source_file="src/audit/logger.py",
        line=1,
        summary="Audit logger.",
    )
    billing_node = AtlasNode(
        id="m:service:billing_ledger",
        tier="manipulate",
        subkind="service",
        label="billing.ledger",
        source_file="src/billing/ledger.py",
        line=1,
        summary="Billing ledger.",
    )

    res = ManipulatorExtractionResult(
        nodes=[api_node, orders_node, audit_node, billing_node],
        edges=[
            AtlasEdge(
                id="e:api->billing:calls_helper",
                source_id=api_node.id,
                target_id=billing_node.id,
                kind="calls_helper",
                verification="verified",
                evidence_path="src/api/routes.py",
                evidence_note="Pre-existing helper edge without symbol links.",
                symbol_links=[],
            ),
        ],
        routes=[],
    )
    augment_tach_boundaries(tmp_path, "src", res)

    edges_by_target = {e.target_id: e for e in res.edges if e.source_id == api_node.id}
    assert edges_by_target[orders_node.id].symbol_links == [
        "*->create_order",
        "*->validate_order",
    ]
    assert edges_by_target[audit_node.id].symbol_links == []
    assert edges_by_target[billing_node.id].symbol_links == ["*->post_charge"]

    # Verify surgical Lineage Cone pruning: archive_stale_orders -> t:order_archives is excluded
    orders_tbl = AtlasNode(
        id="t:orders",
        tier="truth",
        subkind="table",
        label="orders",
        source_file="schema.sql",
        line=1,
        summary="Orders table.",
    )
    archives_tbl = AtlasNode(
        id="t:order_archives",
        tier="truth",
        subkind="table",
        label="order_archives",
        source_file="schema.sql",
        line=10,
        summary="Order archives table.",
    )
    fixed_ts = datetime(2026, 11, 14, 12, 0, 0, tzinfo=UTC)
    report = TruthAtlasReport(
        target_slug="tach-demo",
        target_name="Tach Demo",
        repo_path=str(tmp_path),
        stack_profile="fastapi-sqlalchemy-nextjs",
        source_commit="abc123456789",
        observed_at=fixed_ts,
        valid_until=fixed_ts,
        observation_source="static_ast",
        content_digest="deadbeef1234",
        summary=AtlasSummaryStats(
            truth_tables=2,
            sql_functions=0,
            ephemeral_stores=0,
            manipulator_routes=1,
            manipulator_services=3,
            display_pages=0,
            display_hooks_and_clients=0,
            verified_edges=3,
            end_to_end_chains=0,
            clean_nodes=6,
            flagged_nodes=0,
            blocking_findings=0,
            warning_findings=0,
        ),
        nodes=[*res.nodes, orders_tbl, archives_tbl],
        edges=[
            *res.edges,
            AtlasEdge(
                id="e:orders->t_orders",
                source_id=orders_node.id,
                target_id=orders_tbl.id,
                kind="writes_truth",
                verification="verified",
                evidence_path="src/orders/service.py",
                evidence_note="create_order writes orders",
                symbol_links=["create_order->*"],
            ),
            AtlasEdge(
                id="e:orders->t_archives",
                source_id=orders_node.id,
                target_id=archives_tbl.id,
                kind="writes_truth",
                verification="verified",
                evidence_path="src/orders/service.py",
                evidence_note="archive_stale_orders writes order_archives",
                symbol_links=["archive_stale_orders->*"],
            ),
        ],
        chains=[],
        findings=[],
        gate=GateEvaluation(
            verdict="PASS",
            mode="strict",
            blocking_violations=0,
            evaluated_at=fixed_ts,
        ),
        legacy_bridge=LegacyBridgeSummary(present=False),
    )
    cone = build_lineage_cone_slice(report, api_node.id, full=True)
    cone_ids = {n.id for n in cone.downstream_truth_nodes}
    assert "t:orders" in cone_ids
    assert "t:order_archives" not in cone_ids


def test_adapters_plugins_endpoint_and_broken_entry_point_isolation(
    isolated_db_url: str,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Verify GET /api/v1/adapters/plugins enforces local_plugins_allowed=False and isolates errors."""
    assert isolated_db_url.startswith("sqlite:")
    app = create_app()
    with TestClient(app) as client:
        resp = client.get("/api/v1/adapters/plugins")
        assert resp.status_code == 200
        parsed = PluginListResponse.model_validate(resp.json())
        assert parsed.local_plugins_allowed is False
        by_name = {p.name: p for p in parsed.plugins}
        assert "tach-boundaries" in by_name
        assert "container-sources" in by_name
        assert by_name["tach-boundaries"].origin == "builtin"
        assert by_name["tach-boundaries"].version == __version__ == "0.2.7"
        assert by_name["tach-boundaries"].trusted is True
        assert by_name["tach-boundaries"].tier == "manipulate"
        assert by_name["container-sources"].version == __version__ == "0.2.7"
        assert "Kubernetes" in by_name["container-sources"].description

        class _GoodEP:
            name = "third-party-audit"
            value = "acme_wythe:plugin"
            dist = type("_Dist", (), {"version": "1.4.2"})()

            def load(self) -> WythePluginSpec:
                return WythePluginSpec(
                    name="third-party-audit",
                    kind="post_scan_check",
                    version="1.4.2",
                    description="External post-scan audit check.",
                    post_scan_hook=lambda _root, _rep: [],
                )

        class _BrokenEP:
            name = "broken-ep"
            value = "broken_pkg:boom"
            dist = None

            def load(self) -> object:
                raise RuntimeError("boom during entry point import")

        monkeypatch.setattr(
            importlib.metadata,
            "entry_points",
            lambda **kw: [_BrokenEP(), _GoodEP()] if kw.get("group") == ENTRY_POINT_GROUP else [],
        )
        resp2 = client.get("/api/v1/adapters/plugins")
        assert resp2.status_code == 200
        parsed2 = PluginListResponse.model_validate(resp2.json())
        assert parsed2.local_plugins_allowed is False
        names2 = {p.name: p for p in parsed2.plugins}
        assert "third-party-audit" in names2
        assert names2["third-party-audit"].origin == "entry_point"
        assert names2["third-party-audit"].tier == "cross_tier"
        assert any("broken-ep" in err for err in parsed2.load_errors)


def test_openlineage_http_endpoint_and_mcp_tools(
    isolated_db_url: str,
    db_session,
    tmp_path: Path,
) -> None:
    """Verify GET /scans/{slug}/openlineage and MCP wythe_plugins + wythe_openlineage."""
    assert isolated_db_url.startswith("sqlite:")
    repo_dir = _write_synthetic_target_repo(tmp_path / "mini-shop")

    app = create_app()
    with TestClient(app) as client:
        reg = client.post(
            "/api/v1/targets",
            json={
                "slug": "mini-shop",
                "name": "Mini Shop",
                "repo_path": str(repo_dir),
                "stack_profile_slug": "fastapi-sqlalchemy-nextjs",
                "backend_subdir": "backend",
                "frontend_subdir": "frontend",
            },
        )
        assert reg.status_code in (200, 201)

        missing = client.get("/api/v1/scans/does-not-exist-404/openlineage")
        assert missing.status_code == 404

        ol_resp = client.get("/api/v1/scans/mini-shop/openlineage")
        assert ol_resp.status_code == 200
        ol_bundle = OpenLineageBundleResponse.model_validate(ol_resp.json())
        assert ol_bundle.producer == "https://github.com/Euda1mon1a/wythe"
        assert ol_bundle.schemaURL == "https://openlineage.io/spec/2-0-2/OpenLineage.json"
        assert ol_bundle.target.slug == "mini-shop"
        ds_names = {d.name for d in ol_bundle.datasets}
        assert "invoices" in ds_names
        assert any("invoices" in [o.name for o in j.outputs] for j in ol_bundle.jobs)
        assert "not an automated security audit" in ol_bundle.nonCertificationNotice.lower()

        # Verify MCP HTTP manifest + JSON-RPC calls for wythe_plugins and wythe_openlineage
        mcp_manifest = client.get("/api/v1/mcp")
        assert mcp_manifest.status_code == 200
        tool_names = {t["name"] for t in mcp_manifest.json()["tools"]}
        assert "wythe_plugins" in tool_names
        assert "wythe_openlineage" in tool_names

        rpc_plugins = client.post(
            "/api/v1/mcp",
            json={
                "jsonrpc": "2.0",
                "id": 101,
                "method": "tools/call",
                "params": {"name": "wythe_plugins", "arguments": {}},
            },
        )
        assert rpc_plugins.status_code == 200
        plug_body = rpc_plugins.json()["result"]
        assert plug_body["isError"] is False
        assert "tach-boundaries" in plug_body["content"][0]["text"]
        assert "v0.2.7" in plug_body["content"][0]["text"]
        assert "Kubernetes" in plug_body["content"][0]["text"]
        assert "local_plugins_allowed=false" in plug_body["content"][0]["text"]

        rpc_ol = client.post(
            "/api/v1/mcp",
            json={
                "jsonrpc": "2.0",
                "id": 102,
                "method": "tools/call",
                "params": {"name": "wythe_openlineage", "arguments": {"target": "mini-shop"}},
            },
        )
        assert rpc_ol.status_code == 200
        ol_text = rpc_ol.json()["result"]["content"][0]["text"]
        assert "Static OpenLineage Bundle :: `mini-shop`" in ol_text
        assert "invoices" in ol_text

    # Also verify direct stdio dispatcher (`dispatch_mcp_request`) without HTTP wrapper
    direct_plug = dispatch_mcp_request(
        db_session,
        {"jsonrpc": "2.0", "id": 201, "method": "tools/call", "params": {"name": "wythe_plugins", "arguments": {}}},
    )
    assert direct_plug is not None
    assert direct_plug["result"]["isError"] is False
    assert "container-sources" in direct_plug["result"]["content"][0]["text"]

    missing_target_ol = dispatch_mcp_request(
        db_session,
        {"jsonrpc": "2.0", "id": 202, "method": "tools/call", "params": {"name": "wythe_openlineage", "arguments": {}}},
    )
    assert missing_target_ol is not None
    assert missing_target_ol["result"]["isError"] is True


def test_openlineage_api_and_mcp_symbol_scoped_readonly_workers(
    isolated_db_url: str,
    db_session,
    tmp_path: Path,
) -> None:
    """Read-only K8s CronJob & Compose worker calling mixed service omit uncalled SQL writes."""
    assert isolated_db_url.startswith("sqlite:")
    repo = tmp_path / "audit-stack"
    (repo / "backend" / "app" / "api").mkdir(parents=True)
    (repo / "backend" / "app" / "services").mkdir(parents=True)
    (repo / "backend" / "app" / "workers").mkdir(parents=True)
    (repo / "frontend" / "src" / "app").mkdir(parents=True)
    (repo / "k8s").mkdir(parents=True)

    (repo / "backend" / "schema.sql").write_text(
        "CREATE TABLE audit_logs (id SERIAL PRIMARY KEY, event_kind TEXT NOT NULL);\n",
        encoding="utf-8",
    )
    (repo / "backend" / "app" / "services" / "audit_svc.py").write_text(
        "def write_audit(db):\n"
        '    db.execute("INSERT INTO audit_logs (event_kind) VALUES (\'created\')")\n\n'
        "def read_audit_digest(db):\n"
        '    return db.execute("SELECT id, event_kind FROM audit_logs")\n',
        encoding="utf-8",
    )
    (repo / "backend" / "app" / "workers" / "k8s_cron.py").write_text(
        "from app.services.audit_svc import read_audit_digest\n\n"
        "def run_digest(db=None):\n"
        "    return read_audit_digest(db)\n",
        encoding="utf-8",
    )
    (repo / "backend" / "app" / "api" / "events.py").write_text(
        "from fastapi import APIRouter\n"
        "from app.services.audit_svc import write_audit\n\n"
        "router = APIRouter(prefix='/api/v1/events')\n\n"
        "@router.post('')\n"
        "def record_event():\n"
        "    return write_audit(None)\n",
        encoding="utf-8",
    )
    (repo / "backend" / "app" / "main.py").write_text(
        "from fastapi import FastAPI\n"
        "from app.api.events import router\n\n"
        "app = FastAPI()\n"
        "app.include_router(router)\n",
        encoding="utf-8",
    )
    (repo / "frontend" / "src" / "app" / "page.tsx").write_text(
        "export default function EventsPage() {\n"
        "  return <main>events</main>;\n"
        "}\n",
        encoding="utf-8",
    )
    (repo / "Dockerfile").write_text(
        "FROM python:3.12-slim\n"
        "WORKDIR /srv\n"
        "COPY backend/app /srv/app\n"
        'CMD ["uvicorn", "app.main:app"]\n',
        encoding="utf-8",
    )
    (repo / "compose.yaml").write_text(
        "services:\n"
        "  local-worker:\n"
        "    build: .\n"
        '    command: ["python", "-m", "app.workers.k8s_cron"]\n',
        encoding="utf-8",
    )
    (repo / "k8s" / "cron.yaml").write_text(
        "apiVersion: batch/v1\n"
        "kind: CronJob\n"
        "metadata:\n"
        "  name: audit-digest\n"
        "spec:\n"
        "  schedule: '0 * * * *'\n"
        "  jobTemplate:\n"
        "    spec:\n"
        "      template:\n"
        "        spec:\n"
        "          containers:\n"
        "            - name: digest\n"
        "              image: audit-stack:latest\n"
        '              command: ["python", "-m", "app.workers.k8s_cron"]\n',
        encoding="utf-8",
    )

    app = create_app()
    with TestClient(app) as client:
        reg = client.post(
            "/api/v1/targets",
            json={
                "slug": "audit-stack",
                "name": "Audit Stack",
                "repo_path": str(repo),
                "stack_profile_slug": "fastapi-sqlalchemy-nextjs",
                "backend_subdir": "backend",
                "frontend_subdir": "frontend",
            },
        )
        assert reg.status_code in (200, 201)

        ol_resp = client.get("/api/v1/scans/audit-stack/openlineage")
        assert ol_resp.status_code == 200
        ol_bundle = OpenLineageBundleResponse.model_validate(ol_resp.json())
        jobs_by_name = {j.name: j for j in ol_bundle.jobs}

        for readonly_id in (
            "m:service:workers.k8s_cron",
            "m:k8s:k8s/cron.yaml:cronjob:audit-digest",
            "m:compose:compose.yaml:local-worker",
        ):
            job = jobs_by_name[readonly_id]
            assert [i.name for i in job.inputs] == ["audit_logs"]
            assert job.outputs == []

        df_job = jobs_by_name["m:dockerfile:Dockerfile"]
        assert [o.name for o in df_job.outputs] == ["audit_logs"]

    mcp_res = dispatch_mcp_request(
        db_session,
        {
            "jsonrpc": "2.0",
            "id": 301,
            "method": "tools/call",
            "params": {"name": "wythe_openlineage", "arguments": {"target": "audit-stack"}},
        },
    )
    assert mcp_res is not None
    mcp_md = mcp_res["result"]["content"][0]["text"]
    for line in mcp_md.splitlines():
        if any(
            k in line
            for k in (
                "`m:service:workers.k8s_cron`",
                "`m:k8s:k8s/cron.yaml:cronjob:audit-digest`",
                "`m:compose:compose.yaml:local-worker`",
            )
        ):
            assert "inputs=[audit_logs]" in line
            assert "outputs=[none]" in line
