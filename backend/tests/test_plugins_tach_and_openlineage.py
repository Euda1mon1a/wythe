"""Tests for Wythe plugin registry, tach.toml bridge, OpenLineage & security correlator."""

from __future__ import annotations

import json
import sys
from datetime import UTC, datetime
from pathlib import Path
from types import ModuleType

import pytest

from app.adapters.base import ManipulatorExtractionResult
from app.adapters.plugin_registry import (
    ENTRY_POINT_GROUP,
    WythePluginSpec,
    discover_plugins,
    list_registered_plugins,
    run_manipulator_plugins,
    run_post_scan_plugins,
)
from app.adapters.python_ast_inspect import parse_python_module
from app.adapters.tach_bridge import augment_tach_boundaries
from app.schemas.atlas import (
    AtlasEdge,
    AtlasNode,
    AtlasSummaryStats,
    BoundaryFinding,
    EndToEndChain,
    GateEvaluation,
    LegacyBridgeSummary,
    TruthAtlasReport,
)
from app.services.companion_export_service import (
    build_openlineage_static_bundle,
    summarize_companion_security_artifacts,
)


def _sample_report() -> TruthAtlasReport:
    fixed_ts = datetime(2026, 11, 14, 12, 0, 0, tzinfo=UTC)
    nodes = [
        AtlasNode(
            id="t:customers",
            tier="truth",
            subkind="table",
            label="customers",
            source_file="backend/schema.sql",
            line=10,
            summary="Authoritative customer records.",
            columns=["id: uuid", "email: text", "tier VARCHAR(32)"],
            read_by_count=2,
            written_by_count=0,
        ),
        AtlasNode(
            id="t:orders",
            tier="truth",
            subkind="table",
            label="orders",
            source_file="backend/schema.sql",
            line=28,
            summary="Customer purchase orders.",
            columns=["id: uuid", "customer_id: uuid", "total_cents: integer"],
            read_by_count=1,
            written_by_count=1,
        ),
        AtlasNode(
            id="t:redis:rate_window",
            tier="truth",
            subkind="cache_store",
            label="redis:rate_window",
            source_file="backend/app/services/order_service.py",
            line=14,
            summary="Ephemeral Redis rate counter with TTL.",
            columns=["key: str", "ttl_seconds: int"],
            read_by_count=1,
            written_by_count=1,
        ),
        AtlasNode(
            id="m:service:order_service",
            tier="manipulate",
            subkind="service",
            label="order_service",
            source_file="backend/app/services/order_service.py",
            line=1,
            summary="Transactional order service.",
        ),
        AtlasNode(
            id="m:route:GET:/api/v1/orders",
            tier="manipulate",
            subkind="route",
            label="GET /api/v1/orders",
            source_file="backend/app/api/orders.py",
            line=12,
            summary="List orders endpoint.",
            http_methods=["GET"],
            http_paths=["/api/v1/orders"],
        ),
        AtlasNode(
            id="m:route:POST:/api/v1/orders",
            tier="manipulate",
            subkind="route",
            label="POST /api/v1/orders",
            source_file="backend/app/api/orders.py",
            line=25,
            summary="Create order endpoint.",
            http_methods=["POST"],
            http_paths=["/api/v1/orders"],
        ),
        AtlasNode(
            id="d:page:orders",
            tier="display",
            subkind="page",
            label="/orders",
            source_file="frontend/app/orders/page.tsx",
            line=1,
            summary="Orders dashboard page.",
        ),
    ]
    edges = [
        AtlasEdge(
            id="e:route_get->svc",
            source_id="m:route:GET:/api/v1/orders",
            target_id="m:service:order_service",
            kind="calls_helper",
            verification="verified",
            evidence_path="backend/app/api/orders.py",
            evidence_note="GET route calls order_service.list_orders",
        ),
        AtlasEdge(
            id="e:route_post->svc",
            source_id="m:route:POST:/api/v1/orders",
            target_id="m:service:order_service",
            kind="calls_helper",
            verification="verified",
            evidence_path="backend/app/api/orders.py",
            evidence_note="POST route calls order_service.create_order",
        ),
        AtlasEdge(
            id="e:svc->customers:read",
            source_id="m:service:order_service",
            target_id="t:customers",
            kind="reads_truth",
            verification="verified",
            evidence_path="backend/app/services/order_service.py",
            evidence_note="SELECT customer before creating order",
        ),
        AtlasEdge(
            id="e:svc->orders:read",
            source_id="m:service:order_service",
            target_id="t:orders",
            kind="reads_truth",
            verification="verified",
            evidence_path="backend/app/services/order_service.py",
            evidence_note="SELECT orders list",
        ),
        AtlasEdge(
            id="e:svc->orders:write",
            source_id="m:service:order_service",
            target_id="t:orders",
            kind="writes_truth",
            verification="verified",
            evidence_path="backend/app/services/order_service.py",
            evidence_note="INSERT into orders",
        ),
        AtlasEdge(
            id="e:svc->redis:write",
            source_id="m:service:order_service",
            target_id="t:redis:rate_window",
            kind="writes_truth",
            verification="verified",
            evidence_path="backend/app/services/order_service.py",
            evidence_note="SETEX rate_window",
        ),
    ]
    chains = [
        EndToEndChain(
            id="chain:1",
            display_node_id="d:page:orders",
            display_label="/orders",
            http_method="POST",
            http_path="/api/v1/orders",
            route_node_id="m:route:POST:/api/v1/orders",
            route_label="POST /api/v1/orders",
            manipulator_node_ids=["m:service:order_service"],
            truth_table_ids=["t:customers", "t:orders"],
            truth_table_labels=["customers", "orders"],
            operation="write",
            verified=True,
        ),
        EndToEndChain(
            id="chain:2",
            display_node_id="d:page:orders",
            display_label="/orders",
            http_method="GET",
            http_path="/api/v1/orders",
            route_node_id="m:route:GET:/api/v1/orders",
            route_label="GET /api/v1/orders",
            manipulator_node_ids=["m:service:order_service"],
            truth_table_ids=["t:orders"],
            truth_table_labels=["orders"],
            operation="read",
            verified=True,
        ),
    ]
    findings = [
        BoundaryFinding(
            id="f:1",
            rule_code="TRUTH-003",
            tier="truth",
            severity="blocking",
            blocks_gate=True,
            node_id="m:route:POST:/api/v1/orders",
            target_node_id="t:orders",
            source_file="backend/app/api/orders.py",
            line=30,
            title="Direct route write",
            detail="Route writes directly.",
            remediation="Use service door.",
        ),
        BoundaryFinding(
            id="f:2",
            rule_code="DISP-001",
            tier="display",
            severity="blocking",
            blocks_gate=True,
            node_id="d:page:orders",
            source_file="frontend/app/orders/page.tsx",
            line=9,
            title="Client policy shadow",
            detail="Client defines threshold.",
            remediation="Fetch from server.",
        ),
        BoundaryFinding(
            id="f:3",
            rule_code="TRUTH-001",
            tier="truth",
            severity="warning",
            blocks_gate=False,
            node_id="t:unused_rules",
            source_file="backend/schema.sql",
            line=50,
            title="Unplugged policy table",
            detail="Zero readers.",
            remediation="Wire or retire.",
        ),
        BoundaryFinding(
            id="f:4",
            rule_code="MANIP-005",
            tier="manipulate",
            severity="warning",
            blocks_gate=False,
            node_id="m:dockerfile:Dockerfile",
            source_file="Dockerfile",
            line=12,
            title="Omitted runtime helper in COPY",
            detail="Helper not copied.",
            remediation="Update COPY.",
        ),
    ]
    return TruthAtlasReport(
        target_slug="demo-shop",
        target_name="Demo Shop",
        repo_path="/workspace/demo-shop",
        stack_profile="fastapi-sqlalchemy-nextjs",
        source_commit="abc1234def5678",
        observed_at=fixed_ts,
        valid_until=fixed_ts,
        observation_source="static_ast",
        content_digest="deadbeef",
        summary=AtlasSummaryStats(
            truth_tables=2,
            sql_functions=0,
            ephemeral_stores=1,
            manipulator_routes=2,
            manipulator_services=1,
            display_pages=1,
            display_hooks_and_clients=0,
            verified_edges=6,
            end_to_end_chains=2,
            clean_nodes=5,
            flagged_nodes=2,
            blocking_findings=2,
            warning_findings=2,
        ),
        nodes=nodes,
        edges=edges,
        chains=chains,
        findings=findings,
        gate=GateEvaluation(
            verdict="FAIL",
            mode="strict",
            blocking_violations=2,
            evaluated_at=fixed_ts,
        ),
        legacy_bridge=LegacyBridgeSummary(present=False),
    )


class _FakeDist:
    def __init__(self, version: str) -> None:
        import sysconfig

        self.version = version
        self._path = Path(sysconfig.get_path("purelib")) / f"fake_plugin-{version}.dist-info"

    def locate_file(self, path: str) -> Path:
        return self._path.parent / path


class _FakeEntryPoint:
    def __init__(self, name: str, value: str, loader: object, version: str = "1.2.3") -> None:
        self.name = name
        self.value = value
        self.group = ENTRY_POINT_GROUP
        self.dist = _FakeDist(version)
        self._loader = loader

    def load(self) -> object:
        if isinstance(self._loader, Exception):
            raise self._loader
        return self._loader


def test_plugin_discovery_entry_points_and_error_isolation(monkeypatch: pytest.MonkeyPatch) -> None:
    def _good_aug(repo_root: Path, backend_subdir: str, res: ManipulatorExtractionResult) -> None:
        res.notes.append("good-ep-ran")

    def _broken_aug(repo_root: Path, backend_subdir: str, res: ManipulatorExtractionResult) -> None:
        res.notes.append("partial-dirty-note-must-rollback")
        raise RuntimeError("boom inside third-party plugin")

    fake_eps = [
        _FakeEntryPoint(
            "zeta-broken-load",
            "pkg_z:plugin",
            ImportError("missing optional dep"),
        ),
        _FakeEntryPoint(
            "alpha-good",
            "pkg_a:plugin",
            lambda: WythePluginSpec(
                name="alpha-good",
                kind="manipulator_augmenter",
                description="Good third-party augmenter",
                manipulator_hook=_good_aug,
            ),
            version="2.0.1",
        ),
        _FakeEntryPoint(
            "beta-crash-runtime",
            "pkg_b:plugin",
            WythePluginSpec(
                name="beta-crash-runtime",
                kind="manipulator_augmenter",
                description="Crashes mid-run",
                manipulator_hook=_broken_aug,
            ),
        ),
    ]
    monkeypatch.setattr("importlib.metadata.entry_points", lambda *, group: fake_eps)

    fake_compose = ModuleType("app.adapters.compose_sources")
    fake_compose.augment_container_sources = lambda root, sub, res: None  # type: ignore[attr-defined]
    monkeypatch.setitem(sys.modules, "app.adapters.compose_sources", fake_compose)

    meta = list_registered_plugins()
    names = [m["name"] for m in meta]
    assert names == [
        "container-sources",
        "tach-boundaries",
        "alpha-good",
        "beta-crash-runtime",
    ]
    assert meta[0]["origin"] == "builtin"
    assert meta[2]["origin"] == "entry_point"
    assert meta[2]["version"] == "2.0.1"
    json.dumps(meta)  # Must be 100% JSON-serializable

    res = ManipulatorExtractionResult(nodes=[], edges=[], routes=[])
    executed = run_manipulator_plugins(Path("/tmp"), ".", res)
    assert "alpha-good" in executed
    assert "beta-crash-runtime" not in executed
    assert "good-ep-ran" in res.notes
    assert "partial-dirty-note-must-rollback" not in res.notes
    assert any("zeta-broken-load" in n and "isolated" in n for n in res.notes)
    assert any("beta-crash-runtime" in n and "isolated" in n for n in res.notes)

    with pytest.raises(ImportError):
        discover_plugins(strict_plugins=True)


def test_untrusted_repo_never_executed_without_explicit_opt_in(tmp_path: Path) -> None:
    sentinel = tmp_path / "pwned.txt"
    evil_code = (
        "from pathlib import Path\n"
        f"Path({str(sentinel)!r}).write_text('executed!')\n"
        "from app.adapters.plugin_registry import WythePluginSpec\n"
        "WYTHE_PLUGIN = WythePluginSpec(\n"
        "    name='optin-local',\n"
        "    kind='post_scan_check',\n"
        "    post_scan_hook=lambda root, rep: ['local-check-ok'],\n"
        ")\n"
    )
    (tmp_path / "wythe_plugin.py").write_text(evil_code, encoding="utf-8")
    (tmp_path / "plugins").mkdir()
    plugin_file = tmp_path / "plugins" / "custom_hook.py"
    plugin_file.write_text(evil_code, encoding="utf-8")

    # 1. Default discovery and scan execution NEVER import `.py` files from target repo.
    res = ManipulatorExtractionResult(nodes=[], edges=[], routes=[])
    run_manipulator_plugins(tmp_path, ".", res, plugins=None)
    assert not sentinel.exists()

    # 2. Passing local_plugin_modules WITHOUT allow_local_plugins=True fails closed BEFORE import.
    with pytest.raises(PermissionError):
        discover_plugins(
            repo_root=tmp_path,
            local_plugin_modules=[str(plugin_file)],
            allow_local_plugins=False,
        )
    assert not sentinel.exists()

    # 3. Explicit opt-in (`allow_local_plugins=True`) loads and executes the local plugin.
    report = _sample_report()
    out = run_post_scan_plugins(
        tmp_path,
        report,
        allow_local_plugins=True,
        local_plugin_modules=[str(plugin_file)],
    )
    assert sentinel.exists()
    assert "optin-local" in out.executed_plugins
    assert "local-check-ok" in report.scan_notes


def test_tach_bridge_noop_when_absent(tmp_path: Path) -> None:
    res = ManipulatorExtractionResult(nodes=[], edges=[], routes=[])
    augment_tach_boundaries(tmp_path, "backend", res)
    assert res.notes == []
    assert res.findings == []


def test_tach_bridge_domains_utility_interfaces_and_violations(tmp_path: Path) -> None:
    (tmp_path / "tach.toml").write_text(
        """
source_roots = ["src"]
layers = ["api", "domain", "infra"]

[[modules]]
path = "<root>"
depends_on = ["api", "orders", "billing"]

[[modules]]
path = "shared_log"
utility = true
depends_on = []

[[modules]]
path = "orders"
layer = "domain"
depends_on = [{ path = "customers", deprecated = true }]

[[interfaces]]
from = ["orders"]
expose = ["create_order", "schemas.*"]

[[modules]]
path = "customers"
layer = "domain"
depends_on = []
strict = true

[[modules]]
path = "billing"
layer = "domain"
depends_on = ["orders"]

[[modules]]
path = "api"
layer = "api"
depends_on = ["orders", "billing"]
""",
        encoding="utf-8",
    )

    src = tmp_path / "src"
    for pkg in ("shared_log", "orders", "customers", "billing", "api"):
        (src / pkg).mkdir(parents=True)
        (src / pkg / "__init__.py").write_text("", encoding="utf-8")

    (src / "main.py").write_text("from api import routes\n", encoding="utf-8")
    (src / "shared_log" / "logger.py").write_text("def log_msg(x: str) -> None:\n    pass\n")
    (src / "customers" / "__init__.py").write_text(
        "__all__ = ['CustomerDTO']\nCustomerDTO = dict\nSecretRow = dict\n",
        encoding="utf-8",
    )
    (src / "customers" / "repo.py").write_text("def raw_query() -> None:\n    pass\n")

    # Allowed imports in orders: utility (`shared_log`) + deprecated dep (`customers.CustomerDTO`)
    (src / "orders" / "__init__.py").write_text(
        "from .service import create_order\n__all__ = ['create_order']\n",
        encoding="utf-8",
    )
    (src / "orders" / "schemas.py").write_text("class OrderRead:\n    pass\n")
    (src / "orders" / "internal.py").write_text("def _secret_pricing() -> int:\n    return 42\n")
    (src / "orders" / "service.py").write_text(
        "from shared_log.logger import log_msg\n"
        "from customers import CustomerDTO\n"
        "def create_order() -> CustomerDTO:\n"
        "    log_msg('ok')\n"
        "    return {}\n",
        encoding="utf-8",
    )

    # Allowed in api: exposed `orders.create_order` and `orders.schemas.OrderRead`
    (src / "api" / "routes.py").write_text(
        "from orders import create_order\n"
        "from orders.schemas import OrderRead\n",
        encoding="utf-8",
    )

    # Violations in billing:
    # 1) `customers` is NOT in billing.depends_on
    # 2) `orders.internal._secret_pricing` bypasses `orders` [[interfaces]]
    (src / "billing" / "invoice.py").write_text(
        "from orders import create_order\n"
        "from customers import CustomerDTO\n"
        "from orders.internal import _secret_pricing\n",
        encoding="utf-8",
    )
    # Caller-only file (no AtlasNode) violating `strict = true` on `customers`
    (src / "orders" / "models_caller.py").write_text(
        "from customers.repo import raw_query\n",
        encoding="utf-8",
    )

    res = ManipulatorExtractionResult(
        nodes=[
            AtlasNode(
                id="m:service:orders_service",
                tier="manipulate",
                subkind="service",
                label="orders.service",
                source_file="src/orders/service.py",
                line=1,
                summary="Orders domain service.",
            ),
            AtlasNode(
                id="m:service:billing_invoice",
                tier="manipulate",
                subkind="service",
                label="billing.invoice",
                source_file="src/billing/invoice.py",
                line=1,
                summary="Billing invoice service.",
            ),
            AtlasNode(
                id="m:service:customers_repo",
                tier="manipulate",
                subkind="service",
                label="customers.repo",
                source_file="src/customers/repo.py",
                line=1,
                summary="Customer repo.",
            ),
        ],
        edges=[
            # Synthetic calls_helper edge from customers -> api (upward/undeclared dependency)
            AtlasEdge(
                id="e:cust->api",
                source_id="m:service:customers_repo",
                target_id="m:service:billing_invoice",
                kind="calls_helper",
                verification="declared",
                evidence_path="src/customers/repo.py",
                evidence_note="Synthetic helper call",
            )
        ],
        routes=[],
    )

    augment_tach_boundaries(tmp_path, "src", res)

    orders_node = next(n for n in res.nodes if n.id == "m:service:orders_service")
    assert "[tach:orders (layer=domain)]" in orders_node.summary
    assert orders_node.verification_note is not None
    assert "tach module `orders`" in orders_node.verification_note

    # Zero violations on valid files (`src/orders/service.py`, `src/api/routes.py`, `src/main.py`)
    flagged_files = [f.source_file for f in res.findings]
    assert "src/orders/service.py" not in flagged_files
    assert "src/api/routes.py" not in flagged_files
    assert "src/main.py" not in flagged_files

    # Expected MANIP-006 violations:
    assert all(f.rule_code == "MANIP-006" for f in res.findings)
    assert all(f.confidence == "confirmed" for f in res.findings)
    assert all(f.evidence_strength == "structural_match" for f in res.findings)

    billing_findings = [f for f in res.findings if f.source_file == "src/billing/invoice.py"]
    assert len(billing_findings) == 2
    assert any("customers" in f.title for f in billing_findings)
    assert any("interfaces" in f.title and "_secret_pricing" in f.title for f in billing_findings)

    strict_findings = [f for f in res.findings if f.source_file == "src/orders/models_caller.py"]
    assert len(strict_findings) == 1
    assert "Strict tach module boundary" in strict_findings[0].title

    edge_findings = [f for f in res.findings if f.source_file == "src/customers/repo.py"]
    assert len(edge_findings) == 1
    assert "billing" in edge_findings[0].title


def test_openlineage_static_bundle_accuracy_and_determinism() -> None:
    report = _sample_report()
    bundle_a = build_openlineage_static_bundle(report)
    bundle_b = build_openlineage_static_bundle(report)
    assert json.dumps(bundle_a, sort_keys=True) == json.dumps(bundle_b, sort_keys=True)

    assert bundle_a["producer"] == "https://github.com/Euda1mon1a/wythe"
    assert bundle_a["schemaURL"] == "https://openlineage.io/spec/2-0-2/OpenLineage.json"

    datasets = {d["name"]: d for d in bundle_a["datasets"]}  # type: ignore[index]
    assert set(datasets) == {"customers", "orders", "redis:rate_window"}
    assert datasets["customers"]["namespace"] == "wythe://demo-shop/sql"
    assert datasets["redis:rate_window"]["namespace"] == "wythe://demo-shop/cache"
    cust_fields = datasets["customers"]["facets"]["schema"]["fields"]
    assert cust_fields == [
        {"name": "id", "type": "uuid"},
        {"name": "email", "type": "text"},
        {"name": "tier", "type": "VARCHAR(32)"},
    ]
    cust_loc = datasets["customers"]["facets"]["sourceCodeLocation"]
    assert cust_loc["path"] == "backend/schema.sql"
    assert cust_loc["line"] == 10
    assert cust_loc["version"] == "abc1234def5678"

    jobs = {j["name"]: j for j in bundle_a["jobs"]}  # type: ignore[index]
    svc_job = jobs["m:service:order_service"]
    assert [i["name"] for i in svc_job["inputs"]] == ["customers", "orders"]
    assert [o["name"] for o in svc_job["outputs"]] == ["redis:rate_window", "orders"]

    # Read-only GET route inherits reads (`inputs`) without inheriting service writes (`outputs`)!
    get_job = jobs["m:route:GET:/api/v1/orders"]
    assert [i["name"] for i in get_job["inputs"]] == ["customers", "orders"]
    assert get_job["outputs"] == []

    # Mutating POST route propagates both read inputs and written outputs.
    post_job = jobs["m:route:POST:/api/v1/orders"]
    assert [i["name"] for i in post_job["inputs"]] == ["customers", "orders"]
    assert [o["name"] for o in post_job["outputs"]] == ["redis:rate_window", "orders"]

    # E2E write chain vs read chain
    write_chain = jobs["chain:1:POST:/api/v1/orders"]
    assert [i["name"] for i in write_chain["inputs"]] == ["customers", "orders"]
    assert [o["name"] for o in write_chain["outputs"]] == ["orders"]

    read_chain = jobs["chain:2:GET:/api/v1/orders"]
    assert [i["name"] for i in read_chain["inputs"]] == ["orders"]
    assert read_chain["outputs"] == []


def test_companion_security_correlator_trivy_json_sarif_and_syft_sboms(tmp_path: Path) -> None:
    report = _sample_report()

    # 1. Trivy JSON + Syft CycloneDX JSON
    trivy_json = tmp_path / "trivy-report.json"
    redacted_probe_marker = "SYNTHETIC_TRIVY_MATCH_DO_NOT_ECHO"  # @secret-ok: synthetic redaction assertion sentinel
    trivy_json.write_text(
        json.dumps(
            {
                "SchemaVersion": 2,
                "Results": [
                    {
                        "Target": "demo-shop:latest",
                        "Vulnerabilities": [
                            {
                                "VulnerabilityID": "CVE-2026-1001",
                                "PkgName": "openssl",
                                "Severity": "CRITICAL",
                                "Title": "Buffer overflow in X509 parser",
                            },
                            {
                                "VulnerabilityID": "CVE-2026-1002",
                                "PkgName": "urllib3",
                                "Severity": "MEDIUM",
                                "Title": "Redirect header leak",
                            },
                        ],
                        "Misconfigurations": [
                            {
                                "ID": "DS002",
                                "Status": "FAIL",
                                "Severity": "HIGH",
                                "Title": "Image user should not be root",
                            },
                            {
                                "ID": "DS001",
                                "Status": "PASS",
                                "Severity": "LOW",
                                "Title": "Passed check should not count",
                            },
                        ],
                        "Secrets": [
                            {
                                "RuleID": "aws-access-key-id",
                                "Severity": "CRITICAL",
                                "Title": "AWS Access Key ID",
                                "Match": redacted_probe_marker,
                            }
                        ],
                    }
                ],
            }
        ),
        encoding="utf-8",
    )

    syft_cdx = tmp_path / "sbom.cdx.json"
    syft_cdx.write_text(
        json.dumps(
            {
                "bomFormat": "CycloneDX",
                "specVersion": "1.5",
                "components": [
                    {
                        "name": "fastapi",
                        "version": "0.115.0",
                        "purl": "pkg:pypi/fastapi@0.115.0",
                    },
                    {
                        "name": "pydantic",
                        "version": "2.9.2",
                        "purl": "pkg:pypi/pydantic@2.9.2",
                    },
                    {
                        "name": "openssl",
                        "version": "3.0.13",
                        "purl": "pkg:deb/debian/openssl@3.0.13",
                    },
                ],
            }
        ),
        encoding="utf-8",
    )

    summary_1 = summarize_companion_security_artifacts(
        report, trivy_path=trivy_json, syft_path=syft_cdx
    )
    serialized_1 = json.dumps(summary_1)
    assert redacted_probe_marker not in serialized_1  # Never echo secret material!
    assert summary_1["target_code_executed"] is False
    assert summary_1["automated_security_audit"] is False
    assert "NOT an automated security audit" in str(summary_1["non_certification_disclaimer"])

    bp = summary_1["blueprint_stage"]  # type: ignore[index]
    assert len(bp["unguarded_writes_truth_003"]) == 1
    assert len(bp["client_policy_shadows_disp_001"]) == 1
    assert len(bp["unplugged_policy_tables_truth_001"]) == 1
    assert len(bp["container_packaging_drift"]) == 1

    crate_1 = summary_1["crate_stage"]  # type: ignore[index]
    assert crate_1["syft_sbom"]["format"] == "cyclonedx"
    assert crate_1["syft_sbom"]["package_count"] == 3
    assert crate_1["syft_sbom"]["ecosystems"] == {"deb": 1, "pypi": 2}
    assert crate_1["trivy_report"]["format"] == "trivy-json"
    assert crate_1["trivy_report"]["vulnerability_count"] == 2
    assert crate_1["trivy_report"]["misconfiguration_count"] == 1
    assert crate_1["trivy_report"]["secret_count"] == 1
    assert crate_1["trivy_report"]["severity_counts"]["CRITICAL"] == 2
    assert crate_1["trivy_report"]["severity_counts"]["HIGH"] == 1
    assert set(summary_1["handoff"]) == {"blue_team", "red_team", "purple_team"}  # type: ignore[arg-type]

    # 2. Trivy SARIF + Syft SPDX JSON
    trivy_sarif = tmp_path / "trivy.sarif"
    trivy_sarif.write_text(
        json.dumps(
            {
                "version": "2.1.0",
                "runs": [
                    {
                        "tool": {
                            "driver": {
                                "rules": [
                                    {
                                        "id": "CVE-2026-9999",
                                        "properties": {
                                            "tags": ["vulnerability", "CRITICAL"],
                                            "security-severity": "9.8",
                                        },
                                    },
                                    {
                                        "id": "AVD-DS-0002",
                                        "properties": {"tags": ["misconfiguration", "HIGH"]},
                                    },
                                ]
                            }
                        },
                        "results": [
                            {
                                "ruleId": "CVE-2026-9999",
                                "level": "error",
                                "message": {"text": "Critical RCE in libfoo"},
                            },
                            {
                                "ruleId": "AVD-DS-0002",
                                "level": "warning",
                                "message": {"text": "Container runs as root"},
                            },
                        ],
                    }
                ],
            }
        ),
        encoding="utf-8",
    )
    syft_spdx = tmp_path / "sbom.spdx.json"
    syft_spdx.write_text(
        json.dumps(
            {
                "spdxVersion": "SPDX-2.3",
                "packages": [
                    {
                        "SPDXID": "SPDXRef-DocumentRoot-Image-demo",
                        "name": "demo-shop:latest",
                        "primaryPackagePurpose": "CONTAINER",
                    },
                    {
                        "SPDXID": "SPDXRef-Package-react",
                        "name": "react",
                        "versionInfo": "18.3.1",
                        "externalRefs": [
                            {
                                "referenceType": "purl",
                                "referenceLocator": "pkg:npm/react@18.3.1",
                            }
                        ],
                    },
                ],
            }
        ),
        encoding="utf-8",
    )
    summary_2 = summarize_companion_security_artifacts(
        report, trivy_path=trivy_sarif, syft_path=syft_spdx
    )
    crate_2 = summary_2["crate_stage"]  # type: ignore[index]
    assert crate_2["trivy_report"]["format"] == "sarif"
    assert crate_2["trivy_report"]["vulnerability_count"] == 1
    assert crate_2["trivy_report"]["misconfiguration_count"] == 1
    assert crate_2["trivy_report"]["severity_counts"]["CRITICAL"] == 1
    assert crate_2["trivy_report"]["severity_counts"]["HIGH"] == 1
    assert crate_2["syft_sbom"]["format"] == "spdx"
    assert crate_2["syft_sbom"]["package_count"] == 1
    assert crate_2["syft_sbom"]["ecosystems"] == {"npm": 1}


def test_new_modules_pass_wythe_self_dogfood_hygiene() -> None:
    wt_root = Path(__file__).resolve().parents[2]
    targets = [
        ("backend/app/adapters/dockerfile_sources.py", "app.adapters.dockerfile_sources"),
        ("backend/app/adapters/compose_sources.py", "app.adapters.compose_sources"),
        ("backend/app/adapters/k8s_sources.py", "app.adapters.k8s_sources"),
        ("backend/app/adapters/plugin_registry.py", "app.adapters.plugin_registry"),
        ("backend/app/adapters/tach_bridge.py", "app.adapters.tach_bridge"),
        (
            "backend/app/services/companion_export_service.py",
            "app.services.companion_export_service",
        ),
    ]
    for rel_path, mod_name in targets:
        source_text = (wt_root / rel_path).read_text(encoding="utf-8")
        parsed = parse_python_module(source_text, rel_path, mod_name)
        assert parsed is not None
        if "/adapters/" not in rel_path:
            assert parsed.policy_literals == (), f"MANIP-001 triggered in {rel_path}"
        assert parsed.raw_clock_calls == (), f"MANIP-002 triggered in {rel_path}"



def test_protocol_plugin_classes_and_enable_disable_filters(monkeypatch: pytest.MonkeyPatch) -> None:
    class _ProtocolManipPlugin:
        name = "proto-manip"
        version = "0.4.0"
        description = "Protocol-based manipulator augmenter"
        enabled_by_default = False

        def augment_manipulator(
            self, repo_root: Path, backend_subdir: str, result: ManipulatorExtractionResult
        ) -> None:
            result.notes.append("proto-manip-executed")

    class _ProtocolPostPlugin:
        name = "proto-post"
        version = "0.5.0"
        description = "Protocol-based post-scan checker"

        def check_report(self, repo_root: Path, report: TruthAtlasReport) -> object:
            return ["proto-post-executed"]

    fake_eps = [
        _FakeEntryPoint("proto-manip", "pkg:Manip", _ProtocolManipPlugin()),
        _FakeEntryPoint("proto-post", "pkg:Post", _ProtocolPostPlugin()),
    ]
    monkeypatch.setattr("importlib.metadata.entry_points", lambda *, group: fake_eps)

    res = ManipulatorExtractionResult(nodes=[], edges=[], routes=[])
    # Disabled by default (`enabled_by_default = False`)
    ran_default = run_manipulator_plugins(Path("/tmp"), ".", res)
    assert "proto-manip" not in ran_default
    assert "proto-manip-executed" not in res.notes

    # Explicit opt-in via `enabled_names`
    ran_explicit = run_manipulator_plugins(Path("/tmp"), ".", res, enabled_names={"proto-manip"})
    assert ran_explicit == ["proto-manip"]
    assert "proto-manip-executed" in res.notes

    # Post-scan protocol plugin + `disabled_names`
    rep = _sample_report()
    post_skipped = run_post_scan_plugins(Path("/tmp"), rep, disabled_names={"proto-post"})
    assert post_skipped.executed_plugins == []
    post_ran = run_post_scan_plugins(Path("/tmp"), rep)
    assert post_ran.executed_plugins == ["proto-post"]
    assert "proto-post-executed" in rep.scan_notes


def test_tach_subdir_relative_imports_visibility_and_attr_interface(tmp_path: Path) -> None:
    backend = tmp_path / "backend"
    backend.mkdir()
    (backend / "tach.toml").write_text(
        """
source_roots = ["."]

[[modules]]
path = "payments"
depends_on = ["ledger"]

[[modules]]
path = "ledger"
depends_on = []
visibility = ["settlement"]

[[modules]]
path = "settlement"
depends_on = ["ledger"]

[[interfaces]]
from = ["ledger"]
expose = ["record_entry"]
""",
        encoding="utf-8",
    )
    for mod in ("payments", "ledger", "settlement"):
        (backend / mod).mkdir()
        (backend / mod / "__init__.py").write_text(
            "def record_entry() -> None:\n    pass\ndef _wipe_ledger() -> None:\n    pass\n",
            encoding="utf-8",
        )

    # `payments` tries relative import into `ledger`, which restricts visibility to `settlement`.
    (backend / "payments" / "charge.py").write_text(
        "from ..ledger import record_entry\n",
        encoding="utf-8",
    )
    # `settlement` has visibility to `ledger`, but accesses unexposed `ledger._wipe_ledger` via `import ledger`.
    (backend / "settlement" / "reconcile.py").write_text(
        "import ledger\nledger.record_entry()\nledger._wipe_ledger()\n",
        encoding="utf-8",
    )

    res = ManipulatorExtractionResult(nodes=[], edges=[], routes=[])
    augment_tach_boundaries(tmp_path, "backend", res)

    by_file = {f.source_file: f for f in res.findings}
    assert "backend/payments/charge.py" in by_file
    assert "visibility" in by_file["backend/payments/charge.py"].title
    assert "backend/settlement/reconcile.py" in by_file
    assert "_wipe_ledger" in by_file["backend/settlement/reconcile.py"].title
