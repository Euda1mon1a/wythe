"""End-to-end integration tests for CLI, plugins, containers, tach, and OpenLineage across profiles."""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from app import __version__
from app.cli import main as cli_main
from app.db import session as db_session


@pytest.fixture(autouse=True)
def _isolate_state(monkeypatch, tmp_path: Path):
    state_dir = tmp_path / ".wythe-state"
    monkeypatch.setenv("WYTHE_STATE_DIR", str(state_dir))
    monkeypatch.delenv("WYTHE_DATABASE_URL", raising=False)
    monkeypatch.delenv("TRUTH_ATLAS_DATABASE_URL", raising=False)
    db_session.get_session_factory.cache_clear()
    try:
        yield
    finally:
        db_session.get_session_factory.cache_clear()


def test_cli_plugins_list_and_untrusted_refusal(tmp_path: Path, capsys) -> None:
    rc = cli_main(["plugins", "--json"])
    assert rc == 0
    payload = json.loads(capsys.readouterr().out)
    assert payload["entry_point_group"] == "wythe.plugins"
    by_name = {p["name"]: p for p in payload["plugins"]}
    assert "container-sources" in by_name
    assert "tach-boundaries" in by_name
    assert by_name["container-sources"]["version"] == __version__ == "0.2.6"
    assert by_name["tach-boundaries"]["version"] == __version__ == "0.2.6"
    assert "Kubernetes" in by_name["container-sources"]["description"]

    # Local plugin without explicit --allow-local-plugins must fail closed with exit 2
    bad_plugin = tmp_path / "untrusted_plugin.py"
    bad_plugin.write_text("WYTHE_PLUGIN = None\n", encoding="utf-8")
    rc_err = cli_main(["plugins", "--plugin", str(bad_plugin)])
    assert rc_err == 2
    assert "allow_local_plugins" in capsys.readouterr().err


def test_fullstack_scan_gate_openlineage_and_companion_cli(tmp_path: Path, capsys) -> None:
    repo = tmp_path / "sample-stack"
    (repo / "backend" / "app" / "api").mkdir(parents=True)
    (repo / "backend" / "app" / "billing").mkdir(parents=True)
    (repo / "backend" / "app" / "scheduling").mkdir(parents=True)
    (repo / "backend" / "app" / "workers").mkdir(parents=True)
    (repo / "frontend" / "src" / "app").mkdir(parents=True)

    (repo / "backend" / "schema.sql").write_text(
        "CREATE TABLE invoices (id INTEGER PRIMARY KEY, amount INTEGER NOT NULL);\n",
        encoding="utf-8",
    )
    (repo / "backend" / "app" / "models.py").write_text(
        "from sqlalchemy import Integer\n"
        "from sqlalchemy.orm import DeclarativeBase, Mapped, mapped_column\n"
        "class Base(DeclarativeBase):\n    pass\n"
        "class Invoice(Base):\n"
        "    __tablename__ = 'invoices'\n"
        "    id: Mapped[int] = mapped_column(Integer, primary_key=True)\n"
        "    amount: Mapped[int] = mapped_column(Integer)\n",
        encoding="utf-8",
    )
    (repo / "backend" / "app" / "scheduling" / "internal_rules.py").write_text(
        "def compute_slot() -> int:\n    return 1\n",
        encoding="utf-8",
    )
    # Cross-domain forbidden import: billing -> scheduling (violates tach.toml -> MANIP-006)
    (repo / "backend" / "app" / "billing" / "invoice_service.py").write_text(
        "from sqlalchemy import select\n"
        "from app.models import Invoice\n"
        "from app.scheduling.internal_rules import compute_slot\n"
        "def list_invoices(session):\n"
        "    _ = compute_slot()\n"
        "    return session.scalars(select(Invoice)).all()\n",
        encoding="utf-8",
    )
    # Worker called ONLY by compose.yaml (must NOT be flagged as MANIP-003 inert)
    (repo / "backend" / "app" / "workers" / "digest_worker.py").write_text(
        "from sqlalchemy import select\n"
        "from app.models import Invoice\n"
        "def run_digest(session):\n"
        "    return session.scalars(select(Invoice)).all()\n",
        encoding="utf-8",
    )
    (repo / "backend" / "app" / "api" / "invoices.py").write_text(
        "from fastapi import APIRouter\n"
        "from app.billing.invoice_service import list_invoices\n"
        "router = APIRouter(prefix='/api/v1/invoices')\n"
        "@router.get('')\n"
        "def get_invoices(session=None):\n"
        "    return list_invoices(session)\n",
        encoding="utf-8",
    )
    (repo / "backend" / "app" / "main.py").write_text(
        "from fastapi import FastAPI\n"
        "from app.api.invoices import router\n"
        "app = FastAPI()\n"
        "app.include_router(router)\n",
        encoding="utf-8",
    )
    (repo / "frontend" / "package.json").write_text(
        json.dumps({"name": "ui", "dependencies": {"next": "14.2.0", "react": "18.3.0"}}),
        encoding="utf-8",
    )
    (repo / "frontend" / "src" / "app" / "page.tsx").write_text(
        "export default async function Page() {\n"
        "  const res = await fetch('/api/v1/invoices');\n"
        "  return <main>{String(res.ok)}</main>;\n"
        "}\n",
        encoding="utf-8",
    )
    (repo / "backend" / "tach.toml").write_text(
        'source_roots = ["."]\n'
        "[[modules]]\npath = \"app.api\"\ndepends_on = [\"app.billing\"]\n"
        "[[modules]]\npath = \"app.billing\"\ndepends_on = [\"app.models\"]\n"
        "[[modules]]\npath = \"app.scheduling\"\ndepends_on = []\n"
        "[[modules]]\npath = \"app.models\"\nutility = true\n",
        encoding="utf-8",
    )
    # Dockerfile omits app/scheduling/ while app.main transitively imports it, and uses $PORT in exec form
    (repo / "Dockerfile").write_text(
        "FROM python:3.12-slim\n"
        "WORKDIR /srv\n"
        "COPY backend/app/main.py /srv/app/main.py\n"
        "COPY backend/app/models.py /srv/app/models.py\n"
        "COPY backend/app/api /srv/app/api\n"
        "COPY backend/app/billing /srv/app/billing\n"
        'CMD ["uvicorn", "app.main:app", "--port", "$PORT"]\n',
        encoding="utf-8",
    )
    (repo / "compose.yaml").write_text(
        "services:\n"
        "  api:\n"
        "    build: .\n"
        "    environment:\n"
        "      DUTY_HOUR_LIMIT: 80\n"
        "  worker:\n"
        "    build: .\n"
        "    command: python backend/app/workers/digest_worker.py\n",
        encoding="utf-8",
    )

    trivy_file = tmp_path / "trivy.json"
    trivy_file.write_text(
        json.dumps(
            {
                "SchemaVersion": 2,
                "Results": [
                    {
                        "Target": "app:test",
                        "Vulnerabilities": [{"VulnerabilityID": "CVE-2026-0001", "Severity": "HIGH"}],
                    }
                ],
            }
        ),
        encoding="utf-8",
    )
    syft_file = tmp_path / "sbom.cdx.json"
    syft_file.write_text(
        json.dumps(
            {
                "bomFormat": "CycloneDX",
                "specVersion": "1.5",
                "components": [{"name": "fastapi", "version": "0.115.0", "purl": "pkg:pypi/fastapi@0.115.0"}],
            }
        ),
        encoding="utf-8",
    )

    scan_json = tmp_path / "scan.json"
    comp_json = tmp_path / "companion.json"
    rc_scan = cli_main(
        [
            "scan",
            str(repo),
            "--json",
            str(scan_json),
            "--trivy-report",
            str(trivy_file),
            "--syft-sbom",
            str(syft_file),
            "--companion-out",
            str(comp_json),
        ]
    )
    assert rc_scan == 0
    capsys.readouterr()

    report = json.loads(scan_json.read_text(encoding="utf-8"))
    codes = {f["rule_code"] for f in report["findings"]}
    assert {"MANIP-001", "MANIP-004", "MANIP-005", "MANIP-006"} <= codes
    # Worker wired via compose.yaml must not have false MANIP-003
    manip3_files = {f["source_file"] for f in report["findings"] if f["rule_code"] == "MANIP-003"}
    assert "backend/app/workers/digest_worker.py" not in manip3_files

    # Gate fails strictly because MANIP-001 and MANIP-006 are blocking
    assert cli_main(["gate", "--strict", str(repo)]) == 1
    capsys.readouterr()

    # OpenLineage export
    ol_json = tmp_path / "openlineage.json"
    assert cli_main(["export-openlineage", str(repo), "--out", str(ol_json)]) == 0
    capsys.readouterr()
    ol = json.loads(ol_json.read_text(encoding="utf-8"))
    assert any(d["name"] == "invoices" for d in ol["datasets"])
    assert len(ol["jobs"]) >= 3

    # Security companion subcommand
    sec_json = tmp_path / "sec-companion.json"
    assert (
        cli_main(
            [
                "security",
                "companion",
                str(repo),
                "--trivy-report",
                str(trivy_file),
                "--syft-sbom",
                str(syft_file),
                "--json",
                str(sec_json),
            ]
        )
        == 0
    )
    capsys.readouterr()
    comp = json.loads(sec_json.read_text(encoding="utf-8"))
    assert comp["automated_security_audit"] is False
    assert comp["crate_stage"]["syft_sbom"]["package_count"] == 1
    assert comp["crate_stage"]["trivy_report"]["vulnerability_count"] == 1
    assert len(comp["blueprint_stage"]["horizontal_boundary_violations_manip_006"]) == 1


def test_non_python_nextjs_prisma_profile_receives_container_lineage(
    tmp_path: Path, capsys
) -> None:
    repo = tmp_path / "ts-app"
    (repo / "prisma").mkdir(parents=True)
    (repo / "src" / "app" / "api" / "items").mkdir(parents=True)
    (repo / "package.json").write_text(
        json.dumps({"name": "ts-app", "dependencies": {"next": "14.2.0", "@prisma/client": "5.0.0"}}),
        encoding="utf-8",
    )
    (repo / "prisma" / "schema.prisma").write_text(
        "datasource db { provider = \"postgresql\" url = env(\"DATABASE_URL\") }\n"
        "model Item { id Int @id @default(autoincrement()) title String }\n",
        encoding="utf-8",
    )
    (repo / "src" / "app" / "api" / "items" / "route.ts").write_text(
        "export async function GET() { return Response.json([]); }\n",
        encoding="utf-8",
    )
    (repo / "src" / "app" / "page.tsx").write_text(
        "export default async function Home() {\n"
        "  await fetch('/api/items');\n"
        "  return <main>Items</main>;\n"
        "}\n",
        encoding="utf-8",
    )
    (repo / "Dockerfile").write_text(
        "FROM node:22-alpine\n"
        "WORKDIR /app\n"
        "COPY missing-script.mjs /app/missing-script.mjs\n"
        'CMD ["node", "server.js"]\n',
        encoding="utf-8",
    )
    out_json = tmp_path / "ts-scan.json"
    assert cli_main(["scan", str(repo), "--profile", "nextjs-prisma", "--json", str(out_json)]) == 0
    capsys.readouterr()
    data = json.loads(out_json.read_text(encoding="utf-8"))
    node_ids = {n["id"] for n in data["nodes"]}
    assert "m:dockerfile:Dockerfile" in node_ids
    assert any(f["rule_code"] == "MANIP-005" for f in data["findings"])


def test_openlineage_compose_override_depends_on_and_deep_closure(
    tmp_path: Path, capsys
) -> None:
    repo = tmp_path / "ol-compose"
    (repo / "backend" / "app" / "api").mkdir(parents=True)
    (repo / "backend" / "app" / "workers").mkdir(parents=True)
    (repo / "backend" / "app" / "chain").mkdir(parents=True)
    (repo / "frontend" / "src" / "app").mkdir(parents=True)

    (repo / "backend" / "schema.sql").write_text(
        "CREATE TABLE orders (id INTEGER PRIMARY KEY, total INTEGER NOT NULL);\n",
        encoding="utf-8",
    )
    (repo / "backend" / "app" / "models.py").write_text(
        "from sqlalchemy import Integer\n"
        "from sqlalchemy.orm import DeclarativeBase, Mapped, mapped_column\n"
        "class Base(DeclarativeBase):\n    pass\n"
        "class Order(Base):\n"
        "    __tablename__ = 'orders'\n"
        "    id: Mapped[int] = mapped_column(Integer, primary_key=True)\n"
        "    total: Mapped[int] = mapped_column(Integer)\n",
        encoding="utf-8",
    )
    # Build a 32-hop helper chain (>25 old BFS cap) ending in a write to orders
    (repo / "backend" / "app" / "chain" / "step_32.py").write_text(
        "from app.models import Order\n"
        "def hop_32(session):\n"
        "    session.add(Order(id=1, total=10))\n"
        "    session.commit()\n",
        encoding="utf-8",
    )
    for idx in range(31, 0, -1):
        nxt = idx + 1
        (repo / "backend" / "app" / "chain" / f"step_{idx}.py").write_text(
            f"from app.chain.step_{nxt} import hop_{nxt}\n"
            f"def hop_{idx}(session):\n"
            f"    return hop_{nxt}(session)\n",
            encoding="utf-8",
        )
    (repo / "backend" / "app" / "api" / "orders.py").write_text(
        "from fastapi import APIRouter\n"
        "from app.chain.step_1 import hop_1\n"
        "router = APIRouter(prefix='/api/v1/orders')\n"
        "@router.post('')\n"
        "def create_order(session=None):\n"
        "    return hop_1(session)\n",
        encoding="utf-8",
    )
    (repo / "backend" / "app" / "main.py").write_text(
        "from fastapi import FastAPI\n"
        "from app.api.orders import router\n"
        "app = FastAPI()\n"
        "app.include_router(router)\n",
        encoding="utf-8",
    )
    (repo / "backend" / "app" / "workers" / "reconcile_worker.py").write_text(
        "from sqlalchemy import select\n"
        "from app.models import Order\n"
        "def reconcile(session):\n"
        "    return session.scalars(select(Order)).all()\n",
        encoding="utf-8",
    )
    (repo / "frontend" / "package.json").write_text(
        json.dumps({"name": "ui", "dependencies": {"next": "14.2.0"}}),
        encoding="utf-8",
    )
    (repo / "frontend" / "src" / "app" / "page.tsx").write_text(
        "export default function P() { return <main>ok</main>; }\n",
        encoding="utf-8",
    )
    (repo / "Dockerfile").write_text(
        "FROM python:3.12-slim\n"
        "WORKDIR /srv\n"
        "COPY backend /srv/backend\n"
        'CMD ["uvicorn", "backend.app.main:app"]\n',
        encoding="utf-8",
    )
    (repo / "compose.yaml").write_text(
        "services:\n"
        "  api:\n"
        "    build: .\n"
        "  worker:\n"
        "    build: .\n"
        "    command: python backend/app/workers/reconcile_worker.py\n"
        "  web:\n"
        "    image: nginx:alpine\n"
        "    depends_on:\n"
        "      - api\n",
        encoding="utf-8",
    )
    ol_out = tmp_path / "ol.json"
    assert cli_main(["export-openlineage", str(repo), "--out", str(ol_out)]) == 0
    capsys.readouterr()
    ol = json.loads(ol_out.read_text(encoding="utf-8"))
    jobs_by_id = {
        j["facets"]["wytheJob"]["nodeId"]: j
        for j in ol["jobs"]
        if "wytheJob" in j.get("facets", {}) and "nodeId" in j["facets"]["wytheJob"]
    }
    # 32-hop write reaches api compose service & route
    assert [o["name"] for o in jobs_by_id["m:compose:compose.yaml:api"]["outputs"]] == ["orders"]
    # Read-only worker overriding CMD must NOT inherit Dockerfile's write outputs
    worker_job = jobs_by_id["m:compose:compose.yaml:worker"]
    assert [i["name"] for i in worker_job["inputs"]] == ["orders"]
    assert worker_job["outputs"] == []
    # depends_on service must NOT inherit api's write outputs
    assert jobs_by_id["m:compose:compose.yaml:web"]["outputs"] == []


def test_shell_wrappers_split_entrypoint_sh_worker_and_rule_titles(
    tmp_path: Path, capsys
) -> None:
    # 1. FastAPI repo with tini shell wrapper, split ENTRYPOINT ["sh","-c"] + CMD, and .sh worker
    repo = tmp_path / "sh-wrap"
    (repo / "backend" / "app" / "workers").mkdir(parents=True)
    (repo / "frontend" / "src" / "app").mkdir(parents=True)
    (repo / "backend" / "app" / "main.py").write_text(
        "from fastapi import FastAPI\napp = FastAPI()\n", encoding="utf-8"
    )
    (repo / "backend" / "app" / "workers" / "bg.py").write_text(
        "def run_bg() -> int:\n    return 1\n", encoding="utf-8"
    )
    (repo / "entrypoint.sh").write_text(
        "#!/bin/sh\npython backend/app/workers/bg.py\n", encoding="utf-8"
    )
    (repo / "frontend" / "package.json").write_text(
        json.dumps({"name": "ui", "dependencies": {"next": "14.2.0"}}), encoding="utf-8"
    )
    (repo / "frontend" / "src" / "app" / "page.tsx").write_text(
        "export default function P() { return <main>ok</main>; }\n", encoding="utf-8"
    )
    (repo / "Dockerfile").write_text(
        "FROM python:3.12-slim\n"
        "WORKDIR /srv\n"
        "COPY backend /srv/backend\n"
        "COPY entrypoint.sh /srv/entrypoint.sh\n"
        'ENTRYPOINT ["/srv/entrypoint.sh"]\n',
        encoding="utf-8",
    )
    (repo / "Dockerfile.tini").write_text(
        "FROM python:3.12-slim\n"
        "WORKDIR /srv\n"
        "COPY backend /srv/backend\n"
        'ENTRYPOINT ["tini", "--", "sh", "-c", "exec uvicorn backend.app.main:app --port $PORT"]\n',
        encoding="utf-8",
    )
    (repo / "Dockerfile.split").write_text(
        "FROM python:3.12-slim\n"
        "WORKDIR /srv\n"
        "COPY backend /srv/backend\n"
        'ENTRYPOINT ["sh", "-c"]\n'
        'CMD ["uvicorn backend.app.main:app --port $PORT"]\n',
        encoding="utf-8",
    )
    scan_out = tmp_path / "sh-scan.json"
    assert cli_main(["scan", str(repo), "--json", str(scan_out)]) == 0
    capsys.readouterr()
    rep = json.loads(scan_out.read_text(encoding="utf-8"))
    assert [f for f in rep["findings"] if f["rule_code"] in ("MANIP-003", "MANIP-004")] == []
    rule_titles = {r["rule_code"]: r["title"] for r in rep["gate"]["rule_counts"]}
    assert "container" in rule_titles["MANIP-004"].lower()
    assert "container" in rule_titles["MANIP-005"].lower()
    assert "service config" in rule_titles["MANIP-001"].lower()

    # 2. python-services repo: Dockerfile caller reconciles stale 'No source caller' summary
    svc_repo = tmp_path / "py-svc"
    svc_repo.mkdir()
    (svc_repo / "worker.py").write_text("if __name__ == '__main__':\n    pass\n", encoding="utf-8")
    (svc_repo / "Dockerfile").write_text(
        "FROM python:3.12-slim\nWORKDIR /app\nCOPY worker.py /app/worker.py\n"
        'CMD ["python", "/app/worker.py"]\n',
        encoding="utf-8",
    )
    svc_out = tmp_path / "svc-scan.json"
    assert (
        cli_main(["scan", str(svc_repo), "--profile", "python-services", "--json", str(svc_out)])
        == 0
    )
    capsys.readouterr()
    svc_rep = json.loads(svc_out.read_text(encoding="utf-8"))
    worker_node = next(n for n in svc_rep["nodes"] if n["id"] == "m:script:worker.py")
    assert "Declared source caller/reference found." in worker_node["summary"]
    assert "No source caller/reference discovered" not in worker_node["summary"]


def test_v022_k8s_cronjob_manip003_and_openlineage_override(tmp_path: Path, capsys) -> None:
    repo = tmp_path / "k8s-stack"
    (repo / "backend" / "app" / "api").mkdir(parents=True)
    (repo / "backend" / "app" / "workers").mkdir(parents=True)
    (repo / "frontend" / "src" / "app").mkdir(parents=True)
    (repo / "k8s").mkdir(parents=True)

    (repo / "backend" / "schema.sql").write_text(
        "CREATE TABLE orders (id INTEGER PRIMARY KEY, total INTEGER NOT NULL);\n",
        encoding="utf-8",
    )
    (repo / "backend" / "app" / "models.py").write_text(
        "from sqlalchemy import Integer\n"
        "from sqlalchemy.orm import DeclarativeBase, Mapped, mapped_column\n"
        "class Base(DeclarativeBase):\n    pass\n"
        "class Order(Base):\n"
        "    __tablename__ = 'orders'\n"
        "    id: Mapped[int] = mapped_column(Integer, primary_key=True)\n"
        "    total: Mapped[int] = mapped_column(Integer)\n",
        encoding="utf-8",
    )
    (repo / "backend" / "app" / "api" / "orders.py").write_text(
        "from fastapi import APIRouter\n"
        "from app.models import Order\n"
        "router = APIRouter(prefix='/api/v1/orders')\n"
        "@router.post('')\n"
        "def create_order(session=None):\n"
        "    session.add(Order(id=1, total=50))\n"
        "    session.commit()\n",
        encoding="utf-8",
    )
    (repo / "backend" / "app" / "main.py").write_text(
        "from fastapi import FastAPI\n"
        "from app.api.orders import router\n"
        "app = FastAPI()\n"
        "app.include_router(router)\n",
        encoding="utf-8",
    )
    # Worker called ONLY by K8s CronJob (read-only SELECT; must NOT trigger MANIP-003 or write outputs)
    (repo / "backend" / "app" / "workers" / "k8s_audit_worker.py").write_text(
        "from sqlalchemy import select\n"
        "from app.models import Order\n"
        "def run_audit(session):\n"
        "    return session.scalars(select(Order)).all()\n",
        encoding="utf-8",
    )
    (repo / "frontend" / "package.json").write_text(
        json.dumps({"name": "ui", "dependencies": {"next": "14.2.0"}}),
        encoding="utf-8",
    )
    (repo / "frontend" / "src" / "app" / "page.tsx").write_text(
        "export default function P() { return <main>ok</main>; }\n",
        encoding="utf-8",
    )
    (repo / "Dockerfile").write_text(
        "FROM python:3.12-slim\n"
        "WORKDIR /srv\n"
        "COPY backend /srv/backend\n"
        'CMD ["uvicorn", "backend.app.main:app"]\n',
        encoding="utf-8",
    )
    (repo / "k8s" / "workloads.yaml").write_text(
        "apiVersion: v1\n"
        "kind: ConfigMap\n"
        "metadata:\n"
        "  name: app-cfg\n"
        "data:\n"
        "  LOG_LEVEL: info\n"
        "---\n"
        "apiVersion: apps/v1\n"
        "kind: Deployment\n"
        "metadata:\n"
        "  name: orders-api\n"
        "spec:\n"
        "  template:\n"
        "    spec:\n"
        "      containers:\n"
        "        - name: api\n"
        "          image: orders-app:latest\n"
        "          args: [\"--port\", \"$(PORT)\"]\n"
        "---\n"
        "apiVersion: batch/v1\n"
        "kind: CronJob\n"
        "metadata:\n"
        "  name: orders-audit\n"
        "spec:\n"
        "  schedule: '0 * * * *'\n"
        "  jobTemplate:\n"
        "    spec:\n"
        "      template:\n"
        "        spec:\n"
        "          containers:\n"
        "            - name: audit\n"
        "              image: orders-app:latest\n"
        "              command: [\"python\", \"backend/app/workers/k8s_audit_worker.py\"]\n"
        "              envFrom:\n"
        "                - configMapRef:\n"
        "                    name: app-cfg\n",
        encoding="utf-8",
    )

    scan_out = tmp_path / "k8s-scan.json"
    ol_out = tmp_path / "k8s-ol.json"
    assert cli_main(["scan", str(repo), "--json", str(scan_out)]) == 0
    assert cli_main(["export-openlineage", str(repo), "--out", str(ol_out)]) == 0
    capsys.readouterr()

    rep = json.loads(scan_out.read_text(encoding="utf-8"))
    # K8s CronJob caller clears MANIP-003, and K8s $(PORT) does NOT trigger MANIP-004
    assert [f for f in rep["findings"] if f["rule_code"] in ("MANIP-003", "MANIP-004")] == []

    ol = json.loads(ol_out.read_text(encoding="utf-8"))
    jobs_by_id = {
        j["facets"]["wytheJob"]["nodeId"]: j
        for j in ol["jobs"]
        if "wytheJob" in j.get("facets", {}) and "nodeId" in j["facets"]["wytheJob"]
    }
    deploy_job = jobs_by_id["m:k8s:k8s/workloads.yaml:deployment:orders-api"]
    cron_job = jobs_by_id["m:k8s:k8s/workloads.yaml:cronjob:orders-audit"]
    assert [o["name"] for o in deploy_job["outputs"]] == ["orders"]
    assert [i["name"] for i in cron_job["inputs"]] == ["orders"]
    assert cron_job["outputs"] == []


def test_e2e_cli_context_cone_and_symbol_scoped_openlineage_with_tach_and_containers(
    tmp_path: Path, capsys
) -> None:
    """Verify `wythe context` and `wythe export-openlineage` across uvicorn/tach/K8s/Compose."""
    repo = tmp_path / "cone-and-ol-repo"
    (repo / "backend" / "app" / "api").mkdir(parents=True)
    (repo / "backend" / "app" / "services").mkdir(parents=True)
    (repo / "backend" / "app" / "workers").mkdir(parents=True)
    (repo / "frontend" / "src" / "app").mkdir(parents=True)
    (repo / "k8s").mkdir(parents=True)

    (repo / "backend" / "schema.sql").write_text(
        "CREATE TABLE orders (id INTEGER PRIMARY KEY, total INTEGER NOT NULL);\n"
        "CREATE TABLE audit_logs (id INTEGER PRIMARY KEY, message TEXT NOT NULL);\n",
        encoding="utf-8",
    )
    (repo / "backend" / "app" / "models.py").write_text(
        "from sqlalchemy import Integer, String\n"
        "from sqlalchemy.orm import DeclarativeBase, Mapped, mapped_column\n"
        "class Base(DeclarativeBase):\n    pass\n"
        "class Order(Base):\n"
        "    __tablename__ = 'orders'\n"
        "    id: Mapped[int] = mapped_column(Integer, primary_key=True)\n"
        "    total: Mapped[int] = mapped_column(Integer)\n"
        "class AuditLog(Base):\n"
        "    __tablename__ = 'audit_logs'\n"
        "    id: Mapped[int] = mapped_column(Integer, primary_key=True)\n"
        "    message: Mapped[str] = mapped_column(String)\n",
        encoding="utf-8",
    )
    (repo / "backend" / "app" / "services" / "order_svc.py").write_text(
        "from sqlalchemy import select\n"
        "from app.models import Order\n"
        "def list_orders(session):\n"
        "    return session.scalars(select(Order)).all()\n"
        "def create_order(session):\n"
        "    session.add(Order(id=1, total=42))\n"
        "    session.commit()\n",
        encoding="utf-8",
    )
    (repo / "backend" / "app" / "services" / "audit_svc.py").write_text(
        "from sqlalchemy import select\n"
        "from app.models import AuditLog\n"
        "def write_audit(session):\n"
        "    session.add(AuditLog(id=1, message='mutated'))\n"
        "    session.commit()\n"
        "def read_audit_digest(session):\n"
        "    return session.scalars(select(AuditLog)).all()\n",
        encoding="utf-8",
    )
    (repo / "backend" / "app" / "api" / "orders.py").write_text(
        "from fastapi import APIRouter\n"
        "from app.services.order_svc import create_order, list_orders\n"
        "from app.services.audit_svc import write_audit\n"
        "router = APIRouter(prefix='/api/v1/orders')\n"
        "@router.get('')\n"
        "def get_orders(session=None):\n"
        "    return list_orders(session)\n"
        "@router.post('')\n"
        "def post_order(session=None):\n"
        "    create_order(session)\n"
        "    write_audit(session)\n",
        encoding="utf-8",
    )
    (repo / "backend" / "app" / "main.py").write_text(
        "from fastapi import FastAPI\n"
        "from app.api.orders import router\n"
        "app = FastAPI()\n"
        "app.include_router(router)\n",
        encoding="utf-8",
    )
    (repo / "backend" / "app" / "workers" / "k8s_cron.py").write_text(
        "from app.services.audit_svc import read_audit_digest\n"
        "def run_digest(session=None):\n"
        "    return read_audit_digest(session)\n",
        encoding="utf-8",
    )
    (repo / "backend" / "tach.toml").write_text(
        'source_roots = ["."]\n'
        '[[modules]]\npath = "app.main"\ndepends_on = ["app.api"]\n'
        '[[modules]]\npath = "app.api"\ndepends_on = ["app.services"]\n'
        '[[modules]]\npath = "app.workers"\ndepends_on = ["app.services"]\n'
        '[[modules]]\npath = "app.services"\ndepends_on = ["app.models"]\n'
        '[[modules]]\npath = "app.models"\nutility = true\n',
        encoding="utf-8",
    )
    (repo / "frontend" / "package.json").write_text(
        json.dumps({"name": "ui", "dependencies": {"next": "14.2.0"}}),
        encoding="utf-8",
    )
    (repo / "frontend" / "src" / "app" / "page.tsx").write_text(
        "export default async function P() {\n"
        "  await fetch('/api/v1/orders');\n"
        "  return <main>orders</main>;\n"
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
        "  api:\n"
        "    build: .\n"
        '    command: ["uvicorn", "app.main:app"]\n'
        "  local-worker:\n"
        "    build: .\n"
        '    command: ["python", "-m", "app.workers.k8s_cron"]\n',
        encoding="utf-8",
    )
    (repo / "k8s" / "workloads.yaml").write_text(
        "apiVersion: apps/v1\n"
        "kind: Deployment\n"
        "metadata:\n"
        "  name: web-api\n"
        "spec:\n"
        "  template:\n"
        "    spec:\n"
        "      containers:\n"
        "        - name: api\n"
        "          image: cone-app:latest\n"
        '          command: ["uvicorn", "app.main:app"]\n'
        "---\n"
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
        "              image: cone-app:latest\n"
        '              command: ["python", "-m", "app.workers.k8s_cron"]\n',
        encoding="utf-8",
    )

    for seed in ("m:dockerfile:Dockerfile", "m:service:main"):
        assert cli_main(["context", str(repo), seed, "--full", "--json"]) == 0
        cone = json.loads(capsys.readouterr().out)
        manip_ids = {n["id"] for n in cone["manipulator_nodes"]}
        truth_ids = {n["id"] for n in cone["downstream_truth_nodes"]}
        assert "m:route:api.orders" in manip_ids
        assert "m:service:services.order_svc" in manip_ids
        assert "m:service:services.audit_svc" in manip_ids
        assert {"t:orders", "t:audit_logs"} <= truth_ids

    ol_path = tmp_path / "cone-ol.json"
    assert cli_main(["export-openlineage", str(repo), "--out", str(ol_path)]) == 0
    capsys.readouterr()
    ol = json.loads(ol_path.read_text(encoding="utf-8"))
    jobs = {j["name"]: j for j in ol["jobs"]}
    for ro_id in (
        "m:service:workers.k8s_cron",
        "m:k8s:k8s/workloads.yaml:cronjob:audit-digest",
        "m:compose:compose.yaml:local-worker",
    ):
        assert [i["name"] for i in jobs[ro_id]["inputs"]] == ["audit_logs"]
        assert jobs[ro_id]["outputs"] == []
    assert [o["name"] for o in jobs["m:dockerfile:Dockerfile"]["outputs"]] == [
        "audit_logs",
        "orders",
    ]

    # Also verify `--factory` app factory mounting routers does NOT sever the cone
    (repo / "backend" / "app" / "main.py").write_text(
        "from fastapi import FastAPI\n"
        "from app.api.orders import router\n"
        "def create_app():\n"
        "    app = FastAPI()\n"
        "    app.include_router(router)\n"
        "    return app\n",
        encoding="utf-8",
    )
    (repo / "Dockerfile").write_text(
        "FROM python:3.12-slim\n"
        "WORKDIR /srv\n"
        "COPY backend/app /srv/app\n"
        'CMD ["uvicorn", "app.main:create_app", "--factory"]\n',
        encoding="utf-8",
    )
    assert cli_main(["context", str(repo), "m:dockerfile:Dockerfile", "--full", "--json"]) == 0
    factory_cone = json.loads(capsys.readouterr().out)
    assert "m:route:api.orders" in {n["id"] for n in factory_cone["manipulator_nodes"]}
    assert {"t:orders", "t:audit_logs"} <= {
        n["id"] for n in factory_cone["downstream_truth_nodes"]
    }
