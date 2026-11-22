"""Wave 0.2.9 regression tests for Wythe issues #96 (daemon routes) and #101 Item 4 (deployment sources)."""

from __future__ import annotations

import ast
from datetime import UTC, datetime, timedelta
from pathlib import Path

from app.adapters.base import ManipulatorExtractionResult, TruthExtractionResult
from app.adapters.deployment_sources import (
    _clean_repo_source,
    deployment_mappings,
    symbolic_path,
)
from app.adapters.python_daemon_routes import _has_external_display_sources
from app.adapters.python_services import PythonServicesAdapter
from app.adapters.sql_ddl_truth import SqlDdlTruthAdapter
from app.schemas.atlas import (
    AtlasSummaryStats,
    GateEvaluation,
    LegacyBridgeSummary,
    TruthAtlasReport,
)
from app.services.llm_context_service import build_lineage_cone_slice


def _write(root: Path, rel: str, text: str) -> Path:
    dest = root / rel
    dest.parent.mkdir(parents=True, exist_ok=True)
    dest.write_text(text, encoding="utf-8")
    return dest


def test_fastapi_create_app_mount_dedup_and_path_expressions(tmp_path: Path) -> None:
    _write(
        tmp_path,
        "routes_jobs.py",
        "from fastapi import APIRouter\n\n"
        "SUB = '/sub'\n"
        "router = APIRouter(prefix='/jobs')\n\n"
        "def record_audit():\n"
        "    return 1\n\n"
        "@router.get('/status')\n"
        "def job_status():\n"
        "    return {'ok': True}\n\n"
        "@router.post(SUB + '/run')\n"
        "def run_job():\n"
        "    return {'started': True}\n\n"
        "def audit_job():\n"
        "    return record_audit()\n\n"
        "router.add_api_route(f'{SUB}/audit/{{item_id}}', audit_job, methods=['GET', 'POST'])\n",
    )
    _write(
        tmp_path,
        "app_daemon.py",
        "from fastapi import FastAPI\n"
        "from routes_jobs import router\n\n"
        "API_VER = 2\n\n"
        "def get_metrics():\n"
        "    return {'count': 1}\n\n"
        "def create_app():\n"
        "    prefix = '/api/v2'\n"
        "    app = FastAPI()\n"
        "    app.include_router(router, prefix=prefix)\n\n"
        "    @app.get(prefix + '/health')\n"
        "    def health():\n"
        "        return {'ok': True}\n\n"
        "    @app.post(f'{prefix}/items/{{item_id}}')\n"
        "    def create_item(item_id: str):\n"
        "        return {'id': item_id}\n\n"
        "    @app.get(f'/api/v{API_VER}/ping')\n"
        "    def ping():\n"
        "        return {'pong': True}\n\n"
        "    app.add_api_route(f'{prefix}/metrics', get_metrics, methods=['GET'])\n"
        "    return app\n",
    )

    manip = PythonServicesAdapter().extract(tmp_path, ".", TruthExtractionResult([], {}, {}))
    routes = {(r.http_method, r.full_path) for r in manip.routes}

    assert ("GET", "/api/v2/jobs/status") in routes
    assert ("POST", "/api/v2/jobs/sub/run") in routes
    assert ("GET", "/api/v2/jobs/sub/audit/{item_id}") in routes
    assert ("POST", "/api/v2/jobs/sub/audit/{item_id}") in routes
    assert ("GET", "/api/v2/health") in routes
    assert ("POST", "/api/v2/items/{item_id}") in routes
    assert ("GET", "/api/v2/ping") in routes
    assert ("GET", "/api/v2/metrics") in routes

    # Bogus unprefixed router mounts must NEVER be emitted alongside create_app() prefixed mounts.
    assert ("GET", "/jobs/status") not in routes
    assert ("POST", "/jobs/sub/run") not in routes
    assert ("GET", "/jobs/sub/audit/{item_id}") not in routes

    audit_route = next(
        r for r in manip.routes if r.http_method == "POST" and r.full_path == "/api/v2/jobs/sub/audit/{item_id}"
    )
    assert {"audit_job", "record_audit"} <= set(audit_route.called_symbols)

    jobs_node = next(n for n in manip.nodes if n.id == "m:route:routes_jobs.py:fastapi")
    assert all(p.startswith("/api/v2/jobs/") for p in jobs_node.http_paths)


def test_basehttp_path_helpers_tuple_unpack_slicing_and_normalization(tmp_path: Path) -> None:
    _write(
        tmp_path,
        "ops_daemon.py",
        "import posixpath\n"
        "from http.server import BaseHTTPRequestHandler\n"
        "from urllib.parse import unquote, urlparse\n\n"
        "MOUNT = '/ops'\n\n"
        "class OpsHandler(BaseHTTPRequestHandler):\n"
        "    def _parse_path(self):\n"
        "        parsed = urlparse(self.path)\n"
        "        clean = posixpath.normpath(unquote(parsed.path)).removesuffix('/')\n"
        "        return clean or '/', parsed.query\n\n"
        "    def _strip_mount(self, raw):\n"
        "        return raw[len(MOUNT):].removeprefix('/v1')\n\n"
        "    def _handle_sub(self, sub):\n"
        "        if sub == '/status':\n"
        "            self.send_response(200)\n\n"
        "    def do_GET(self):\n"
        "        route_path, _query = self._parse_path()\n"
        "        sub = self._strip_mount(route_path)\n"
        "        self._handle_sub(sub)\n"
        "        parts = self._parse_path()\n"
        "        if parts[0] == '/raw-ok':\n"
        "            self.send_response(200)\n",
    )

    manip = PythonServicesAdapter().extract(tmp_path, ".", TruthExtractionResult([], {}, {}))
    routes = {(r.http_method, r.full_path) for r in manip.routes}
    assert ("GET", "/status") in routes
    assert ("GET", "/raw-ok") in routes


def test_negative_guards_attribute_post_guard_service_and_sql_lineage(tmp_path: Path) -> None:
    _write(
        tmp_path,
        "schema.sql",
        "CREATE TABLE ops_jobs (id TEXT PRIMARY KEY, max_retries INTEGER);\n",
    )
    _write(
        tmp_path,
        "service_helpers.py",
        "import sqlite3\n\n"
        "def load_jobs():\n"
        "    with sqlite3.connect('ops.db') as conn:\n"
        "        return conn.execute('SELECT id, max_retries FROM ops_jobs').fetchall()\n\n"
        "def save_job():\n"
        "    with sqlite3.connect('ops.db') as conn:\n"
        "        conn.execute(\"INSERT INTO ops_jobs (id, max_retries) VALUES ('j1', 3)\")\n\n"
        "def audit_x():\n"
        "    with sqlite3.connect('ops.db') as conn:\n"
        "        conn.execute(\"UPDATE ops_jobs SET max_retries = 5 WHERE id = 'x'\")\n",
    )
    _write(
        tmp_path,
        "app_daemon.py",
        "from http.server import BaseHTTPRequestHandler\n"
        "from service_helpers import audit_x, load_jobs, save_job\n\n"
        "class GuardedHandler(BaseHTTPRequestHandler):\n"
        "    def do_GET(self):\n"
        "        path = self.path.split('?', 1)[0]\n"
        "        if path not in frozenset({'/a', '/c'}):\n"
        "            self.send_error(404)\n"
        "            return\n"
        "        return load_jobs()\n\n"
        "    def do_POST(self):\n"
        "        path = self.path.split('?', 1)[0]\n"
        "        if not (path == '/b' or path.startswith('/b-items/')):\n"
        "            self.send_error(404)\n"
        "            return\n"
        "        return save_job()\n\n"
        "    def do_PUT(self):\n"
        "        path = self.path.split('?', 1)[0]\n"
        "        if path != '/x':\n"
        "            self.send_error(404)\n"
        "            return\n"
        "        return audit_x()\n",
    )

    truth = SqlDdlTruthAdapter().extract(tmp_path, ".")
    manip = PythonServicesAdapter().extract(tmp_path, ".", truth)

    by_key = {(r.http_method, r.full_path): r for r in manip.routes}
    assert ("GET", "/a") in by_key
    assert ("GET", "/c") in by_key
    assert ("POST", "/b") in by_key
    assert ("POST", "/b-items/{param}") in by_key
    assert ("PUT", "/x") in by_key

    assert "load_jobs" in by_key[("GET", "/a")].called_symbols
    assert "send_error" not in by_key[("GET", "/a")].called_symbols
    assert "load_jobs" in by_key[("GET", "/c")].called_symbols
    assert "save_job" in by_key[("POST", "/b")].called_symbols
    assert "save_job" in by_key[("POST", "/b-items/{param}")].called_symbols
    assert "send_error" not in by_key[("POST", "/b")].called_symbols
    assert "audit_x" in by_key[("PUT", "/x")].called_symbols
    assert "send_error" not in by_key[("PUT", "/x")].called_symbols

    route_to_svc = next(
        e
        for e in manip.edges
        if e.source_id == "m:route:app_daemon.py:GuardedHandler"
        and e.target_id == "m:script:service_helpers.py"
    )
    assert {"GET /a->load_jobs", "POST /b->save_job", "PUT /x->audit_x"} <= set(
        route_to_svc.symbol_links
    )


def test_cross_module_server_subclass_and_1hop_factory_resolution(tmp_path: Path) -> None:
    _write(
        tmp_path,
        "server_factory.py",
        "from http.server import ThreadingHTTPServer as BaseSrv\n\n"
        "class OpsHTTPServer(BaseSrv):\n"
        "    pass\n\n"
        "def make_server(handler_cls, host='127.0.0.1', port=8800):\n"
        "    return OpsHTTPServer((host, port), handler_cls)\n",
    )
    _write(
        tmp_path,
        "daemon_worker.py",
        "from http.server import BaseHTTPRequestHandler\n\n"
        "class WorkerHandler(BaseHTTPRequestHandler):\n"
        "    def do_GET(self):\n"
        "        if self.path == '/health':\n"
        "            self.send_response(200)\n",
    )
    _write(
        tmp_path,
        "runner_cli.py",
        "from daemon_worker import WorkerHandler as ApiHandler\n"
        "from server_factory import make_server\n\n"
        "PORT = 9123\n\n"
        "def main():\n"
        "    return make_server(ApiHandler, port=PORT)\n",
    )

    manip = PythonServicesAdapter().extract(tmp_path, ".", TruthExtractionResult([], {}, {}))
    worker_node = next(n for n in manip.nodes if n.id == "m:route:daemon_worker.py:WorkerHandler")
    assert "OpsHTTPServer(127.0.0.1:9123)" in worker_node.summary

    bind_edge = next(
        e
        for e in manip.edges
        if e.id == "e:httpserver:runner_cli.py:main->m:route:daemon_worker.py:WorkerHandler"
    )
    assert "OpsHTTPServer(127.0.0.1:9123)" in bind_edge.evidence_note
    assert bind_edge.symbol_links == ["main->*"]


def test_full_route_descriptor_coverage_and_25_path_cap_omitted_metadata(tmp_path: Path) -> None:
    branches = "\n".join(
        f"        if path == '/ep-{idx:02d}':\n            return {idx}" for idx in range(32)
    )
    _write(
        tmp_path,
        "many_routes.py",
        "from http.server import BaseHTTPRequestHandler\n\n"
        "class ManyHandler(BaseHTTPRequestHandler):\n"
        "    def do_GET(self):\n"
        "        path = self.path\n"
        f"{branches}\n",
    )

    manip = PythonServicesAdapter().extract(tmp_path, ".", TruthExtractionResult([], {}, {}))
    route_node = next(n for n in manip.nodes if n.id == "m:route:many_routes.py:ManyHandler")
    handler_routes = [r for r in manip.routes if r.node_id == route_node.id]
    assert len(handler_routes) == 32
    assert len(route_node.http_paths) == 25
    assert "32 total paths; 7 omitted beyond 25-path cap" in route_node.summary

    obs = datetime(2026, 11, 20, 12, 0, tzinfo=UTC)
    report = TruthAtlasReport(
        target_slug="daemon-many",
        target_name="Daemon Many",
        repo_path=str(tmp_path),
        stack_profile="python-services",
        coverage_complete=False,
        source_commit="abcdef1234567890",
        worktree_dirty=False,
        dirty_path_count=0,
        observed_at=obs,
        valid_until=obs + timedelta(hours=4),
        observation_source="filesystem_ast",
        content_digest="abcdef1234567890abcdef1234567890",
        scan_notes=[],
        summary=AtlasSummaryStats(
            truth_tables=0,
            sql_functions=0,
            manipulator_routes=1,
            manipulator_services=1,
            display_pages=0,
            display_hooks_and_clients=0,
            verified_edges=1,
            end_to_end_chains=0,
            clean_nodes=1,
            flagged_nodes=0,
            blocking_findings=0,
            warning_findings=0,
        ),
        nodes=[route_node],
        edges=[],
        chains=[],
        findings=[],
        gate=GateEvaluation(verdict="PASS", mode="strict", blocking_violations=0, evaluated_at=obs),
        legacy_bridge=LegacyBridgeSummary(present=False),
    )
    cone = build_lineage_cone_slice(report, route_node.id)
    assert cone.manipulator_nodes[0].omitted_http_path_count == 26
    assert "(+26 omitted)" in cone.markdown


def test_external_display_sources_leaf_demos_never_suppress_daemon_html(tmp_path: Path) -> None:
    repo_leaf = tmp_path / "leaf_demos"
    for prefix in ("examples/web", "demos/portal", "samples/ui", "frontend/examples", "src/samples"):
        _write(repo_leaf, f"{prefix}/App.tsx", "export function App() { return <div />; }\n")
    _write(
        repo_leaf,
        "scripts/app_daemon.py",
        "from http.server import BaseHTTPRequestHandler\n\n"
        "class UiHandler(BaseHTTPRequestHandler):\n"
        "    def do_GET(self):\n"
        "        if self.path == '/':\n"
        "            self.send_header('Content-Type', 'text/html')\n"
        "            return b'<html><body>Root</body></html>'\n",
    )
    assert _has_external_display_sources(repo_leaf) is False
    manip_leaf = PythonServicesAdapter().extract(repo_leaf, ".", TruthExtractionResult([], {}, {}))
    assert any(n.id.startswith("d:page:") for n in manip_leaf.nodes)

    repo_root_html = tmp_path / "apps_with_root_html"
    _write(repo_root_html, "index.html", "<!doctype html><html><body>Ops Portal</body></html>\n")
    for idx in range(10):
        _write(repo_root_html, f"apps/side_app/src/Comp{idx}.tsx", f"export const C{idx} = () => null;\n")
    _write(
        repo_root_html,
        "scripts/app_daemon.py",
        "from http.server import BaseHTTPRequestHandler\n\n"
        "class PortalHandler(BaseHTTPRequestHandler):\n"
        "    def do_GET(self):\n"
        "        if self.path == '/':\n"
        "            self.send_header('Content-Type', 'text/html')\n"
        "            return b'<html><body>Portal</body></html>'\n",
    )
    assert _has_external_display_sources(repo_root_html) is False
    manip_root_html = PythonServicesAdapter().extract(
        repo_root_html, ".", TruthExtractionResult([], {}, {})
    )
    assert any(n.id.startswith("d:page:") for n in manip_root_html.nodes)

    repo_py_heavy = tmp_path / "apps_with_py_services"
    for idx in range(10):
        _write(repo_py_heavy, f"apps/sandbox/src/View{idx}.tsx", f"export const V{idx} = () => null;\n")
    for idx in range(8):
        _write(repo_py_heavy, f"scripts/worker_{idx}.py", f"def run_{idx}():\n    return {idx}\n")
    _write(
        repo_py_heavy,
        "scripts/app_daemon.py",
        "from http.server import BaseHTTPRequestHandler\n\n"
        "class ServiceUiHandler(BaseHTTPRequestHandler):\n"
        "    def do_GET(self):\n"
        "        if self.path == '/status':\n"
        "            self.send_header('Content-Type', 'text/html')\n"
        "            return b'<html><body>Status</body></html>'\n",
    )
    assert _has_external_display_sources(repo_py_heavy) is False
    manip_py = PythonServicesAdapter().extract(repo_py_heavy, ".", TruthExtractionResult([], {}, {}))
    assert any(n.id.startswith("d:page:") for n in manip_py.nodes)

    # Real external frontends without root/daemon HTML or Python dominance still suppress d:page:*
    repo_real_fe = tmp_path / "real_frontend"
    _write(repo_real_fe, "frontend/src/App.tsx", "export function App() { return <main />; }\n")
    assert _has_external_display_sources(repo_real_fe) is True

    repo_real_apps = tmp_path / "real_apps_only"
    for idx in range(10):
        _write(repo_real_apps, f"apps/ops_portal/src/Page{idx}.tsx", f"export const P{idx} = () => null;\n")
    assert _has_external_display_sources(repo_real_apps) is True


def test_symbolic_path_parents_above_root_and_clean_repo_source(tmp_path: Path) -> None:
    def _eval(expr_src: str, owner: str) -> str | None:
        node = ast.parse(expr_src, mode="eval").body
        return symbolic_path(node, {}, owner=owner)

    assert _eval("Path(__file__).resolve().parents[0]", "scripts/install.py") == "scripts"
    assert _eval("Path(__file__).resolve().parents[1]", "scripts/install.py") == "."
    assert (
        _eval("Path(__file__).resolve().parents[2] / '.ops' / 'config.json'", "scripts/install.py")
        == "<repo_parent>/.ops/config.json"
    )
    assert (
        _eval("Path(__file__).resolve().parents[1].parent / '.ops' / 'config.json'", "scripts/install.py")
        == "<repo_parent>/.ops/config.json"
    )
    assert (
        _eval("Path(__file__).resolve().parents[1].parent.parent / 'shared.cfg'", "scripts/install.py")
        == "<repo_parent:2>/shared.cfg"
    )
    assert _eval("Path(__file__).resolve().parents[2]", "scripts/sub/install.py") == "."

    assert _clean_repo_source("./scripts/worker.py") == "scripts/worker.py"
    assert _clean_repo_source("<repo_parent>/.ops/config.json") is None
    assert _clean_repo_source("<repo_parent:2>/shared.cfg") is None
    assert _clean_repo_source(".") is None
    assert _clean_repo_source("../escape.py") is None
    assert _clean_repo_source("/etc/passwd") is None
    assert _clean_repo_source("~/ops.py") is None

    _write(tmp_path, "scripts/worker.py", "def run():\n    return 1\n")
    _write(
        tmp_path,
        "scripts/install.py",
        "from dataclasses import dataclass\n"
        "from pathlib import Path\n\n"
        "REPO_ROOT = Path(__file__).resolve().parents[1]\n\n"
        "@dataclass\n"
        "class File:\n"
        "    repo_path: str\n"
        "    live_path: Path\n\n"
        "FILES = [\n"
        "    File(REPO_ROOT / 'scripts' / 'worker.py', REPO_ROOT.parent / '.ops' / 'config.json'),\n"
        "    File(REPO_ROOT.parent / 'outside.py', Path.home() / '.ops' / 'outside.py'),\n"
        "]\n",
    )

    manip = PythonServicesAdapter().extract(tmp_path, ".", TruthExtractionResult([], {}, {}))
    install_tree = ast.parse((tmp_path / "scripts/install.py").read_text(encoding="utf-8"))

    dep_res = ManipulatorExtractionResult(nodes=[], edges=[], routes=[])
    mappings, refs = deployment_mappings(tmp_path, {"scripts/install.py": install_tree}, dep_res)
    assert mappings == {"<repo_parent>/.ops/config.json": {"scripts/worker.py"}}
    assert len(refs) == 1 and refs[0][1] == "scripts/worker.py"
    assert dep_res.findings == []
    assert any("1 unresolved declarations" in note for note in dep_res.notes)
    assert ("m:script:scripts/install.py", "m:script:scripts/worker.py") in {
        (e.source_id, e.target_id) for e in manip.edges
    }
