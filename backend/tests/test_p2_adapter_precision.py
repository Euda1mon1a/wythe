"""Precision & recall regression tests for Wave W3 P2 adapter improvements."""

from __future__ import annotations

import sqlite3
import subprocess
import sys
from datetime import UTC, datetime, timedelta
from pathlib import Path

import pytest
from sqlalchemy.orm import Session

from app.adapters import typescript_nextjs
from app.adapters.autodetect import detect_repository_stack
from app.adapters.container_launchers import augment_container_launchers
from app.adapters.deployment_sources import symbolic_path
from app.adapters.postgres_sqlalchemy import PostgresSqlAlchemyAdapter
from app.adapters.python_fastapi import PythonFastApiAdapter
from app.adapters.python_policy_consumption import _strip_sql_literals_and_comments
from app.adapters.python_services import PythonServicesAdapter
from app.adapters.sql_ddl_truth import SqlDdlTruthAdapter
from app.adapters.treesitter_engine import has_treesitter
from app.adapters.typescript_react import TypeScriptReactSpaAdapter
from app.schemas.atlas import (
    AtlasEdge,
    AtlasNode,
    AtlasSummaryStats,
    GateEvaluation,
    LegacyBridgeSummary,
    TruthAtlasReport,
)
from app.services.git_diff import materialize_base_tree
from app.services.llm_context_service import build_lineage_cone_slice, build_llms_txt_brief


def _write(root: Path, rel: str, text: str) -> Path:
    p = root / rel
    p.parent.mkdir(parents=True, exist_ok=True)
    p.write_text(text, encoding="utf-8")
    return p


def test_f8_strip_sql_literals_comments_and_nested_subquery_policy_consumption(
    tmp_path: Path,
) -> None:
    raw_sql = (
        "-- max_hours_limit in line comment\n"
        "/* nested /* max_hours_limit */ block comment */\n"
        "SELECT length('max_hours_limit'), 'it''s quota_policies.max_hours_limit', "
        "$$quota_policies.max_hours_limit$$, $tag$max_hours_limit$tag$, \"real_col\", `bt_col`, [br_col] "
        "FROM quota_policies"
    )
    stripped = _strip_sql_literals_and_comments(raw_sql)
    assert "max_hours_limit" not in stripped
    assert '"real_col"' in stripped and "`bt_col`" in stripped and "[br_col]" in stripped

    _write(
        tmp_path,
        "backend/app/models/quota.py",
        "from sqlalchemy import Column, Integer\n"
        "from sqlalchemy.orm import declarative_base\n"
        "Base = declarative_base()\n"
        "class QuotaPolicy(Base):\n"
        "    __tablename__ = 'quota_policies'\n"
        "    id = Column(Integer, primary_key=True)\n"
        "    max_hours_limit = Column(Integer)\n",
    )
    _write(
        tmp_path,
        "backend/app/api/routes/good_scans.py",
        "from fastapi import APIRouter\n"
        "from sqlalchemy import text\n"
        "router = APIRouter()\n\n"
        "@router.get('/api/v1/scans/real-coalesce')\n"
        "def real_coalesce(db):\n"
        "    return db.execute(text(\"SELECT coalesce(max_hours_limit, 0) FROM quota_policies\")).scalar()\n",
    )
    truth = PostgresSqlAlchemyAdapter().extract(tmp_path, "backend")
    manip_good = PythonFastApiAdapter().extract(tmp_path, "backend", truth)
    edge_good = next(
        e
        for e in manip_good.edges
        if e.kind == "reads_truth"
        and e.source_id == "m:route:api.routes.good_scans"
        and e.target_id == "t:quota_policies"
    )
    assert edge_good.policy_field_consumption is not None
    assert edge_good.policy_field_consumption.state == "consumed"

    _write(
        tmp_path,
        "backend/app/api/routes/scans.py",
        "from fastapi import APIRouter\n"
        "from sqlalchemy import text\n"
        "router = APIRouter()\n"
        "MAX_HOURS_LIMIT = 80\n\n"
        "@router.get('/api/v1/scans/only-fake')\n"
        "def only_fake(db):\n"
        "    db.execute(text(\"SELECT length('max_hours_limit'), 'quota_policies.max_hours_limit', (SELECT max_hours_limit FROM other_table) FROM quota_policies\"))\n"
        "    return MAX_HOURS_LIMIT\n",
    )
    truth2 = PostgresSqlAlchemyAdapter().extract(tmp_path, "backend")
    manip_fake = PythonFastApiAdapter().extract(tmp_path, "backend", truth2)
    edge_fake = next(
        e
        for e in manip_fake.edges
        if e.kind == "reads_truth"
        and e.source_id == "m:route:api.routes.scans"
        and e.target_id == "t:quota_policies"
    )
    assert edge_fake.policy_field_consumption is not None
    assert edge_fake.policy_field_consumption.state != "consumed"
    assert any(
        f.rule_code == "MANIP-001" and f.node_id == "m:route:api.routes.scans"
        for f in manip_fake.findings
    )


def test_f14_lazy_getattr_vs_eager_reexport_manip003_wording(tmp_path: Path) -> None:
    _write(tmp_path, "backend/app/__init__.py", "")
    _write(
        tmp_path,
        "backend/app/services/__init__.py",
        "import importlib\n\n"
        "UNRELATED_DICT = {'label': '.not_imported'}\n"
        "_LAZY_EXPORTS = {'LazySvc': '.lazy_svc'}\n\n"
        "def __getattr__(name: str):\n"
        "    if name in _LAZY_EXPORTS:\n"
        "        mod = importlib.import_module(_LAZY_EXPORTS[name], __name__)\n"
        "        return getattr(mod, name)\n"
        "    raise AttributeError(name)\n",
    )
    _write(tmp_path, "backend/app/services/lazy_svc.py", "class LazySvc:\n    pass\n")
    _write(tmp_path, "backend/app/services/not_imported.py", "class NotImported:\n    pass\n")
    _write(tmp_path, "backend/app/eager_pkg/__init__.py", "from .eager_svc import EagerSvc\n")
    _write(tmp_path, "backend/app/eager_pkg/eager_svc.py", "class EagerSvc:\n    pass\n")

    proc = subprocess.run(
        [sys.executable, "-B", "-c", "import sys; sys.path.insert(0, '.'); import app.services"],
        cwd=str(tmp_path / "backend"),
        capture_output=True,
        text=True,
        check=False,
    )
    assert proc.returncode == 0

    truth = PostgresSqlAlchemyAdapter().extract(tmp_path, "backend")
    res = PythonFastApiAdapter().extract(tmp_path, "backend", truth)
    by_node = {f.node_id: f for f in res.findings if f.rule_code == "MANIP-003"}

    lazy_f = by_node["m:service:services.lazy_svc"]
    assert "import app.services" in lazy_f.detail and "succeeds" in lazy_f.detail
    assert "lazily exported attribute" in lazy_f.detail
    assert "lazy `__getattr__` export" in lazy_f.remediation

    unrelated_f = by_node["m:service:services.not_imported"]
    assert "lazy `__getattr__`" not in unrelated_f.detail

    eager_f = by_node["m:service:eager_pkg.eager_svc"]
    assert "Passively re-exported by `backend/app/eager_pkg/__init__.py:1`" in eager_f.detail
    assert "will raise `ImportError`/`ModuleNotFoundError` when importing the package" in eager_f.detail


def test_98_autodetect_python_services_over_tiny_leaf_demo_and_manip_findings(
    tmp_path: Path, db_session: Session
) -> None:
    _write(tmp_path, "schema.sql", "CREATE TABLE quota_policies (id INT, max_hours_limit INT);\n")
    _write(
        tmp_path,
        "scripts/daemon_a.py",
        "import datetime\n"
        "import sqlite3\n"
        "from http.server import BaseHTTPRequestHandler, HTTPServer\n\n"
        "MAX_HOURS_LIMIT = 72\n\n"
        "class UiHandler(BaseHTTPRequestHandler):\n"
        "    def do_GET(self):\n"
        "        if self.path == '/':\n"
        "            self.send_Header('Content-Type', 'text/html')\n"
        "            return b'<html><body>Hi</body></html>'\n"
        "        now = datetime.datetime.now()\n"
        "        conn = sqlite3.connect('app.db')\n"
        "        conn.execute('SELECT id FROM quota_policies')\n"
        "        return now, MAX_HOURS_LIMIT\n\n"
        "def serve():\n"
        "    HTTPServer(('127.0.0.1', 8080), UiHandler)\n",
    )
    for idx in range(5):
        _write(tmp_path, f"scripts/worker_{idx}.py", f"def job_{idx}():\n    return {idx}\n")
    _write(
        tmp_path,
        "apps/web/demo/package.json",
        '{"name": "demo", "dependencies": {"react": "^18.0.0"}, "devDependencies": {"vite": "^5.0.0"}}',
    )
    _write(tmp_path, "apps/web/demo/src/App.tsx", "export function App() { return <div>Demo</div>; }\n")

    det = detect_repository_stack(db_session, str(tmp_path))
    assert det.recommended_profile_slug != "frontend-only-react"
    assert det.manipulator_adapter == "python-services"

    truth = SqlDdlTruthAdapter().extract(tmp_path, ".")
    manip = PythonServicesAdapter().extract(tmp_path, ".", truth)
    augment_container_launchers(tmp_path, ".", manip)
    node_ids = {n.id for n in manip.nodes}
    assert any(nid.startswith("d:page:") for nid in node_ids)
    rule_codes = {f.rule_code for f in manip.findings}
    assert "MANIP-001" in rule_codes
    assert "MANIP-002" in rule_codes


def test_96_101_daemon_routes_symbolic_parent_and_cap_counts(tmp_path: Path) -> None:
    import ast

    expr = ast.parse("Path(__file__).resolve().parent.parent / 'worker.py'", mode="eval").body
    res_sym = symbolic_path(expr, {}, owner="scripts/sub/runner.py")
    assert res_sym == "scripts/worker.py"

    many_branches = "\n".join(
        f"        if p == '/api/item-{i}':\n            return {i}" for i in range(30)
    )
    _write(
        tmp_path,
        "server_base.py",
        "from http.server import ThreadingHTTPServer\n"
        "class CustomDaemonServer(ThreadingHTTPServer):\n"
        "    pass\n",
    )
    _write(
        tmp_path,
        "daemon_http.py",
        "from http.server import BaseHTTPRequestHandler\n"
        "from urllib.parse import urlparse\n"
        "from server_base import CustomDaemonServer\n\n"
        "ALLOWED = {'/guard-a', '/guard-b'}\n\n"
        "class GuardHandler(BaseHTTPRequestHandler):\n"
        "    def _norm_path(self):\n"
        "        return urlparse(self.path).path.rstrip('/') or '/'\n\n"
        "    def do_GET(self):\n"
        "        p = self._norm_path()\n"
        "        if p not in ALLOWED:\n"
        "            return\n"
        "        return 200\n\n"
        "    def do_POST(self):\n"
        "        p = self._norm_path()\n"
        "        if p != '/only-post':\n"
        "            return\n"
        f"{many_branches}\n\n"
        "def run_srv():\n"
        "    CustomDaemonServer(('127.0.0.1', 9090), GuardHandler)\n",
    )
    _write(
        tmp_path,
        "fastapi_daemon.py",
        "from fastapi import APIRouter, FastAPI\n"
        "API_PREFIX = '/api/v2'\n"
        "router = APIRouter(prefix='/jobs')\n\n"
        "@router.get('/status')\n"
        "def job_status():\n"
        "    return {'ok': True}\n\n"
        "def create_app():\n"
        "    app = FastAPI()\n"
        "    app.include_router(router, prefix=API_PREFIX)\n"
        "    @app.post(API_PREFIX + '/trigger')\n"
        "    def trigger_job():\n"
        "        return {'started': True}\n"
        "    return app\n",
    )
    truth = SqlDdlTruthAdapter().extract(tmp_path, ".")
    manip = PythonServicesAdapter().extract(tmp_path, ".", truth)
    augment_container_launchers(tmp_path, ".", manip)
    routes = {(r.http_method, r.full_path) for r in manip.routes}
    assert ("GET", "/guard-a") in routes and ("GET", "/guard-b") in routes
    assert ("POST", "/only-post") in routes
    assert ("GET", "/api/v2/jobs/status") in routes
    assert ("POST", "/api/v2/trigger") in routes

    gh_node = next(n for n in manip.nodes if n.id == "m:route:daemon_http.py:GuardHandler")
    assert "33 total paths; 8 omitted beyond 25-path cap" in gh_node.summary
    assert "CustomDaemonServer(127.0.0.1:9090)" in gh_node.summary


@pytest.mark.parametrize("disable_ts", [False, True])
def test_96_101_frontend_mount_prefix_eventsource_dirs_and_a11y(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, disable_ts: bool
) -> None:
    assert has_treesitter() is True
    if disable_ts:
        monkeypatch.setenv("WYTHE_DISABLE_TREESITTER", "1")
        monkeypatch.setattr(typescript_nextjs, "extract_ts_http_calls_cst", lambda *a, **kw: None)
    else:
        monkeypatch.delenv("WYTHE_DISABLE_TREESITTER", raising=False)

    _write(
        tmp_path,
        "frontend/index.html",
        "<!doctype html><html><body>\n"
        "<img src='/banner.png'>\n"
        "<script type='module'>\n"
        "  const es = new EventSource(`${window.API_BASE}/api/events`);\n"
        "</script></body></html>\n",
    )
    _write(
        tmp_path,
        "frontend/src/core/orders-client.ts",
        "export class OrdersClient {\n"
        "  baseUrl = '';\n"
        "  async list() {\n"
        "    return fetch(`${this.baseUrl}/api/orders`);\n"
        "  }\n"
        "}\n",
    )
    _write(
        tmp_path,
        "frontend/src/utils/stream_api.mjs",
        "export function watchStream() {\n"
        "  const tpl = `<button><svg></svg></button>`;\n"
        "  const s = new EventSource('/api/stream');\n"
        "  return [tpl, s, fetch(`${API_ROOT}/health`)];\n"
        "}\n",
    )
    _write(
        tmp_path,
        "frontend/src/shared/ext_guard.ts",
        "const EXT = 'https://external.example';\n"
        "export const runExt = () => fetch(`${EXT}/api/should-not-match`);\n"
        "export const runParam = (params: { probe: { baseUrl: string } }) =>\n"
        "  fetch(`${params.probe.baseUrl}/chat/completions`, { method: 'POST' });\n",
    )
    res = TypeScriptReactSpaAdapter().extract(tmp_path, "frontend")
    calls = {(c.http_method, c.normalized_path) for c in res.http_calls}
    assert ("GET", "/api/events") in calls
    assert ("GET", "/api/orders") in calls
    assert ("GET", "/api/stream") in calls
    assert ("GET", "/health") in calls
    assert not any("should-not-match" in p or "completions" in p for _m, p in calls)

    a11y_files = {f.source_file for f in res.findings if f.rule_code == "DISP-005"}
    assert "frontend/index.html" in a11y_files
    assert "frontend/src/utils/stream_api.mjs" in a11y_files


def test_100_sql_ddl_truth005_live_catalog_and_unmapped_python_sql(tmp_path: Path) -> None:
    _write(tmp_path, "schema.sql", "CREATE TABLE known_items (id INTEGER PRIMARY KEY);\n")
    db_file = tmp_path / "live.sqlite"
    conn = sqlite3.connect(str(db_file))
    conn.execute("CREATE TABLE known_items (id INTEGER PRIMARY KEY)")
    conn.execute("CREATE TABLE shadow_runtime_tbl (id INTEGER PRIMARY KEY, note TEXT)")
    conn.execute("CREATE TABLE alembic_version (version_num TEXT)")
    conn.commit()
    conn.close()

    truth = SqlDdlTruthAdapter().extract(tmp_path, ".", pg_dsn=f"sqlite:///{db_file}")
    t_ids = {n.id for n in truth.nodes}
    assert "t:live:shadow_runtime_tbl" in t_ids
    assert "t:live:alembic_version" not in t_ids
    t005 = [f for f in truth.findings if f.rule_code == "TRUTH-005"]
    assert len(t005) == 1 and t005[0].node_id == "t:live:shadow_runtime_tbl"

    _write(
        tmp_path,
        "worker.py",
        "import sqlite3\n"
        "def sync_data():\n"
        "    c = sqlite3.connect('x.db')\n"
        "    c.execute('SELECT id FROM mystery_source')\n"
        "    c.execute('INSERT INTO mystery_sink (id) VALUES (1)')\n",
    )
    truth_static = SqlDdlTruthAdapter().extract(tmp_path, ".")
    manip = PythonServicesAdapter().extract(tmp_path, ".", truth_static)
    t_after = {n.id for n in truth_static.nodes}
    assert "t:unmapped:mystery_source" in t_after
    assert "t:unmapped:mystery_sink" in t_after
    unmapped_edges = [
        (e.kind, e.target_id, e.verification)
        for e in manip.edges
        if e.target_id.startswith("t:unmapped:")
    ]
    assert ("reads_truth", "t:unmapped:mystery_source", "unverified") in unmapped_edges
    assert ("writes_truth", "t:unmapped:mystery_sink", "unverified") in unmapped_edges


def test_97_yaml_registries_systemd_suffix_and_llm_freshness_markers(tmp_path: Path) -> None:
    _write(
        tmp_path,
        "config/seats.yaml",
        "seats:\n"
        "  fast:\n"
        "    provider: local\n"
        "    timeout_seconds: 30\n"
        "    enabled: true\n"
        "models:\n"
        "  - qwen\n",
    )
    # Excluded meta / lock / compose / workflow files under config/
    _write(tmp_path, "config/pnpm-lock.yaml", "lockfileVersion: '9.0'\npackages: {}\n")
    _write(
        tmp_path,
        "config/docker-compose.yml",
        "services:\n  db:\n    image: postgres:16\n",
    )
    _write(
        tmp_path,
        "config/ci.workflow.yml",
        "jobs:\n  build:\n    runs-on: ubuntu-latest\n    steps: []\n",
    )
    _write(
        tmp_path,
        "config/seats.schema.yaml",
        "$schema: https://json-schema.org/draft/2020-12/schema\ntype: object\nproperties:\n  seats:\n    type: object\n",
    )
    _write(
        tmp_path,
        "scripts/seat_router.py",
        "from pathlib import Path\n"
        "import yaml\n\n"
        "def load_seat_timeout():\n"
        "    cfg = yaml.safe_load(Path('config/seats.yaml').read_text())\n"
        "    return cfg['seats']['fast']['timeout_seconds']\n",
    )
    _write(tmp_path, "scripts/worker.py", "def run_worker():\n    return 1\n")
    _write(tmp_path, "scripts/sub/run.py", "def main():\n    return 2\n")
    _write(
        tmp_path,
        "deploy/worker.service",
        "[Unit]\nDescription=Worker\n[Service]\n"
        "ExecStartPre=/home/u/repo/scripts/sub/run.py\n"
        "ExecStart=/opt/app/bin/worker.py\n",
    )

    truth = SqlDdlTruthAdapter().extract(tmp_path, ".")
    manip = PythonServicesAdapter().extract(tmp_path, ".", truth)
    augment_container_launchers(tmp_path, ".", manip)
    reg_ids = {n.id for n in truth.nodes if n.id.startswith("t:registry:")}
    assert reg_ids == {"t:registry:config/seats.yaml"}
    reg_edge = next(
        e for e in manip.edges if e.kind == "reads_truth" and e.target_id == "t:registry:config/seats.yaml"
    )
    assert reg_edge.policy_field_consumption is not None
    assert reg_edge.policy_field_consumption.state == "consumed"

    sys_edges = {
        e.target_id: e.evidence_note
        for e in manip.edges
        if e.source_id == "m:systemd:deploy/worker.service"
    }
    assert "m:script:scripts/worker.py" in sys_edges
    assert "m:script:scripts/sub/run.py" in sys_edges
    assert "host_install_path_unverified" in sys_edges["m:script:scripts/worker.py"]
    assert "host_install_path_unverified" in sys_edges["m:script:scripts/sub/run.py"]

    obs = datetime(2026, 11, 19, 12, 0, tzinfo=UTC)
    val = obs + timedelta(hours=4)
    route_node = AtlasNode(
        id="m:route:srv",
        tier="manipulate",
        subkind="route",
        label="srv",
        source_file="srv.py",
        line=1,
        summary="Daemon route surface `srv` (GET /a) (30 total paths; 5 omitted beyond 25-path cap).",
        http_methods=["GET"],
        http_paths=[f"/p{i}" for i in range(25)],
    )
    rep = TruthAtlasReport(
        target_slug="svc-demo",
        target_name="Svc Demo",
        repo_path=str(tmp_path),
        stack_profile="python-services",
        coverage_complete=False,
        source_commit="abcdef1234567890",
        worktree_dirty=False,
        dirty_path_count=0,
        observed_at=obs,
        valid_until=val,
        observation_source="filesystem_ast",
        content_digest="1234567890abcdef1234567890abcdef",
        scan_notes=["Python service profile does not inspect UI or HTTP routing; display tier is empty."],
        summary=AtlasSummaryStats(
            truth_tables=0,
            sql_functions=0,
            manipulator_routes=1,
            manipulator_services=0,
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
        edges=[
            AtlasEdge(
                id="e1",
                source_id="m:route:srv",
                target_id="m:route:srv",
                kind="calls_helper",
                verification="verified",
                evidence_note="self",
            )
        ],
        chains=[],
        findings=[],
        gate=GateEvaluation(
            verdict="PASS", mode="strict", blocking_violations=0, evaluated_at=obs
        ),
        legacy_bridge=LegacyBridgeSummary(present=False),
    )
    brief = build_llms_txt_brief(rep)
    assert rep.observed_at == obs
    assert brief.observed_at == obs and brief.valid_until == val
    assert brief.observation_source == "filesystem_ast"
    assert brief.coverage_complete is False
    assert "display" in brief.unobserved_tiers
    assert "unobserved (no-display)" in brief.markdown

    cone = build_lineage_cone_slice(rep, "m:route:srv")
    assert rep.observed_at == obs
    assert cone.observed_at == obs and "display" in cone.unobserved_tiers
    assert "unobserved (no-display)" in cone.markdown
    assert cone.manipulator_nodes[0].omitted_http_path_count == 24


def test_99_git_diff_materialize_base_tree_intra_repo_symlinks_and_fail_closed(
    tmp_path: Path,
) -> None:
    repo = tmp_path / "repo"
    repo.mkdir()
    subprocess.run(["git", "init"], cwd=repo, check=True, capture_output=True)
    subprocess.run(["git", "config", "user.email", "t@example.com"], cwd=repo, check=True)
    subprocess.run(["git", "config", "user.name", "T"], cwd=repo, check=True)

    _write(repo, "shared/policy.sql", "CREATE TABLE items (id INT);\n")
    (repo / "sub").mkdir()
    (repo / "sub" / "linked.sql").symlink_to("../shared/policy.sql")
    subprocess.run(["git", "add", "."], cwd=repo, check=True)
    subprocess.run(["git", "commit", "-m", "ok symlinks"], cwd=repo, check=True, capture_output=True)

    dest = tmp_path / "out_ok"
    dest.mkdir()
    materialize_base_tree(repo, "HEAD", dest)
    assert (dest / "sub" / "linked.sql").is_file()
    assert not (dest / "sub" / "linked.sql").is_symlink()
    assert "CREATE TABLE items" in (dest / "sub" / "linked.sql").read_text(encoding="utf-8")

    (repo / "sub" / "dangling.sql").symlink_to("../shared/untracked.sql")
    subprocess.run(["git", "add", "sub/dangling.sql"], cwd=repo, check=True)
    subprocess.run(["git", "commit", "-m", "dangling symlink"], cwd=repo, check=True, capture_output=True)
    dest_dangling = tmp_path / "out_dangling"
    dest_dangling.mkdir()
    with pytest.raises(ValueError, match="symlink"):
        materialize_base_tree(repo, "HEAD", dest_dangling)

    (repo / "sub" / "dangling.sql").unlink()
    (repo / "escape.sql").symlink_to("../../etc/passwd")
    subprocess.run(["git", "add", "-A"], cwd=repo, check=True)
    subprocess.run(["git", "commit", "-m", "escape symlink"], cwd=repo, check=True, capture_output=True)

    dest_bad = tmp_path / "out_bad"
    dest_bad.mkdir()
    with pytest.raises(ValueError, match="symlink"):
        materialize_base_tree(repo, "HEAD", dest_bad)


def test_ts_fallback_blocks_param_mount_with_object_return_type(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Pure-Python TS fallback must block parameter-rooted URL prefixes even with `{...}` types."""
    from app.adapters import typescript_nextjs as ts_next

    monkeypatch.setattr(ts_next, "extract_ts_http_calls_cst", lambda *a, **kw: None)
    sample = (
        "export async function runAsk(params: {\n"
        "  probe: { baseUrl: string };\n"
        "  history?: Array<{ role: 'user' | 'assistant'; content: string }>;\n"
        "}): Promise<{ answerMarkdown: string; usedVision: boolean }> {\n"
        "  const res = await fetch(`${params.probe.baseUrl}/chat/completions`, { method: 'POST' });\n"
        "  return { answerMarkdown: await res.text(), usedVision: false };\n"
        "}\n"
    )
    assert ts_next._extract_ts_http_calls(ts_next._strip_ts_comments(sample)) == []
