"""Wave 1 Slice A tests: polyglot autodetect (#90) and inline stores, stdlib HTTP/MCP & registries (#91)."""

from __future__ import annotations

import json
from pathlib import Path

from sqlalchemy import select
from sqlalchemy.orm import Session

from app.adapters.autodetect import detect_repository_stack
from app.adapters.python_services import PythonServicesAdapter
from app.adapters.sql_ddl_truth import SqlDdlTruthAdapter
from app.models import StackProfile, TargetProject
from app.services.llm_context_service import build_lineage_cone_slice
from app.services.scanner_service import run_target_scan


def _put(root: Path, rel: str, content: str) -> Path:
    dest = root / rel
    dest.parent.mkdir(parents=True, exist_ok=True)
    dest.write_text(content, encoding="utf-8")
    return dest


def test_seed_profiles_include_polyglot_python_services_react_and_nextjs(
    db_session: Session,
) -> None:
    profiles = {
        p.slug: p for p in db_session.scalars(select(StackProfile)).all()
    }
    assert "python-services-react" in profiles
    assert "python-services-nextjs" in profiles

    react_prof = profiles["python-services-react"]
    assert react_prof.is_enabled is True
    assert react_prof.truth_adapter == "sql-ddl"
    assert react_prof.manipulator_adapter == "python-services"
    assert react_prof.display_adapter == "typescript-react"

    next_prof = profiles["python-services-nextjs"]
    assert next_prof.is_enabled is True
    assert next_prof.truth_adapter == "sql-ddl"
    assert next_prof.manipulator_adapter == "python-services"
    assert next_prof.display_adapter == "typescript-nextjs"


def test_polyglot_nested_apps_web_subapp_resolves_python_services_react_with_telemetry(
    db_session: Session, tmp_path: Path
) -> None:
    repo = tmp_path / "polyglot_ops"
    # Root tooling package.json without Node backend deps must NOT suppress Python services
    _put(
        repo,
        "package.json",
        json.dumps({"private": True, "workspaces": ["apps/web/*"], "devDependencies": {"prettier": "3.2.0"}}),
    )
    _put(
        repo,
        "scripts/gateway_daemon.py",
        "import sqlite3\ndef run_daemon():\n    conn = sqlite3.connect('metrics.db')\n    return conn\n",
    )
    _put(repo, "src/helper_service.py", "def compute_summary():\n    return {'ok': True}\n")
    # Note: apps/web itself has NO package.json; nested sub-app lives at apps/web/demo-ui/package.json
    _put(
        repo,
        "apps/web/demo-ui/package.json",
        json.dumps({"name": "demo-ui", "dependencies": {"react": "18.3.0", "react-dom": "18.3.0"}, "devDependencies": {"vite": "5.4.0"}}),
    )
    _put(repo, "apps/web/demo-ui/vite.config.ts", "export default {};\n")
    _put(
        repo,
        "apps/web/demo-ui/src/App.tsx",
        "export function App() { void fetch('/api/metrics'); return <main><h1>Metrics</h1></main>; }\n",
    )

    det = detect_repository_stack(db_session, str(repo))
    assert det.manipulator_adapter == "python-services"
    assert det.backend_subdir == "."
    assert det.truth_adapter == "sql-ddl"
    assert det.display_adapter == "typescript-react"
    assert det.frontend_subdir == "apps/web/demo-ui"
    assert det.recommended_profile_slug == "python-services-react"
    assert det.coverage_complete is True
    assert det.confidence == "high"
    assert (
        "Subtrees: backend='.' (python-services), frontend='apps/web/demo-ui' (typescript-react)"
        in det.detected_signals
    )


def test_polyglot_examples_nextjs_multi_web_and_framework_preservation(
    db_session: Session, tmp_path: Path
) -> None:
    # 1. Nested Next.js under apps/* + root/src Python daemon -> python-services-nextjs
    next_repo = tmp_path / "polyglot_next"
    _put(next_repo, "schema.sql", "CREATE TABLE jobs (id TEXT PRIMARY KEY, state TEXT);\n")
    _put(
        next_repo,
        "src/job_daemon.py",
        "from http.server import HTTPServer\ndef poll_jobs():\n    return []\n",
    )
    _put(
        next_repo,
        "apps/portal-ui/package.json",
        json.dumps({"dependencies": {"next": "15.0.0", "react": "18.3.0"}}),
    )
    _put(
        next_repo,
        "apps/portal-ui/src/app/page.tsx",
        "export default function Page() { return <main>Portal</main>; }\n",
    )
    det_next = detect_repository_stack(db_session, str(next_repo))
    assert det_next.recommended_profile_slug == "python-services-nextjs"
    assert det_next.backend_subdir == "."
    assert det_next.frontend_subdir == "apps/portal-ui"
    assert det_next.display_adapter == "typescript-nextjs"
    assert det_next.manipulator_adapter == "python-services"

    # 2. Multi-subapp under apps/web/* (two React SPAs, no apps/web/package.json) -> frontend_subdir='apps/web'
    multi_repo = tmp_path / "polyglot_multi"
    _put(multi_repo, "scripts/supervisor.py", "import sqlite3\nconn = sqlite3.connect('ops.db')\n")
    _put(multi_repo, "apps/web/surf-one/package.json", json.dumps({"dependencies": {"react": "18.3.0"}}))
    _put(multi_repo, "apps/web/surf-one/src/App.tsx", "export function App() { return <main>One</main>; }\n")
    _put(multi_repo, "apps/web/surf-two/package.json", json.dumps({"dependencies": {"react": "18.3.0"}}))
    _put(multi_repo, "apps/web/surf-two/src/App.tsx", "export function App() { return <main>Two</main>; }\n")
    det_multi = detect_repository_stack(db_session, str(multi_repo))
    assert det_multi.recommended_profile_slug == "python-services-react"
    assert det_multi.frontend_subdir == "apps/web"

    # 3. Preservation: Go + scripts/helper.py still selects go-http, NOT python-services
    go_repo = tmp_path / "go_with_script"
    _put(go_repo, "go.mod", "module example.com/demo\ngo 1.22\n")
    _put(go_repo, "scripts/helper.py", "print('codegen')\n")
    _put(go_repo, "web/package.json", json.dumps({"dependencies": {"react": "18.3.0"}}))
    det_go = detect_repository_stack(db_session, str(go_repo))
    assert det_go.manipulator_adapter == "go-http"
    assert det_go.recommended_profile_slug == "postgres-go-react"


def test_inline_sqlite_postgres_jsonl_and_cross_engine_collision_disambiguation(
    tmp_path: Path,
) -> None:
    # 1. Single-engine standalone .sql keeps `t:<table>` backward compatibility
    pure_sql = tmp_path / "pure_sql"
    _put(pure_sql, "schema.sql", "CREATE TABLE customers (id INTEGER PRIMARY KEY, email TEXT);\n")
    pure_res = SqlDdlTruthAdapter().extract(pure_sql, ".")
    assert {n.id for n in pure_res.nodes} == {"t:customers"}
    assert pure_res.table_symbol_map["customers"] == "t:customers"

    # 2. Mixed standalone .sql + inline SQLite + inline Postgres + JSONL with colliding `events` & `policy`
    repo = tmp_path / "mixed_stores"
    _put(
        repo,
        "sql/schema.sql",
        "CREATE TABLE nodes (id TEXT PRIMARY KEY, role TEXT);\n"
        "CREATE TABLE events (id UUID PRIMARY KEY, payload JSONB);\n",
    )
    _put(
        repo,
        "scripts/metrics_daemon.py",
        """\
import sqlite3
from pathlib import Path

DB_FILE = Path("state") / "metrics.db"

def init_db():
    conn = sqlite3.connect(DB_FILE)
    conn.execute(
        \"\"\"
        CREATE TABLE IF NOT EXISTS events (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            ts TEXT NOT NULL,
            kind TEXT NOT NULL
        )
        \"\"\"
    )
    conn.execute(
        "CREATE TABLE IF NOT EXISTS rollups (bucket TEXT PRIMARY KEY, max_quota INTEGER)"
    )
    return conn

def read_sqlite_events(conn):
    return conn.execute("SELECT id, kind FROM events").fetchall()
""",
    )
    _put(
        repo,
        "scripts/pg_worker.py",
        """\
import psycopg

def bootstrap_pg(dsn: str):
    with psycopg.connect(dsn) as conn:
        conn.execute("CREATE TABLE IF NOT EXISTS ops.leases (holder TEXT PRIMARY KEY, expires_at TIMESTAMPTZ)")
        conn.execute("CREATE TABLE IF NOT EXISTS policy (name TEXT PRIMARY KEY, max_capacity INTEGER)")
        conn.execute("INSERT INTO events (id, payload) VALUES (%s, %s)", ("1", "{}"))
        conn.execute("SELECT max_capacity FROM policy")
""",
    )
    _put(
        repo,
        "scripts/local_cache.py",
        """\
import sqlite3

def sync_local_policy():
    conn = sqlite3.connect("cache.sqlite3")
    conn.execute("CREATE TABLE IF NOT EXISTS policy (name TEXT PRIMARY KEY, ttl_seconds INTEGER)")
    return conn.execute("SELECT ttl_seconds FROM policy").fetchall()
""",
    )
    _put(
        repo,
        "scripts/ledger.py",
        """\
from pathlib import Path

LEDGER_PATH = Path("var") / "ops_ledger.jsonl"

def append_entry(line: str) -> None:
    with open(LEDGER_PATH, "a", encoding="utf-8") as fh:
        fh.write(line + "\\n")

def read_entries() -> str:
    return LEDGER_PATH.read_text(encoding="utf-8")
""",
    )

    truth = SqlDdlTruthAdapter().extract(repo, ".")
    node_ids = {n.id for n in truth.nodes}
    assert "t:nodes" in node_ids  # Non-colliding standalone .sql stays t:<table>
    assert "t:postgres:public.events" in node_ids
    assert "t:sqlite:metrics:events" in node_ids
    assert "t:sqlite:metrics:rollups" in node_ids
    assert "t:postgres:ops.leases" in node_ids
    assert "t:postgres:public.policy" in node_ids
    assert "t:sqlite:cache:policy" in node_ids
    assert "t:jsonl:ops_ledger" in node_ids

    # Unambiguous bare names resolve; colliding bare names (`events`, `policy`) never overwrite
    assert truth.table_symbol_map["nodes"] == "t:nodes"
    assert truth.table_symbol_map["rollups"] == "t:sqlite:metrics:rollups"
    assert truth.table_symbol_map["leases"] == "t:postgres:ops.leases"
    assert truth.table_symbol_map["ops_ledger"] == "t:jsonl:ops_ledger"
    assert "events" not in truth.table_symbol_map
    assert "policy" not in truth.table_symbol_map
    assert any("Disambiguated colliding bare store names" in n for n in truth.notes)

    manip = PythonServicesAdapter().extract(repo, ".", truth)
    edge_set = {(e.source_id, e.kind, e.target_id) for e in manip.edges}
    assert ("m:script:scripts/metrics_daemon.py", "reads_truth", "t:sqlite:metrics:events") in edge_set
    assert ("m:script:scripts/pg_worker.py", "writes_truth", "t:postgres:public.events") in edge_set
    assert ("m:script:scripts/pg_worker.py", "reads_truth", "t:postgres:public.policy") in edge_set
    assert ("m:script:scripts/local_cache.py", "reads_truth", "t:sqlite:cache:policy") in edge_set
    assert ("m:script:scripts/ledger.py", "writes_truth", "t:jsonl:ops_ledger") in edge_set
    assert ("m:script:scripts/ledger.py", "reads_truth", "t:jsonl:ops_ledger") in edge_set

    tnodes = {n.id: n for n in truth.nodes}
    assert tnodes["t:sqlite:metrics:events"].read_by_count == 1
    assert tnodes["t:postgres:public.events"].written_by_count == 1
    assert tnodes["t:jsonl:ops_ledger"].read_by_count == 1
    assert tnodes["t:jsonl:ops_ledger"].written_by_count == 1


def test_stdlib_http_mcp_tools_subprocess_sql_wrappers_and_3tier_chains(
    db_session: Session, tmp_path: Path
) -> None:
    repo = tmp_path / "daemon_stack"
    _put(
        repo,
        "scripts/sql_helper.py",
        """\
import sqlite3

def query_rows(sql: str):
    with sqlite3.connect("metrics.db") as conn:
        return conn.execute(sql).fetchall()
""",
    )
    _put(repo, "scripts/sync_task.py", "def main():\n    return 0\n\nif __name__ == '__main__':\n    main()\n")
    _put(repo, "scripts/cleanup.sh", "#!/bin/sh\necho ok\n")
    _put(
        repo,
        "scripts/gateway_daemon.py",
        """\
import sqlite3
import subprocess
import sys
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import urlparse
from scripts.sql_helper import query_rows

PORT = 8765

def init_store():
    with sqlite3.connect("metrics.db") as conn:
        conn.execute(
            "CREATE TABLE IF NOT EXISTS surf_metrics (id TEXT PRIMARY KEY, max_threshold INTEGER)"
        )

def load_metrics():
    return query_rows("SELECT id, max_threshold FROM surf_metrics")

def record_metric(item_id: str):
    query_rows(f"INSERT OR REPLACE INTO surf_metrics (id, max_threshold) VALUES ('{item_id}', 10)")
    subprocess.run([sys.executable, "scripts/sync_task.py"], check=True)

def purge_metrics():
    subprocess.check_call(["/bin/sh", "scripts/cleanup.sh"])
    query_rows("DELETE FROM surf_metrics WHERE id = 'old'")

class GatewayHandler(BaseHTTPRequestHandler):
    def do_GET(self):
        clean_path = urlparse(self.path).path
        if clean_path == "/api/metrics":
            _ = load_metrics()
        elif clean_path == "/ui":
            self.send_header("Content-Type", "text/html")

    def do_POST(self):
        if self.path.startswith("/api/metrics/"):
            record_metric("demo")

    def do_PUT(self):
        if self.path == "/api/metrics/config":
            record_metric("cfg")

    def do_DELETE(self):
        if self.path == "/api/metrics/old":
            purge_metrics()

def serve():
    server = ThreadingHTTPServer(("127.0.0.1", PORT), GatewayHandler)
    return server
""",
    )
    _put(
        repo,
        "scripts/mcp_daemon.py",
        """\
import subprocess
from mcp.server import FastMCP, Server

mcp = FastMCP("surf_demo")
low_server = Server("surf_low")

@mcp.tool()
def inspect_surface() -> dict:
    out = subprocess.check_output(["python3", "scripts/sync_task.py"])
    return {"bytes": len(out)}

@low_server.list_tools()
async def list_tools():
    return [{"name": "trigger_cleanup", "description": "Run cleanup"}]

@low_server.call_tool()
async def call_tool(name: str, arguments: dict):
    if name == "trigger_cleanup":
        proc = subprocess.Popen(["/bin/sh", "scripts/cleanup.sh"])
        proc.wait()
    return []
""",
    )
    _put(
        repo,
        "apps/web/surf-demo/package.json",
        json.dumps({"dependencies": {"react": "18.3.0"}}),
    )
    _put(
        repo,
        "apps/web/surf-demo/src/App.tsx",
        """\
export function App() {
  void fetch('/api/metrics');
  void fetch('/api/metrics/item-1', { method: 'POST' });
  return <main><h1>Surface Demo</h1></main>;
}
""",
    )

    det = detect_repository_stack(db_session, str(repo))
    assert det.recommended_profile_slug == "python-services-react"
    target = TargetProject(
        id=0,
        slug="daemon-stack",
        name="Daemon Stack",
        repo_path=str(repo),
        stack_profile_slug=det.recommended_profile_slug,
        backend_subdir=det.backend_subdir,
        frontend_subdir=det.frontend_subdir,
        description="Polyglot stdlib HTTP + MCP + React",
        is_active=True,
    )
    report = run_target_scan(db_session, target, strict_gate=True, persist_snapshot=False)
    nodes_by_id = {n.id: n for n in report.nodes}

    gw_route_id = "m:route:scripts/gateway_daemon.py:GatewayHandler"
    mcp_route_id = "m:route:scripts/mcp_daemon.py:mcp"
    assert gw_route_id in nodes_by_id
    assert mcp_route_id in nodes_by_id
    gw_node = nodes_by_id[gw_route_id]
    assert set(gw_node.http_methods) == {"GET", "POST", "PUT", "DELETE"}
    assert "/api/metrics" in gw_node.http_paths
    assert "/api/metrics/{param}" in gw_node.http_paths
    assert "ThreadingHTTPServer(127.0.0.1:8765)" in gw_node.summary
    assert "Serves HTML view" in gw_node.summary

    mcp_node = nodes_by_id[mcp_route_id]
    assert "/mcp/tools/inspect_surface" in mcp_node.http_paths
    assert "/mcp/tools/trigger_cleanup" in mcp_node.http_paths

    # Subprocess edges carry function-scoped symbol_links and `declared` verification
    sub_sync = next(
        e
        for e in report.edges
        if e.id == "e:subprocess:scripts/gateway_daemon.py:scripts/sync_task.py"
    )
    assert sub_sync.verification == "declared"
    assert "record_metric->*" in sub_sync.symbol_links

    sub_mcp = next(
        e
        for e in report.edges
        if e.id == "e:subprocess:scripts/mcp_daemon.py:scripts/cleanup.sh"
    )
    assert "call_tool->*" in sub_mcp.symbol_links

    # Truth read_by_count & written_by_count populated from SQL helper wrapper calls
    tbl_node = nodes_by_id["t:sqlite:metrics:surf_metrics"]
    assert tbl_node.read_by_count >= 1
    assert tbl_node.written_by_count >= 1

    # End-to-end 3-tier chain connects React App.tsx -> GatewayHandler -> gateway_daemon.py -> SQLite store
    assert len(report.chains) >= 2
    assert any(
        ch.http_method == "GET"
        and ch.http_path == "/api/metrics"
        and "t:sqlite:metrics:surf_metrics" in ch.truth_table_ids
        for ch in report.chains
    )
    assert "DISP-004" not in {f.rule_code for f in report.findings}
    assert "DISP-008" not in {f.rule_code for f in report.findings}

    # Surgical cone from React App.tsx reaches GatewayHandler, gateway_daemon.py, and surf_metrics
    cone = build_lineage_cone_slice(report, "App")
    assert any(p.id == "t:sqlite:metrics:surf_metrics" for p in cone.downstream_truth_nodes)


def test_stdlib_http_emits_embedded_html_display_page_when_display_empty(tmp_path: Path) -> None:
    repo = tmp_path / "embedded_html_only"
    _put(repo, "ui/status.html", "<!doctype html><html><body>OK</body></html>\n")
    _put(
        repo,
        "scripts/status_server.py",
        """\
from http.server import BaseHTTPRequestHandler
from pathlib import Path

class StatusHandler(BaseHTTPRequestHandler):
    def do_GET(self):
        if self.path == "/status":
            body = Path("ui/status.html").read_bytes()
            self.send_header("Content-Type", "text/html")
            self.wfile.write(body)
""",
    )
    truth = SqlDdlTruthAdapter().extract(repo, ".")
    manip = PythonServicesAdapter().extract(repo, ".", truth)
    disp_pages = [n for n in manip.nodes if n.tier == "display" and n.subkind == "page"]
    assert len(disp_pages) == 1
    assert disp_pages[0].label == "ui/status.html"
    assert any(
        e.source_id == disp_pages[0].id
        and e.target_id == "m:route:scripts/status_server.py:StatusHandler"
        and e.kind == "queries_endpoint"
        for e in manip.edges
    )


def test_declarative_json_registries_emit_policy_truth_and_field_consumption(
    tmp_path: Path,
) -> None:
    repo = tmp_path / "registry_lineage"
    _put(repo, "scripts/gateway_daemon.py", "def run():\n    return 0\n")
    _put(repo, "scripts/hourly_job.py", "def run():\n    return 0\n")
    _put(
        repo,
        "config/surfaces.json",
        json.dumps(
            {
                "surfaces": {
                    "surf_demo": {
                        "enabled": True,
                        "rate_limit": 120,
                        "wrapper": "scripts/gateway_daemon.py",
                    }
                }
            }
        ),
    )
    _put(
        repo,
        "configs/schedules.json",
        json.dumps(
            {
                "schedules": [
                    {
                        "id": "hourly_rollup",
                        "enabled": True,
                        "cadence_seconds": 3600,
                        "command": ["python3", "scripts/hourly_job.py"],
                    }
                ]
            }
        ),
    )
    _put(
        repo,
        "config/capabilities.json",
        json.dumps({"capabilities": {"demo.read": {"timeout_seconds": 15, "allowlist": ["local"]}}}),
    )
    # 1. Consuming reader with fallback constant
    _put(
        repo,
        "scripts/surface_loader.py",
        """\
import json
from pathlib import Path

DEFAULT_RATE_LIMIT = 60
SURFACES_FILE = Path("config") / "surfaces.json"

def get_surface_limit() -> int:
    data = json.loads(SURFACES_FILE.read_text(encoding="utf-8"))
    surf = data["surfaces"]["surf_demo"]
    if not surf.get("enabled"):
        return 0
    return surf.get("rate_limit", DEFAULT_RATE_LIMIT)
""",
    )
    # 2. Bypassing reader substituting hardcoded policy constant
    _put(
        repo,
        "scripts/schedule_bypasser.py",
        """\
import json
from pathlib import Path

DEFAULT_CADENCE = 300

def read_schedule_interval() -> int:
    doc = json.loads(Path("configs/schedules.json").read_text(encoding="utf-8"))
    _ = doc.get("version")
    return DEFAULT_CADENCE
""",
    )
    # 3. Dynamic/unresolved reader
    _put(
        repo,
        "scripts/dynamic_cap_reader.py",
        """\
import json
from pathlib import Path

def lookup_cap(field_name: str):
    payload = json.loads(Path("config/capabilities.json").read_text(encoding="utf-8"))
    return payload[field_name]
""",
    )

    truth = SqlDdlTruthAdapter().extract(repo, ".")
    manip = PythonServicesAdapter().extract(repo, ".", truth)

    tnodes = {n.id: n for n in truth.nodes}
    for reg_id in (
        "t:registry:config/surfaces.json",
        "t:registry:configs/schedules.json",
        "t:registry:config/capabilities.json",
    ):
        assert reg_id in tnodes
        assert tnodes[reg_id].role == "policy"
        assert tnodes[reg_id].read_by_count == 1
        assert len(tnodes[reg_id].policy_columns) >= 1

    # Wrapper & command `calls_helper` links preserved alongside Tier-1 Truth nodes
    pairs = {(e.source_id, e.target_id) for e in manip.edges if e.kind == "calls_helper"}
    assert ("m:registry:config/surfaces.json", "m:script:scripts/gateway_daemon.py") in pairs
    assert ("m:registry:configs/schedules.json", "m:script:scripts/hourly_job.py") in pairs

    edges_by_src_tgt = {(e.source_id, e.target_id): e for e in manip.edges if e.kind == "reads_truth"}
    surf_edge = edges_by_src_tgt[("m:script:scripts/surface_loader.py", "t:registry:config/surfaces.json")]
    assert surf_edge.policy_field_consumption is not None
    assert surf_edge.policy_field_consumption.state == "consumed"
    assert "rate_limit" in surf_edge.policy_field_consumption.consumed_columns
    assert "DEFAULT_RATE_LIMIT" in surf_edge.policy_field_consumption.fallback_constants

    sched_edge = edges_by_src_tgt[("m:script:scripts/schedule_bypasser.py", "t:registry:configs/schedules.json")]
    assert sched_edge.policy_field_consumption is not None
    assert sched_edge.policy_field_consumption.state == "bypassed"
    assert "DEFAULT_CADENCE" in sched_edge.policy_field_consumption.substituted_constants

    cap_edge = edges_by_src_tgt[("m:script:scripts/dynamic_cap_reader.py", "t:registry:config/capabilities.json")]
    assert cap_edge.policy_field_consumption is not None
    assert cap_edge.policy_field_consumption.state == "unresolved"


def test_asyncpg_cross_module_registry_loader_and_module_subprocess(
    db_session: Session, tmp_path: Path
) -> None:
    repo = tmp_path / "asyncpg_and_cross_loader"
    _put(
        repo,
        "config/commands.json",
        json.dumps(
            {
                "commands": {
                    "reindex": {
                        "enabled": True,
                        "timeout_seconds": 45,
                        "argv": ["python3", "src/pkg/reindex.py"],
                    }
                }
            }
        ),
    )
    _put(
        repo,
        "src/pkg/__init__.py",
        "",
    )
    _put(
        repo,
        "src/pkg/cfg_loader.py",
        """\
import json
from pathlib import Path

def load_commands_registry() -> dict:
    return json.loads((Path("config") / "commands.json").read_text(encoding="utf-8"))
""",
    )
    _put(
        repo,
        "src/pkg/reindex.py",
        """\
import asyncpg

async def ensure_tables(dsn: str) -> None:
    conn = await asyncpg.connect(dsn)
    await conn.execute(
        "CREATE TABLE IF NOT EXISTS search.documents (doc_id TEXT PRIMARY KEY, max_tokens INTEGER)"
    )
    await conn.execute("INSERT INTO search.documents (doc_id, max_tokens) VALUES ($1, $2)", "d1", 512)
""",
    )
    _put(
        repo,
        "src/pkg/dispatcher.py",
        """\
import subprocess
from pkg.cfg_loader import load_commands_registry

def run_enabled_commands() -> int:
    reg = load_commands_registry()
    cmd_cfg = reg["commands"]["reindex"]
    if not cmd_cfg["enabled"]:
        return 0
    subprocess.run(["python3", "-m", "pkg.reindex"], check=True)
    return int(cmd_cfg["timeout_seconds"])
""",
    )

    truth = SqlDdlTruthAdapter().extract(repo, ".")
    manip = PythonServicesAdapter().extract(repo, ".", truth)

    tnodes = {n.id: n for n in truth.nodes}
    assert "t:postgres:search.documents" in tnodes
    assert tnodes["t:postgres:search.documents"].written_by_count == 1
    assert "t:registry:config/commands.json" in tnodes
    # Both cfg_loader.py and 1-hop caller dispatcher.py read t:registry:config/commands.json
    assert tnodes["t:registry:config/commands.json"].read_by_count == 2

    disp_read = next(
        e
        for e in manip.edges
        if e.source_id == "m:script:src/pkg/dispatcher.py"
        and e.target_id == "t:registry:config/commands.json"
        and e.kind == "reads_truth"
    )
    assert disp_read.policy_field_consumption is not None
    assert disp_read.policy_field_consumption.state == "consumed"
    assert {"commands", "enabled", "timeout_seconds"} <= set(
        disp_read.policy_field_consumption.consumed_columns
    )

    # `python3 -m pkg.reindex` subprocess resolves to `src/pkg/reindex.py`
    mod_sub = next(
        e
        for e in manip.edges
        if e.id == "e:subprocess:src/pkg/dispatcher.py:src/pkg/reindex.py"
    )
    assert mod_sub.verification == "declared"
    assert mod_sub.symbol_links == ["run_enabled_commands->*"]

    # Preservation checks for FastAPI, NestJS, and frontend-only SPA autodetect
    fa_repo = tmp_path / "preserve_fastapi"
    _put(fa_repo, "backend/pyproject.toml", '[project]\ndependencies = ["fastapi", "sqlalchemy"]\n')
    _put(fa_repo, "backend/app/main.py", "from fastapi import FastAPI\napp = FastAPI()\n")
    _put(fa_repo, "frontend/package.json", '{"dependencies": {"next": "15.0.0"}}')
    assert detect_repository_stack(db_session, str(fa_repo)).recommended_profile_slug == "fastapi-sqlalchemy-nextjs"

    nest_repo = tmp_path / "preserve_nestjs"
    _put(nest_repo, "apps/server/package.json", '{"dependencies": {"@nestjs/core": "10.0.0"}}')
    _put(nest_repo, "apps/client/package.json", '{"dependencies": {"react": "18.3.0"}}')
    assert detect_repository_stack(db_session, str(nest_repo)).manipulator_adapter == "typescript-node"

    spa_repo = tmp_path / "preserve_spa"
    _put(spa_repo, "package.json", '{"dependencies": {"react": "18.3.0"}}')
    _put(spa_repo, "src/App.tsx", "export function App() { return <main>SPA</main>; }\n")
    det_spa = detect_repository_stack(db_session, str(spa_repo))
    assert det_spa.manipulator_adapter == "no-manipulator"
    assert det_spa.recommended_profile_slug == "frontend-only-react"


def test_autodetect_never_hijacks_nextjs_prisma_turborepo_or_spa_with_helper_py(
    tmp_path: Path, db_session: Session
) -> None:
    # (a) Next.js + Prisma Server Actions (no app/api/) + linter-only pyproject.toml
    nx_prisma = tmp_path / "nextjs_prisma_sa"
    _put(nx_prisma, "package.json", '{"dependencies": {"next": "15.0.0", "@prisma/client": "6.0.0"}}')
    _put(nx_prisma, "prisma/schema.prisma", "model Item { id Int @id }\n")
    _put(nx_prisma, "src/app/page.tsx", "export default function Page() { return <div />; }\n")
    _put(nx_prisma, "pyproject.toml", '[tool.ruff]\nline-length = 100\n')
    det_np = detect_repository_stack(db_session, str(nx_prisma))
    assert det_np.recommended_profile_slug == "nextjs-prisma"
    assert det_np.manipulator_adapter == "typescript-node"
    assert det_np.truth_adapter == "prisma-schema"

    # (b) Turborepo (`apps/web` Next.js + `packages/api` Express + `packages/db/schema.prisma` + `scripts/deploy.py`)
    turbo = tmp_path / "turborepo_express"
    _put(turbo, "apps/web/package.json", '{"dependencies": {"next": "15.0.0", "react": "19.0.0"}}')
    _put(turbo, "apps/web/src/app/page.tsx", "export default function Home() { return <main />; }\n")
    _put(turbo, "packages/api/package.json", '{"dependencies": {"express": "5.0.0"}}')
    _put(turbo, "packages/db/schema.prisma", "model Account { id Int @id }\n")
    _put(turbo, "scripts/deploy.py", 'if __name__ == "__main__":\n    print("deploy")\n')
    det_tb = detect_repository_stack(db_session, str(turbo))
    assert det_tb.manipulator_adapter == "typescript-node"
    assert det_tb.truth_adapter == "prisma-schema"
    assert det_tb.recommended_profile_slug == "nextjs-prisma"

    # (c) Root React/Vite SPA + lone `scripts/release.py` helper (no backend, no SQL)
    spa_py = tmp_path / "spa_with_release_script"
    _put(spa_py, "package.json", '{"dependencies": {"react": "18.3.0", "vite": "6.0.0"}}')
    _put(spa_py, "vite.config.ts", "export default {};\n")
    _put(spa_py, "src/App.tsx", "export function App() { return <div />; }\n")
    _put(spa_py, "scripts/release.py", 'print("tag release")\n')
    det_sp = detect_repository_stack(db_session, str(spa_py))
    assert det_sp.manipulator_adapter == "no-manipulator"
    assert det_sp.truth_adapter == "no-truth"
    assert det_sp.recommended_profile_slug == "frontend-only-react"


def test_containment_and_registry_bypass_local_return_regressions(tmp_path: Path) -> None:
    outside = tmp_path / "outside_secret"
    _put(outside, "leak.sql", "CREATE TABLE secret_table (id INT PRIMARY KEY);\n")
    _put(outside, "leak.html", "<html><body>leak</body></html>\n")

    repo = tmp_path / "contained_repo"
    _put(repo, "db/schema.sql", "CREATE TABLE jobs (id INT PRIMARY KEY);\n")
    _put(repo, "services/api/migrations/001_users.up.sql", "CREATE TABLE users (id INT PRIMARY KEY);\n")
    (repo / "backend").symlink_to("services/api")
    _put(
        repo,
        "config/schedules.json",
        json.dumps(
            {
                "schedules": [
                    {"name": "nightly", "command": "scripts/worker.py", "enabled": True, "interval_seconds": 60}
                ]
            }
        ),
    )
    _put(
        repo,
        "config/jobs.json",
        json.dumps(
            {
                "jobs": [
                    {"name": "sync", "command": "scripts/worker.py", "enabled": True, "interval_seconds": 120}
                ]
            }
        ),
    )
    _put(
        repo,
        "scripts/worker.py",
        (
            "import json\n"
            "from http.server import BaseHTTPRequestHandler\n"
            "from pathlib import Path\n\n"
            "def bypassed_local_var() -> int:\n"
            "    cfg = json.loads(Path('config/schedules.json').read_text())\n"
            "    interval = 300\n"
            "    return interval\n\n"
            "def load_jobs_with_block():\n"
            "    with open('config/jobs.json') as fh:\n"
            "        data = json.load(fh)\n"
            "    return data\n\n"
            "class Handler(BaseHTTPRequestHandler):\n"
            "    def do_GET(self):\n"
            "        if self.path == '/ui':\n"
            "            self.send_header('Content-Type', 'text/html')\n"
            "            Path('../outside_secret/leak.html').read_text()\n"
        ),
    )

    # B2 negative control: invalid, symlinked, or missing backend_subdir skips ONLY that subdir
    # while still extracting all in-repo tables (`t:jobs`, `t:users`) and excluding `secret_table`.
    for sub in ("../outside_secret", "backend", "missing_server", "."):
        res = SqlDdlTruthAdapter().extract(repo, sub)
        ids = {n.id for n in res.nodes}
        assert "t:secret_table" not in ids
        assert {"t:jobs", "t:users", "t:registry:config/schedules.json", "t:registry:config/jobs.json"} <= ids

    truth = SqlDdlTruthAdapter().extract(repo, ".")
    manip = PythonServicesAdapter().extract(repo, ".", truth)
    for node in [*truth.nodes, *manip.nodes]:
        assert not node.source_file.startswith("..")
        assert "outside_secret" not in node.source_file

    sched_edge = next(
        e
        for e in manip.edges
        if e.source_id == "m:script:scripts/worker.py"
        and e.target_id == "t:registry:config/schedules.json"
        and e.kind == "reads_truth"
    )
    assert sched_edge.policy_field_consumption is not None
    assert sched_edge.policy_field_consumption.state == "bypassed"

    # M3 negative control: `with open(...) as fh: data = json.load(fh); return data` is consumed.
    jobs_edge = next(
        e
        for e in manip.edges
        if e.source_id == "m:script:scripts/worker.py"
        and e.target_id == "t:registry:config/jobs.json"
        and e.kind == "reads_truth"
    )
    assert jobs_edge.policy_field_consumption is not None
    assert jobs_edge.policy_field_consumption.state == "consumed"


def test_b1_h1_h2_ui_sql_monorepo_examples_and_daemon_catchall_regressions(
    tmp_path: Path, db_session: Session
) -> None:
    # B1(a): Vite+React SPA + Supabase SQL migrations (zero Python) -> frontend-only-react & INCOMPLETE gate
    spa_supa = tmp_path / "spa_supabase"
    _put(spa_supa, "package.json", '{"dependencies": {"react": "18.3.0", "vite": "6.0.0"}}')
    _put(spa_supa, "vite.config.ts", "export default {};\n")
    _put(
        spa_supa,
        "src/App.tsx",
        'export async function load() { return fetch("/api/items"); }\n'
        "export function App() { return <div>Items</div>; }\n",
    )
    _put(spa_supa, "supabase/migrations/20240101_init.sql", "CREATE TABLE items (id UUID PRIMARY KEY);\n")
    det_supa = detect_repository_stack(db_session, str(spa_supa))
    assert det_supa.recommended_profile_slug == "frontend-only-react"
    assert det_supa.manipulator_adapter == "no-manipulator"
    t_supa = TargetProject(
        id=0,
        slug="spa-supabase",
        name="spa-supabase",
        repo_path=str(spa_supa),
        stack_profile_slug=det_supa.recommended_profile_slug,
        backend_subdir=det_supa.backend_subdir,
        frontend_subdir=det_supa.frontend_subdir,
        is_active=True,
    )
    rep_supa = run_target_scan(db_session, t_supa, strict_gate=True, persist_snapshot=False)
    assert rep_supa.gate.verdict == "INCOMPLETE"
    assert all(f.rule_code != "DISP-004" for f in rep_supa.findings)

    # B1(b): `frontend/` React SPA + `scripts/release.py` helper (no Python manifest or daemon/store)
    fe_helper = tmp_path / "frontend_dir_helper_py"
    _put(fe_helper, "frontend/package.json", '{"dependencies": {"react": "18.3.0"}}')
    _put(
        fe_helper,
        "frontend/src/App.tsx",
        'export async function load() { return fetch("/api/items"); }\n'
        "export function App() { return <div>Items</div>; }\n",
    )
    _put(fe_helper, "scripts/release.py", 'print("tag release")\n')
    det_fh = detect_repository_stack(db_session, str(fe_helper))
    assert det_fh.recommended_profile_slug == "frontend-only-react"
    assert det_fh.manipulator_adapter == "no-manipulator"

    # B1(c): Next.js + `db/schema.sql` (zero Python) -> frontend-only-nextjs
    nx_sql = tmp_path / "next_rootsql"
    _put(nx_sql, "package.json", '{"dependencies": {"next": "15.0.0", "react": "19.0.0"}}')
    _put(nx_sql, "app/page.tsx", "export default function Page() { return <main>Hi</main>; }\n")
    _put(nx_sql, "db/schema.sql", "CREATE TABLE widgets (id INT PRIMARY KEY);\n")
    det_nx = detect_repository_stack(db_session, str(nx_sql))
    assert det_nx.recommended_profile_slug == "frontend-only-nextjs"
    assert det_nx.manipulator_adapter == "no-manipulator"

    # H1(a): Monorepo with two UI sub-apps (`apps/blog` + `apps/dashboard`) + FastAPI `backend/`
    # preserves root frontend scan so `apps/dashboard`'s `GET /api/orders` edge is retained.
    mono = tmp_path / "mono_two_apps"
    _put(mono, "package.json", '{"private": true, "workspaces": ["apps/*"]}')
    _put(mono, "backend/pyproject.toml", '[project]\ndependencies = ["fastapi", "sqlalchemy"]\n')
    _put(
        mono,
        "backend/app/main.py",
        "from fastapi import FastAPI\napp = FastAPI()\n@app.get('/api/orders')\ndef list_orders():\n    return []\n",
    )
    _put(mono, "apps/blog/package.json", '{"dependencies": {"next": "15.0.0", "react": "19.0.0"}}')
    _put(mono, "apps/blog/app/page.tsx", "export default function Blog() { return <article>Blog</article>; }\n")
    _put(mono, "apps/dashboard/package.json", '{"dependencies": {"react": "18.3.0"}}')
    _put(
        mono,
        "apps/dashboard/src/App.tsx",
        'export async function fetchOrders() { return (await fetch("/api/orders")).json(); }\n'
        "export function App() { return <div>Dash</div>; }\n",
    )
    det_mono = detect_repository_stack(db_session, str(mono))
    assert det_mono.frontend_subdir == "."
    assert det_mono.confidence == "medium"
    t_mono = TargetProject(
        id=0,
        slug="mono-two-apps",
        name="mono-two-apps",
        repo_path=str(mono),
        stack_profile_slug=det_mono.recommended_profile_slug,
        backend_subdir=det_mono.backend_subdir,
        frontend_subdir=det_mono.frontend_subdir,
        is_active=True,
    )
    rep_mono = run_target_scan(db_session, t_mono, strict_gate=True, persist_snapshot=False)
    assert any("/api/orders" in (e.evidence_note or "") for e in rep_mono.edges)

    # H1(b): Python library with `examples/` UI demos never selects an `examples/*` frontend
    pylib = tmp_path / "pylib_examples"
    _put(pylib, "pyproject.toml", '[project]\nname = "mylib"\ndependencies = ["httpx"]\n')
    _put(pylib, "src/mylib/__init__.py", "def client():\n    return None\n")
    _put(pylib, "examples/a-nextjs-chat/package.json", '{"dependencies": {"next": "15.0.0", "react": "19.0.0"}}')
    _put(pylib, "examples/a-nextjs-chat/app/page.tsx", "export default function Demo() { return <div />; }\n")
    det_pylib = detect_repository_stack(db_session, str(pylib))
    assert not det_pylib.frontend_subdir.startswith("examples")
    assert det_pylib.display_adapter == "no-display"

    # H2: Pathless `do_GET` daemon handler never acts as a verified catch-all masking DISP-004 typos
    catchall = tmp_path / "daemon_catchall"
    _put(catchall, "pyproject.toml", '[project]\nname = "ops"\ndependencies = []\n')
    _put(catchall, "frontend/package.json", '{"dependencies": {"react": "18.3.0"}}')
    _put(
        catchall,
        "frontend/src/App.tsx",
        'export async function ok() { return fetch("/api/users"); }\n'
        'export async function bad() { return fetch("/api/usres-typo"); }\n'
        "export function App() { return <div>Ops</div>; }\n",
    )
    _put(
        catchall,
        "scripts/api.py",
        "from http.server import BaseHTTPRequestHandler\n"
        "class ApiHandler(BaseHTTPRequestHandler):\n"
        "    def do_GET(self):\n"
        "        if self.path == '/api/users':\n"
        "            self.send_response(200)\n",
    )
    _put(
        catchall,
        "scripts/healthd.py",
        "from http.server import BaseHTTPRequestHandler\n"
        "class Health(BaseHTTPRequestHandler):\n"
        "    def do_GET(self):\n"
        "        self.send_response(204)\n",
    )
    det_ca = detect_repository_stack(db_session, str(catchall))
    t_ca = TargetProject(
        id=0,
        slug="daemon-catchall",
        name="daemon-catchall",
        repo_path=str(catchall),
        stack_profile_slug=det_ca.recommended_profile_slug,
        backend_subdir=det_ca.backend_subdir,
        frontend_subdir=det_ca.frontend_subdir,
        is_active=True,
    )
    rep_ca = run_target_scan(db_session, t_ca, strict_gate=True, persist_snapshot=False)
    assert rep_ca.gate.verdict == "FAIL"
    assert any(f.rule_code == "DISP-004" and "/api/usres-typo" in f.title for f in rep_ca.findings)


def test_m6_m7_l4_l5_factory_handlers_dup_truth_ids_inline_heuristics_and_deep_json(
    db_session: Session, tmp_path: Path
) -> None:
    """Negative controls for M6 (nested handler class), M7 (unique truth IDs), L4 (SQLite UUID + prose), and L5 (deep JSON)."""
    from app.adapters.inline_store_truth import scan_inline_stores

    # M6: Handler class nested inside a factory function links `/api/status` and passes strict gate
    fac = tmp_path / "daemon_factory"
    _put(fac, "pyproject.toml", '[project]\nname = "ops"\ndependencies = []\n')
    _put(fac, "frontend/package.json", '{"dependencies": {"react": "18.3.0", "vite": "6.0.0"}}')
    _put(
        fac,
        "frontend/src/App.tsx",
        'export async function s() { return (await fetch("/api/status")).json(); }\n'
        "export function App() { return <div />; }\n",
    )
    _put(
        fac,
        "scripts/statusd.py",
        "from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer\n"
        "def make_handler(state):\n"
        "    class Handler(BaseHTTPRequestHandler):\n"
        "        def do_GET(self):\n"
        "            if self.path == '/api/status':\n"
        "                self.send_response(200)\n"
        "    return Handler\n"
        "ThreadingHTTPServer(('127.0.0.1', 8765), make_handler({'ok': True}))\n",
    )
    det_fac = detect_repository_stack(db_session, str(fac))
    t_fac = TargetProject(
        id=0,
        slug="daemon-factory",
        name="daemon-factory",
        repo_path=str(fac),
        stack_profile_slug=det_fac.recommended_profile_slug,
        backend_subdir=det_fac.backend_subdir,
        frontend_subdir=det_fac.frontend_subdir,
        is_active=True,
    )
    rep_fac = run_target_scan(db_session, t_fac, strict_gate=True, persist_snapshot=False)
    assert rep_fac.gate.verdict == "PASS"
    assert any(
        e.source_id == "d:page:App" and e.target_id == "m:route:scripts/statusd.py:Handler"
        for e in rep_fac.edges
    )

    # M7: Standalone SQLite `.sql` + inline SQLite `CREATE TABLE` against `<stem>.db` emits unique node IDs
    dup = tmp_path / "sqlite_dup_ids"
    _put(dup, "data/ledger.sql", "CREATE TABLE events (id INTEGER PRIMARY KEY AUTOINCREMENT, kind TEXT);\n")
    _put(
        dup,
        "scripts/recorder.py",
        "import sqlite3\n"
        "DB = 'data/ledger.db'\n"
        "def init():\n"
        "    conn = sqlite3.connect(DB)\n"
        "    conn.execute('CREATE TABLE IF NOT EXISTS events (id INTEGER PRIMARY KEY AUTOINCREMENT, kind TEXT, at TEXT)')\n"
        "    conn.execute('CREATE TABLE IF NOT EXISTS runs (id INTEGER PRIMARY KEY AUTOINCREMENT)')\n",
    )
    truth_dup = SqlDdlTruthAdapter().extract(dup, ".")
    dup_ids = [n.id for n in truth_dup.nodes]
    assert len(dup_ids) == len(set(dup_ids))
    ev_node = next(n for n in truth_dup.nodes if "events" in n.id)
    assert set(ev_node.columns) >= {"id", "kind", "at"}

    # L4: sqlite3-only module with `UUID` column stays `sqlite`, and prose error strings create zero tables
    heur = tmp_path / "inline_heur"
    _put(
        heur,
        "scripts/session_store.py",
        "import sqlite3\n"
        "def init():\n"
        "    conn = sqlite3.connect('sessions.db')\n"
        "    conn.execute('CREATE TABLE IF NOT EXISTS sessions (id UUID PRIMARY KEY, data TEXT)')\n",
    )
    _put(
        heur,
        "scripts/bootstrap.py",
        "import sys\n"
        "def main():\n"
        "    sys.exit('Could not create table users (is the volume mounted read-only?)')\n",
    )
    scanned_stores = scan_inline_stores(heur, ".")
    assert [(s.engine, s.qualifier, s.table_name) for s in scanned_stores] == [
        ("sqlite", "sessions", "sessions")
    ]

    # L5: 2,000-level nested `config/*.json` never raises `RecursionError`
    deep = tmp_path / "deep_json_repo"
    _put(deep, "config/deep.json", ("[" * 2000) + "1" + ("]" * 2000))
    truth_deep = SqlDdlTruthAdapter().extract(deep, ".")
    assert [n.id for n in truth_deep.nodes] == []

