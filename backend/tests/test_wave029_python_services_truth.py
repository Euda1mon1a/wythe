"""Wave 029 tests for autodetect (#98), python_services (#98/#100), and sql_ddl_truth (#100)."""

from __future__ import annotations

import json
from pathlib import Path

import pytest
from sqlalchemy.orm import Session

from app.adapters import sql_ddl_truth
from app.adapters.autodetect import detect_repository_stack
from app.adapters.python_services import PythonServicesAdapter
from app.adapters.sql_ddl_truth import SqlDdlTruthAdapter


def _put(root: Path, rel: str, text: str) -> Path:
    dest = root / rel
    dest.parent.mkdir(parents=True, exist_ok=True)
    dest.write_text(text, encoding="utf-8")
    return dest


@pytest.mark.parametrize(
    "ui_prefix,js_rel,expected_sub",
    [
        ("", "views/home.js", "."),
        ("", "core/api_client.js", "."),
        ("", "app.js", "."),
        ("ui/", "ui/utils/dom.js", "ui"),
        ("web/", "web/shared/state.js", "web"),
        ("static/", "static/main.js", "static"),
        ("public/", "public/views/dash.js", "public"),
        ("frontend/", "frontend/core/client.js", "frontend"),
        ("apps/ops_portal/", "apps/ops_portal/views/overview.js", "apps/ops_portal"),
    ],
)
def test_98_autodetect_vanilla_es_module_ui_roots_and_subdirs(
    db_session: Session,
    tmp_path: Path,
    ui_prefix: str,
    js_rel: str,
    expected_sub: str,
) -> None:
    repo = tmp_path / "vanilla_repo"
    _put(
        repo,
        f"{ui_prefix}index.html",
        "<!doctype html><html><body><div id='app'></div>"
        "<script type=\"module\" src=\"./app.js\"></script></body></html>\n",
    )
    _put(repo, js_rel, "export async function load() { return fetch('/api/health'); }\n")
    _put(
        repo,
        "scripts/app_daemon.py",
        "from http.server import BaseHTTPRequestHandler, HTTPServer\n"
        "class Handler(BaseHTTPRequestHandler):\n"
        "    def do_GET(self):\n"
        "        if self.path == '/api/health':\n"
        "            self.send_response(200)\n",
    )

    det = detect_repository_stack(db_session, str(repo))
    assert det.display_adapter == "typescript-react"
    assert det.frontend_subdir == expected_sub
    assert det.manipulator_adapter == "python-services"
    assert det.truth_adapter == "sql-ddl"
    assert det.recommended_profile_slug == "python-services-react"


def test_98_autodetect_predominant_python_services_not_hijacked_by_aux_demos(
    db_session: Session, tmp_path: Path
) -> None:
    # 1. Primary root vanilla ES UI + 10 Python scripts + launchd plist + FastAPI dep (no app/ layout)
    #    + tiny auxiliary apps/web/demo and examples/demo must NOT hijack frontend_subdir or collapse tiers.
    repo = tmp_path / "ops_daemon_repo"
    _put(
        repo,
        "pyproject.toml",
        '[project]\nname = "ops_portal"\ndependencies = ["fastapi", "uvicorn"]\n',
    )
    _put(
        repo,
        "index.html",
        "<!doctype html><html><body><script type='module' src='./app.js'></script></body></html>\n",
    )
    _put(repo, "app.js", "import { render } from './views/home.js'; render();\n")
    _put(repo, "views/home.js", "export function render() { return fetch('/api/status'); }\n")
    _put(
        repo,
        "launchagents/com.example.daemon.plist",
        '<?xml version="1.0"?><plist version="1.0"><dict>'
        "<key>Label</key><string>com.example.daemon</string>"
        "<key>ProgramArguments</key><array><string>/usr/bin/python3</string>"
        "<string>daemons/app_daemon.py</string></array></dict></plist>\n",
    )
    _put(
        repo,
        "daemons/app_daemon.py",
        "from http.server import BaseHTTPRequestHandler\n"
        "class OpsHandler(BaseHTTPRequestHandler):\n"
        "    def do_GET(self):\n"
        "        if self.path == '/api/status':\n"
        "            self.send_response(200)\n",
    )
    for idx in range(10):
        _put(repo, f"scripts/slice_builder_{idx}.py", f"def run_{idx}():\n    return {idx}\n")
    _put(
        repo,
        "apps/web/demo/package.json",
        json.dumps({"name": "demo", "dependencies": {"next": "15.0.0", "react": "19.0.0"}}),
    )
    _put(repo, "apps/web/demo/app/page.tsx", "export default function Demo() { return <div />; }\n")
    _put(
        repo,
        "examples/toy/package.json",
        json.dumps({"name": "toy", "dependencies": {"react": "18.3.0"}}),
    )
    _put(repo, "examples/toy/src/App.tsx", "export function App() { return <div />; }\n")

    det = detect_repository_stack(db_session, str(repo))
    assert det.frontend_subdir == "."
    assert det.display_adapter == "typescript-react"
    assert det.manipulator_adapter == "python-services"
    assert det.truth_adapter == "sql-ddl"
    assert det.recommended_profile_slug == "python-services-react"

    # 2. Daemon UI in static/ + single daemon_routes file outside scripts/src + tiny apps/web/demo
    static_repo = tmp_path / "static_daemon_repo"
    _put(
        static_repo,
        "static/index.html",
        "<!doctype html><html><body><script type=\"module\" src=\"./core/client.js\"></script></body></html>\n",
    )
    _put(static_repo, "static/core/client.js", "export const ping = () => fetch('/api/ping');\n")
    _put(
        static_repo,
        "daemons/slice_builder.py",
        "from http.server import BaseHTTPRequestHandler\n"
        "class PingHandler(BaseHTTPRequestHandler):\n"
        "    def do_GET(self):\n"
        "        if self.path == '/api/ping':\n"
        "            self.send_response(200)\n",
    )
    _put(
        static_repo,
        "apps/web/demo/package.json",
        json.dumps({"dependencies": {"react": "18.3.0"}}),
    )
    _put(static_repo, "apps/web/demo/src/App.tsx", "export function App() { return <div />; }\n")

    det_static = detect_repository_stack(db_session, str(static_repo))
    assert det_static.frontend_subdir == "static"
    assert det_static.display_adapter == "typescript-react"
    assert det_static.manipulator_adapter == "python-services"
    assert det_static.recommended_profile_slug == "python-services-react"

    # 3. Framework override (Next.js) wins over vanilla index.html when Next.js markers exist
    next_repo = tmp_path / "next_override"
    _put(next_repo, "package.json", json.dumps({"dependencies": {"next": "15.0.0", "react": "19.0.0"}}))
    _put(next_repo, "index.html", "<script type='module' src='./app.js'></script>\n")
    _put(next_repo, "app.js", "console.log('hi');\n")
    _put(next_repo, "src/app/page.tsx", "export default function Home() { return <main />; }\n")
    _put(next_repo, "scripts/worker.py", "import sqlite3\nconn = sqlite3.connect('ops.db')\n")
    det_next = detect_repository_stack(db_session, str(next_repo))
    assert det_next.display_adapter == "typescript-nextjs"
    assert det_next.recommended_profile_slug == "python-services-nextjs"


def test_98_python_services_manip001_skips_test_and_constant_modules_keeps_clock_and_services(
    tmp_path: Path,
) -> None:
    _put(
        tmp_path,
        "scripts/constants.py",
        '"""Pure shared policy defaults module."""\n'
        "from typing import Final\n"
        "MAX_HOURS_LIMIT: Final[int] = 72\n"
        "DEFAULT_PENALTY = 10\n",
    )
    _put(
        tmp_path,
        "scripts/enums.py",
        "from enum import IntEnum\n"
        "class QuotaDefaults(IntEnum):\n"
        "    MAX_WORKLOAD = 40\n",
    )
    _put(
        tmp_path,
        "scripts/test_policy_helpers.py",
        "MAX_SHIFT_CAP = 12\n"
        "def test_cap():\n"
        "    assert MAX_SHIFT_CAP == 12\n",
    )
    _put(
        tmp_path,
        "scripts/slice_builder.py",
        "from datetime import date\n"
        "MAX_SHIFT_CAP = 16\n"
        "def build_slice():\n"
        "    return date.today(), MAX_SHIFT_CAP\n",
    )
    _put(
        tmp_path,
        "scripts/clock.py",
        "from datetime import date\n"
        "def current_day():\n"
        "    return date.today()\n",
    )

    truth = SqlDdlTruthAdapter().extract(tmp_path, ".")
    manip = PythonServicesAdapter().extract(tmp_path, ".", truth)

    m1 = [f for f in manip.findings if f.rule_code == "MANIP-001"]
    m2 = [f for f in manip.findings if f.rule_code == "MANIP-002"]
    assert [(f.source_file, f.title.split("`")[1]) for f in m1] == [
        ("scripts/slice_builder.py", "MAX_SHIFT_CAP")
    ]
    assert [f.source_file for f in m2] == ["scripts/slice_builder.py"]

    nodes = {n.id: n for n in manip.nodes}
    assert nodes["m:script:scripts/constants.py"].status == "clean"
    assert nodes["m:script:scripts/enums.py"].status == "clean"
    assert nodes["m:script:scripts/test_policy_helpers.py"].status == "clean"
    assert nodes["m:script:scripts/slice_builder.py"].status == "policy_in_code"


def test_100_unmapped_sql_collision_store_mismatch_and_missing_ddl_emit_unverified_edges(
    tmp_path: Path,
) -> None:
    _put(
        tmp_path,
        "scripts/sqlite_events.py",
        "import sqlite3\n"
        "def init_sq():\n"
        "    c = sqlite3.connect('local.db')\n"
        "    c.execute('CREATE TABLE IF NOT EXISTS events (id INTEGER PRIMARY KEY, kind TEXT)')\n",
    )
    _put(
        tmp_path,
        "scripts/pg_events.py",
        "import psycopg\n"
        "def init_pg(dsn: str):\n"
        "    with psycopg.connect(dsn) as conn:\n"
        "        conn.execute('CREATE TABLE IF NOT EXISTS events (id BIGSERIAL PRIMARY KEY, payload JSONB)')\n",
    )
    _put(
        tmp_path,
        "scripts/ledger_writer.py",
        "from pathlib import Path\n"
        "def write_ledger(line: str):\n"
        "    Path('var/audit_log.jsonl').write_text(line)\n",
    )
    # 1. Cross-engine collision (`events` in both SQLite & PG) read without driver import -> t:unmapped:events
    # 2. Store-kind mismatch (`audit_log.jsonl` exists only as JSONL, queried via SQL) -> t:unmapped:audit_log
    # 3. Non-public schema mismatch (`analytics.events` queried when only `public.events` exists) -> t:unmapped:analytics.events
    _put(
        tmp_path,
        "scripts/neutral_reader.py",
        "def run_queries(conn):\n"
        "    conn.execute('SELECT id FROM events')\n"
        "    conn.execute('SELECT * FROM audit_log')\n"
        "    conn.execute('INSERT INTO analytics.events (id) VALUES (1)')\n",
    )

    truth = SqlDdlTruthAdapter().extract(tmp_path, ".")
    assert "events" not in truth.table_symbol_map
    assert truth.table_symbol_map["audit_log"] == "t:jsonl:audit_log"

    manip = PythonServicesAdapter().extract(tmp_path, ".", truth)
    tnodes = {n.id: n for n in truth.nodes}

    for tid in ("t:unmapped:events", "t:unmapped:audit_log", "t:unmapped:analytics.events"):
        assert tid in tnodes
        assert tnodes[tid].role == "unmapped"
        assert tnodes[tid].status == "gray_zone"
        assert "unmapped_sql_reference" in (tnodes[tid].verification_note or "")

    edges = {(e.source_id, e.kind, e.target_id, e.verification) for e in manip.edges}
    assert (
        "m:script:scripts/neutral_reader.py",
        "reads_truth",
        "t:unmapped:events",
        "unverified",
    ) in edges
    assert (
        "m:script:scripts/neutral_reader.py",
        "reads_truth",
        "t:unmapped:audit_log",
        "unverified",
    ) in edges
    assert (
        "m:script:scripts/neutral_reader.py",
        "writes_truth",
        "t:unmapped:analytics.events",
        "unverified",
    ) in edges
    assert tnodes["t:unmapped:events"].read_by_count == 1
    assert tnodes["t:unmapped:analytics.events"].written_by_count == 1


def test_100_inline_pg_ddl_with_vector_jsonb_question_mark_and_live_truth005(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    _put(
        tmp_path,
        "migrations/001_core.sql",
        "CREATE TABLE core_accounts (id BIGSERIAL PRIMARY KEY, name TEXT NOT NULL);\n",
    )
    # Inline Postgres DDL WITHOUT importing psycopg directly, containing VECTOR, DOUBLE PRECISION,
    # TEXT[], TIMESTAMPTZ, UUID, JSONB CHECK (? operator), SQL comment with `?`, and USING hnsw / gin.
    _put(
        tmp_path,
        "scripts/schema_boot.py",
        '"""Bootstrap vector & audit tables inline."""\n'
        "DDL = \"\"\"\n"
        "CREATE TABLE IF NOT EXISTS doc_chunks (\n"
        "    id UUID PRIMARY KEY,\n"
        "    seq_id BIGSERIAL NOT NULL,\n"
        "    embedding VECTOR(1536),\n"
        "    score DOUBLE PRECISION,\n"
        "    tags TEXT[],\n"
        "    created_at TIMESTAMPTZ NOT NULL,\n"
        "    -- store flexible payload? yes\n"
        "    meta JSONB CHECK (meta ? 'source')\n"
        ");\n"
        "CREATE INDEX IF NOT EXISTS idx_doc_emb ON doc_chunks USING hnsw (embedding vector_cosine_ops);\n"
        "CREATE INDEX IF NOT EXISTS idx_doc_meta ON doc_chunks USING gin (meta);\n"
        "\"\"\"\n",
    )
    _put(
        tmp_path,
        "scripts/chunk_worker.py",
        "import psycopg\n"
        "def sync_chunks(dsn: str):\n"
        "    with psycopg.connect(dsn) as conn:\n"
        "        conn.execute('INSERT INTO doc_chunks (tags) VALUES (%s)', (['a'],))\n"
        "        return conn.execute(\"SELECT id, score FROM doc_chunks WHERE meta ? 'source'\").fetchall()\n",
    )

    truth_static = SqlDdlTruthAdapter().extract(tmp_path, ".")
    tnodes_static = {n.id: n for n in truth_static.nodes}
    assert "t:postgres:public.doc_chunks" in tnodes_static
    assert not any(nid.startswith("t:sqlite:") for nid in tnodes_static)
    chunk_node = tnodes_static["t:postgres:public.doc_chunks"]
    assert {"id", "seq_id", "embedding", "score", "tags", "created_at", "meta"} <= set(chunk_node.columns)
    assert "inline_python_ddl" in (chunk_node.verification_note or "")

    manip = PythonServicesAdapter().extract(tmp_path, ".", truth_static)
    edge_pairs = {(e.source_id, e.kind, e.target_id, e.verification) for e in manip.edges}
    assert (
        "m:script:scripts/chunk_worker.py",
        "reads_truth",
        "t:postgres:public.doc_chunks",
        "verified",
    ) in edge_pairs
    assert (
        "m:script:scripts/chunk_worker.py",
        "writes_truth",
        "t:postgres:public.doc_chunks",
        "verified",
    ) in edge_pairs
    assert chunk_node.read_by_count == 1
    assert chunk_node.written_by_count == 1

    # Reverse live-catalog TRUTH-005 check under pg_dsn:
    # `core_accounts` is in migrations/001_core.sql -> NO TRUTH-005
    # `alembic_version` is migration meta -> NO TRUTH-005
    # `doc_chunks` is ONLY inline Python DDL (not .sql) -> MUST emit TRUTH-005
    # `out_of_band_tbl` has no DDL at all -> MUST emit TRUTH-005
    monkeypatch.setattr(
        sql_ddl_truth,
        "probe_live_catalog_tables",
        lambda _dsn: (
            {"core_accounts", "doc_chunks", "out_of_band_tbl", "alembic_version"},
            "static_ast+pg_catalog_readonly",
        ),
    )
    truth_live = SqlDdlTruthAdapter().extract(
        tmp_path, ".", pg_dsn="postgresql://readonly:pw@localhost:5432/app"
    )
    t005 = {f.node_id: f for f in truth_live.findings if f.rule_code == "TRUTH-005"}
    assert set(t005) == {"t:postgres:public.doc_chunks", "t:live:out_of_band_tbl"}
    assert t005["t:postgres:public.doc_chunks"].source_file == "scripts/schema_boot.py"
    assert "alembic_version" not in {n.label for n in truth_live.nodes}
    live_nodes = {n.id: n for n in truth_live.nodes}
    assert live_nodes["t:postgres:public.doc_chunks"].status == "gray_zone"
    assert live_nodes["t:core_accounts"].status == "clean"
