"""Regression tests for post-PR-13 graph, probe, React reachability, DDL-age, and SARIF tightening."""

from __future__ import annotations

import os
import subprocess
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path

import pytest
from sqlalchemy.orm import Session

from app import __version__
from app.adapters.base import RawCandidateFinding, TruthExtractionResult
from app.adapters.postgres_sqlalchemy import PostgresSqlAlchemyAdapter
from app.adapters.python_fastapi import PythonFastApiAdapter
from app.schemas.atlas import TargetProjectCreate
from app.services.diff_and_sarif_service import build_sarif_log
from app.services.governance_service import get_target_by_slug, register_target
from app.services.route_probe_service import apply_live_route_probe
from app.services.scanner_service import run_target_scan


def _write(root: Path, rel: str, text: str) -> None:
    path = root / rel
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(text, encoding="utf-8")


def test_python_nested_closures_and_stdlib_methods_do_not_forge_edges(tmp_path: Path) -> None:
    _write(
        tmp_path,
        "backend/app/services/helper_box.py",
        "def outer(items):\n"
        "    def resolve(x):\n"
        "        return x\n"
        "    def walk(x):\n"
        "        return x\n"
        "    return [resolve(i) for i in walk(items)]\n\n"
        "class SlotCatalog:\n"
        "    def list_slots(self):\n"
        "        return []\n",
    )
    _write(
        tmp_path,
        "backend/app/api/routes/items.py",
        "import ast\n"
        "from pathlib import Path\n"
        "from fastapi import APIRouter\n\n"
        "router = APIRouter()\n\n"
        "@router.get('/api/v1/items')\n"
        "def get_items(registry):\n"
        "    p = Path('.').resolve()\n"
        "    _ = list(ast.walk(ast.parse('x = 1')))\n"
        "    return {'path': str(p), 'slots': registry.list_slots()}\n",
    )
    empty_truth = TruthExtractionResult(
        nodes=[],
        table_symbol_map={},
        function_symbol_map={},
        findings=[],
        observation_source="static_ast",
    )
    res = PythonFastApiAdapter().extract(tmp_path, "backend", empty_truth)
    notes = [e.evidence_note for e in res.edges]
    assert not any("resolve()" in n for n in notes)
    assert not any("walk()" in n for n in notes)
    assert any("Calls `list_slots()` across manipulation tier." in n for n in notes)

    wythe_root = Path(__file__).resolve().parents[2]
    self_res = PythonFastApiAdapter().extract(wythe_root, "backend", empty_truth)
    self_notes = [e.evidence_note for e in self_res.edges]
    assert not any("Calls `resolve()`" in n for n in self_notes)
    assert not any("Calls `walk()`" in n for n in self_notes)


def test_live_probe_over_real_tcp_socket_ignores_http_proxy_and_blocks_link_local(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    wire_calls: list[tuple[str, str]] = []

    class Handler(BaseHTTPRequestHandler):
        def do_GET(self) -> None:
            wire_calls.append(("GET", self.path))
            if self.path.startswith("/__wythe_probe_absent_"):
                self.send_response(404)
            elif self.path == "/api/v1/protected":
                self.send_response(401)
            elif self.path == "/api/v1/mutate":
                self.send_response(405)
            else:
                self.send_response(404)
            self.end_headers()

        def log_message(self, fmt: str, *args: object) -> None:
            return

    server = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
    port = server.server_address[1]
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()

    try:
        # Poison proxy env vars: local loopback probing must bypass env proxies (trust_env=False).
        monkeypatch.setenv("HTTP_PROXY", "http://127.0.0.1:1")
        monkeypatch.setenv("HTTPS_PROXY", "http://127.0.0.1:1")
        findings = [
            RawCandidateFinding(
                rule_code="DISP-004",
                node_id="d:hook:a",
                source_file="frontend/src/hooks/a.ts",
                line=4,
                title="missing",
                detail="static.",
                remediation="fix",
                http_method="GET",
                http_path="/api/v1/gone",
            ),
            RawCandidateFinding(
                rule_code="DISP-004",
                node_id="d:hook:a",
                source_file="frontend/src/hooks/a.ts",
                line=8,
                title="protected",
                detail="static.",
                remediation="fix",
                http_method="GET",
                http_path="/api/v1/protected",
            ),
            RawCandidateFinding(
                rule_code="DISP-004",
                node_id="d:hook:a",
                source_file="frontend/src/hooks/a.ts",
                line=12,
                title="mutate",
                detail="static.",
                remediation="fix",
                http_method="POST",
                http_path="/api/v1/mutate",
            ),
        ]
        adjusted, note = apply_live_route_probe(findings, f"http://127.0.0.1:{port}")
        by_path = {f.http_path: f for f in adjusted}
        assert by_path["/api/v1/gone"].rule_code == "DISP-004"
        assert "(confirmed)" in by_path["/api/v1/gone"].detail
        assert by_path["/api/v1/protected"].rule_code == "DISP-006"
        assert by_path["/api/v1/mutate"].rule_code == "DISP-004"
        assert "was not verified" in by_path["/api/v1/mutate"].detail
        assert all(method == "GET" for method, _ in wire_calls)
        assert "1 confirmed missing" in note and "1 answered by a live route" in note
    finally:
        server.shutdown()
        server.server_close()

    for blocked in ("http://169.254.169.254/latest/meta-data", "http://0.0.0.0:8000"):
        with pytest.raises(ValueError, match="link-local, multicast, or unspecified"):
            apply_live_route_probe(findings[:1], blocked, allow_remote=False)
        with pytest.raises(ValueError, match="link-local, multicast, or unspecified"):
            apply_live_route_probe(findings[:1], blocked, allow_remote=True)


def test_react_spa_per_symbol_reachability_splits_live_and_dead_calls(
    db_session: Session, tmp_path: Path
) -> None:
    _write(tmp_path, "backend/schema.sql", "CREATE TABLE widgets (id SERIAL PRIMARY KEY);\n")
    _write(
        tmp_path,
        "backend/app/api/routes/widgets.py",
        "from fastapi import APIRouter\n"
        "router = APIRouter()\n"
        "@router.get('/api/v1/widgets')\n"
        "def list_widgets():\n"
        "    return []\n",
    )
    _write(
        tmp_path,
        "frontend/src/main.tsx",
        "import { App } from './App';\nexport const boot = App;\n",
    )
    _write(
        tmp_path,
        "frontend/src/App.tsx",
        "import { useLiveCall } from './hooks/useWidgets';\n"
        "export function App() {\n"
        "  useLiveCall();\n"
        "  return <main>ok</main>;\n"
        "}\n",
    )
    _write(
        tmp_path,
        "frontend/src/hooks/useWidgets.ts",
        "export async function useLiveCall() {\n"
        "  return fetch('/api/v1/missing-live');\n"
        "}\n"
        "export async function useUnusedLegacyCall() {\n"
        "  return fetch('/api/v1/missing-dead');\n"
        "}\n",
    )
    register_target(
        db_session,
        TargetProjectCreate(
            slug="react-reach-demo",
            name="React Reach Demo",
            repo_path=str(tmp_path),
            stack_profile_slug="fastapi-react-spa",
        ),
    )
    target = get_target_by_slug(db_session, "react-reach-demo")
    assert target is not None
    report = run_target_scan(db_session, target, strict_gate=True, persist_snapshot=False)
    by_code = {f.rule_code: f for f in report.findings if f.rule_code in ("DISP-004", "DISP-007")}
    assert "DISP-004" in by_code and "DISP-007" in by_code
    assert "/api/v1/missing-live" in by_code["DISP-004"].title
    assert "Reached from:" in by_code["DISP-004"].detail
    assert "/api/v1/missing-dead" in by_code["DISP-007"].title
    assert not by_code["DISP-007"].blocks_gate

    sarif = build_sarif_log(report)
    driver = sarif["runs"][0]["tool"]["driver"]
    assert driver["version"] == __version__
    assert driver["informationUri"] == "https://github.com/Euda1mon1a/wythe"


def test_data_only_migration_does_not_mark_schema_sql_stale(tmp_path: Path) -> None:
    def git(*args: str, date_iso: str | None = None) -> None:
        env = {
            **os.environ,
            "GIT_AUTHOR_NAME": "Test",
            "GIT_AUTHOR_EMAIL": "user@example.com",
            "GIT_COMMITTER_NAME": "Test",
            "GIT_COMMITTER_EMAIL": "user@example.com",
        }
        if date_iso:
            env["GIT_AUTHOR_DATE"] = date_iso
            env["GIT_COMMITTER_DATE"] = date_iso
        subprocess.run(["git", *args], cwd=tmp_path, check=True, capture_output=True, env=env)

    git("init")
    _write(tmp_path, "backend/schema.sql", "CREATE TABLE items (id SERIAL PRIMARY KEY);\n")
    _write(
        tmp_path,
        "backend/app/models/item.py",
        "from sqlalchemy.orm import DeclarativeBase, Mapped, mapped_column\n"
        "class Base(DeclarativeBase):\n    pass\n"
        "class Item(Base):\n"
        "    __tablename__ = 'items'\n"
        "    id: Mapped[int] = mapped_column(primary_key=True)\n",
    )
    _write(
        tmp_path,
        "backend/alembic/versions/0001_init.py",
        "from alembic import op\nimport sqlalchemy as sa\n"
        "revision = '0001'\ndown_revision = None\n"
        "def upgrade() -> None:\n"
        "    op.create_table('items', sa.Column('id', sa.Integer, primary_key=True))\n",
    )
    git("add", ".")
    git("commit", "-m", "init", date_iso="2026-11-01T00:00:00Z")

    _write(
        tmp_path,
        "backend/alembic/versions/0002_seed_data.py",
        "from alembic import op\nimport sqlalchemy as sa\n"
        "revision = '0002'\ndown_revision = '0001'\n"
        "def upgrade() -> None:\n"
        "    op.get_bind().execute(sa.text('INSERT INTO items (id) VALUES (1)'))\n",
    )
    git("add", ".")
    git("commit", "-m", "seed", date_iso="2026-11-05T00:00:00Z")

    res_seed = PostgresSqlAlchemyAdapter().extract(tmp_path, "backend")
    assert not any("schema.sql was last changed" in n for n in res_seed.notes)

    _write(
        tmp_path,
        "backend/alembic/versions/0003_ddl_table.py",
        "from alembic import op\nimport sqlalchemy as sa\n"
        "revision = '0003'\ndown_revision = '0002'\n"
        "def upgrade() -> None:\n"
        "    op.create_table('orders', sa.Column('id', sa.Integer, primary_key=True))\n",
    )
    git("add", ".")
    git("commit", "-m", "ddl", date_iso="2026-11-08T00:00:00Z")

    res_ddl = PostgresSqlAlchemyAdapter().extract(tmp_path, "backend")
    assert any("schema.sql was last changed" in n for n in res_ddl.notes)
