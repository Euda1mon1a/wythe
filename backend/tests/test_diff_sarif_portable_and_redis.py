"""Tests for DB Policy Vocabularies, Redis Ephemeral Lineage, PR Diff/SARIF, & Portable Config."""

from __future__ import annotations

import json
import socket
import subprocess
import threading
from pathlib import Path

from sqlalchemy.orm import Session

from app.cli import main as cli_main
from app.db.session import get_session_factory
from app.main import initialize_database
from app.schemas.atlas import (
    AuditRulingCreate,
    PolicyVocabularyCreate,
    PolicyVocabularyUpdate,
    RatchetCaptureRequest,
    RulePolicyUpdate,
    TargetProjectCreate,
)
from app.services.governance_service import (
    capture_ratchet_baselines,
    create_policy_vocabulary,
    get_target_by_slug,
    list_policy_vocabularies,
    list_ratchet_baselines,
    list_rule_policies,
    list_rulings,
    record_audit_ruling,
    register_target,
    update_policy_vocabulary,
    update_rule_policy,
)
from app.services.scanner_service import run_target_scan


def test_custom_db_vocabulary_pack_drives_policy_detection(
    db_session: Session, tmp_path: Path
) -> None:
    """Adding a custom token in `atlas_policy_vocabularies` flags Python & TSX without code edits."""
    repo = tmp_path / "media_royalty_app"
    (repo / "backend" / "app" / "models").mkdir(parents=True)
    (repo / "backend" / "app" / "services").mkdir(parents=True)
    (repo / "backend" / "app" / "api").mkdir(parents=True)
    (repo / "frontend" / "src" / "app").mkdir(parents=True)

    (repo / "backend" / "schema.sql").write_text(
        "CREATE TABLE tracks (id INTEGER PRIMARY KEY, title TEXT NOT NULL);\n",
        encoding="utf-8",
    )
    (repo / "backend" / "app" / "models" / "track.py").write_text(
        "from sqlalchemy.orm import DeclarativeBase, Mapped, mapped_column\n"
        "class Base(DeclarativeBase): pass\n"
        "class Track(Base):\n"
        "    __tablename__ = 'tracks'\n"
        "    id: Mapped[int] = mapped_column(primary_key=True)\n"
        "    title: Mapped[str]\n",
        encoding="utf-8",
    )
    (repo / "backend" / "app" / "services" / "payout_service.py").write_text(
        "from sqlalchemy import select\n"
        "from app.models.track import Track\n"
        "STREAM_ROYALTY_BPS = 250\n"
        "def list_tracks(db):\n"
        "    return db.scalars(select(Track)).all()\n",
        encoding="utf-8",
    )
    (repo / "backend" / "app" / "api" / "routes.py").write_text(
        "from fastapi import APIRouter\n"
        "from app.services.payout_service import list_tracks\n"
        "router = APIRouter()\n"
        "@router.get('/tracks')\n"
        "def get_tracks():\n"
        "    return list_tracks(None)\n",
        encoding="utf-8",
    )
    (repo / "backend" / "app" / "main.py").write_text(
        "from fastapi import FastAPI\n"
        "from app.api.routes import router\n"
        "app = FastAPI()\n"
        "app.include_router(router, prefix='/api/v1')\n",
        encoding="utf-8",
    )
    (repo / "frontend" / "src" / "app" / "page.tsx").write_text(
        "const ARTIST_ROYALTY_BPS = 250;\n"
        "export default function Page() { return <div>{ARTIST_ROYALTY_BPS}</div>; }\n",
        encoding="utf-8",
    )

    register_target(
        db_session,
        TargetProjectCreate(slug="royalty-app", name="Royalty App", repo_path=str(repo)),
    )
    target = get_target_by_slug(db_session, "royalty-app")
    assert target is not None

    # Before adding ROYALTY_BPS: 0 policy findings.
    clean_rep = run_target_scan(db_session, target, strict_gate=True)
    assert clean_rep.gate.verdict == "PASS"

    # Insert custom vocabulary token in DB truth -> both MANIP-001 and DISP-001 fire!
    vocab = create_policy_vocabulary(
        db_session,
        PolicyVocabularyCreate(
            domain_pack="music",
            token="ROYALTY_BPS",
            description="Streaming royalty split basis points.",
        ),
    )
    flagged_rep = run_target_scan(db_session, target, strict_gate=True)
    codes = {f.rule_code for f in flagged_rep.findings}
    assert {"MANIP-001", "DISP-001"} <= codes

    # Disable token in DB truth -> passes again!
    update_policy_vocabulary(db_session, vocab.id, PolicyVocabularyUpdate(is_enabled=False))
    disabled_rep = run_target_scan(db_session, target, strict_gate=True)
    assert disabled_rep.gate.verdict == "PASS"


def test_redis_ephemeral_keyspace_ttl_guard_worker_door_and_live_probe(
    db_session: Session, tmp_path: Path
) -> None:
    """Verify Redis `cache_store` nodes, `TRUTH-004` TTL check, Celery worker door, & RESP probe."""
    repo = tmp_path / "redis_worker_app"
    (repo / "backend" / "app" / "models").mkdir(parents=True)
    (repo / "backend" / "app" / "services").mkdir(parents=True)
    (repo / "backend" / "app" / "tasks").mkdir(parents=True)
    (repo / "backend" / "app" / "api").mkdir(parents=True)
    (repo / "frontend" / "src" / "app").mkdir(parents=True)

    (repo / "backend" / "schema.sql").write_text(
        "CREATE TABLE jobs (id INTEGER PRIMARY KEY, status TEXT NOT NULL);\n",
        encoding="utf-8",
    )
    (repo / "backend" / "app" / "models" / "job.py").write_text(
        "from sqlalchemy.orm import DeclarativeBase, Mapped, mapped_column\n"
        "class Base(DeclarativeBase): pass\n"
        "class Job(Base):\n"
        "    __tablename__ = 'jobs'\n"
        "    id: Mapped[int] = mapped_column(primary_key=True)\n"
        "    status: Mapped[str]\n",
        encoding="utf-8",
    )
    (repo / "backend" / "app" / "services" / "cache_service.py").write_text(
        "import redis\n"
        "from sqlalchemy import select\n"
        "from app.models.job import Job\n"
        "redis_client = redis.Redis()\n"
        "def sync_jobs(db):\n"
        "    redis_client.setex('schedule_cache:latest', 300, 'ok')\n"
        "    redis_client.set('shadow_state:forever', 'bad')\n"
        "    return db.scalars(select(Job)).all()\n",
        encoding="utf-8",
    )
    (repo / "backend" / "app" / "services" / "worker_service.py").write_text(
        "from celery import shared_task\n"
        "@shared_task\n"
        "def crunch_digest():\n"
        "    return True\n",
        encoding="utf-8",
    )
    (repo / "backend" / "app" / "api" / "routes.py").write_text(
        "import redis\n"
        "from fastapi import APIRouter\n"
        "from app.services.cache_service import sync_jobs\n"
        "router = APIRouter()\n"
        "redis_client = redis.Redis()\n"
        "@router.post('/jobs')\n"
        "def run_job():\n"
        "    redis_client.set('route_mut:1', 'x', ex=60)\n"
        "    return sync_jobs(None)\n",
        encoding="utf-8",
    )
    (repo / "backend" / "app" / "main.py").write_text(
        "from fastapi import FastAPI\n"
        "from app.api.routes import router\n"
        "app = FastAPI()\n"
        "app.include_router(router, prefix='/api/v1')\n",
        encoding="utf-8",
    )
    (repo / "frontend" / "src" / "app" / "page.tsx").write_text(
        "export default function P() { return <div>Jobs</div>; }\n",
        encoding="utf-8",
    )

    # Ephemeral mock RESP server verifying zero GET/HGET value reads
    received_cmds: list[str] = []
    srv = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    srv.bind(("127.0.0.1", 0))
    srv.listen(1)
    port = srv.getsockname()[1]

    def _serve_resp() -> None:
        conn, _ = srv.accept()
        with conn:
            conn.settimeout(1.0)
            for _ in range(2):
                data = conn.recv(1024).decode("utf-8", errors="replace")
                received_cmds.append(data)
                if "INFO" in data:
                    conn.sendall(b"$22\r\n# Keyspace\r\ndb0:keys=2\r\n")
                else:
                    conn.sendall(
                        b"*2\r\n$1\r\n0\r\n*2\r\n$12\r\nlive_probe:1\r\n$12\r\nlive_probe:2\r\n"
                    )
        srv.close()

    t = threading.Thread(target=_serve_resp, daemon=True)
    t.start()

    register_target(
        db_session,
        TargetProjectCreate(slug="redis-app", name="Redis App", repo_path=str(repo)),
    )
    target = get_target_by_slug(db_session, "redis-app")
    assert target is not None

    rep = run_target_scan(
        db_session, target, redis_dsn=f"redis://127.0.0.1:{port}/0", strict_gate=True
    )
    t.join(timeout=2)

    assert rep.observation_source == "static_ast+redis_scan"
    assert not any("GET" in cmd for cmd in received_cmds)
    store_ids = {n.id for n in rep.nodes if n.subkind == "cache_store"}
    assert {
        "t:redis:schedule_cache",
        "t:redis:shadow_state",
        "t:redis:route_mut",
        "t:redis:queue_worker_service",
        "t:redis:live_probe",
    } <= store_ids

    # `shadow_state` without TTL triggers TRUTH-004; `schedule_cache` with `setex` does NOT.
    t4 = [f for f in rep.findings if f.rule_code == "TRUTH-004"]
    assert len(t4) == 1
    assert "shadow_state" in t4[0].title

    # Direct route Redis mutation triggers TRUTH-003.
    assert any(f.rule_code == "TRUTH-003" and "route_mut" in f.title for f in rep.findings)

    # `@shared_task` worker_service is NOT false-flagged as inert under MANIP-003!
    assert not any(
        f.rule_code == "MANIP-003" and "worker_service" in f.source_file for f in rep.findings
    )


def test_pr_diff_gate_blast_radius_and_sarif_export(
    isolated_db_url: str, tmp_path: Path
) -> None:
    """Legacy violations outside touched hunks pass `diff`, while new hunk violations fail + emit SARIF."""
    assert isolated_db_url.startswith("sqlite:")
    repo = tmp_path / "git_diff_repo"
    (repo / "backend" / "app" / "models").mkdir(parents=True)
    (repo / "backend" / "app" / "services").mkdir(parents=True)
    (repo / "backend" / "app" / "api").mkdir(parents=True)
    (repo / "frontend" / "src" / "api").mkdir(parents=True)
    (repo / "frontend" / "src" / "app" / "orders").mkdir(parents=True)

    (repo / "backend" / "schema.sql").write_text(
        "CREATE TABLE orders (id INTEGER PRIMARY KEY, total INTEGER NOT NULL);\n",
        encoding="utf-8",
    )
    (repo / "backend" / "app" / "models" / "order.py").write_text(
        "from sqlalchemy.orm import DeclarativeBase, Mapped, mapped_column\n"
        "class Base(DeclarativeBase): pass\n"
        "class Order(Base):\n"
        "    __tablename__ = 'orders'\n"
        "    id: Mapped[int] = mapped_column(primary_key=True)\n"
        "    total: Mapped[int]\n",
        encoding="utf-8",
    )
    # Untouched legacy violation in legacy_service.py
    (repo / "backend" / "app" / "services" / "legacy_service.py").write_text(
        "LEGACY_SHIFT_CAP = 12\n"
        "def legacy_helper():\n"
        "    return 1\n",
        encoding="utf-8",
    )
    svc_file = repo / "backend" / "app" / "services" / "order_service.py"
    svc_file.write_text(
        "from sqlalchemy import select\n"
        "from app.models.order import Order\n"
        "from app.services.legacy_service import legacy_helper\n"
        "def list_orders(db):\n"
        "    _ = legacy_helper()\n"
        "    return db.scalars(select(Order)).all()\n",
        encoding="utf-8",
    )
    (repo / "backend" / "app" / "api" / "routes.py").write_text(
        "from fastapi import APIRouter\n"
        "from app.services.order_service import list_orders\n"
        "router = APIRouter()\n"
        "@router.get('/orders')\n"
        "def get_orders():\n"
        "    return list_orders(None)\n",
        encoding="utf-8",
    )
    (repo / "backend" / "app" / "main.py").write_text(
        "from fastapi import FastAPI\n"
        "from app.api.routes import router\n"
        "app = FastAPI()\n"
        "app.include_router(router, prefix='/api/v1')\n",
        encoding="utf-8",
    )
    (repo / "frontend" / "src" / "api" / "orders.ts").write_text(
        "import type { paths } from './api-generated';\n"
        "export type P = paths;\n"
        "export const fetchOrders = () => fetch('/api/v1/orders');\n",
        encoding="utf-8",
    )
    (repo / "frontend" / "src" / "app" / "orders" / "page.tsx").write_text(
        "import { fetchOrders } from '../../api/orders';\n"
        "export default function OrdersPage() { void fetchOrders(); return <div>Orders</div>; }\n",
        encoding="utf-8",
    )

    git_env = {
        "GIT_AUTHOR_NAME": "Test",
        "GIT_AUTHOR_EMAIL": "user@example.com",
        "GIT_COMMITTER_NAME": "Test",
        "GIT_COMMITTER_EMAIL": "user@example.com",
        "PATH": "/usr/bin:/bin:/usr/local/bin:/opt/homebrew/bin",
    }
    subprocess.run(["git", "init"], cwd=repo, check=True, env=git_env, capture_output=True)
    subprocess.run(["git", "add", "."], cwd=repo, check=True, env=git_env, capture_output=True)
    subprocess.run(
        ["git", "-c", "core.hooksPath=/dev/null", "commit", "-m", "baseline"],
        cwd=repo,
        check=True,
        env=git_env,
        capture_output=True,
    )

    # Clean edit to order_service.py -> `diff --base HEAD` PASSES despite legacy_service.py!
    diff_json = tmp_path / "clean_diff.json"
    svc_file.write_text(
        svc_file.read_text(encoding="utf-8") + "\ndef count_orders():\n    return 0\n",
        encoding="utf-8",
    )
    assert cli_main(["diff", str(repo), "--base", "HEAD", "--json", str(diff_json)]) == 0
    parsed_diff = json.loads(diff_json.read_text(encoding="utf-8"))
    assert parsed_diff["diff_verdict"] == "PASS"
    assert "t:orders" in parsed_diff["impacted_truth_nodes"]
    assert len(parsed_diff["impacted_display_nodes"]) >= 1
    assert len(parsed_diff["impacted_chains"]) == 1

    # Now introduce a blocking MANIP-001 violation on a touched line -> `diff` FAILS + emits SARIF!
    sarif_out = tmp_path / "pr.sarif.json"
    svc_file.write_text(
        svc_file.read_text(encoding="utf-8") + "NEW_WORKLOAD_CAP = 80\n",
        encoding="utf-8",
    )
    assert cli_main(["diff", str(repo), "--base", "HEAD", "--sarif", str(sarif_out)]) == 1
    sarif_doc = json.loads(sarif_out.read_text(encoding="utf-8"))
    assert sarif_doc["version"] == "2.1.0"
    assert sarif_doc["runs"][0]["results"][0]["ruleId"] == "MANIP-001"


def test_portable_governance_bundle_export_and_ci_sync_roundtrip(
    monkeypatch, tmp_path: Path
) -> None:
    """Export `.wythe/governance.json` from DB A and hydrate into fresh DB B."""
    repo = tmp_path / "portable_repo"
    (repo / "backend" / "app").mkdir(parents=True)
    (repo / "frontend" / "src" / "app").mkdir(parents=True)
    (repo / "backend" / "app" / "main.py").write_text(
        "from fastapi import FastAPI\napp = FastAPI()\n", encoding="utf-8"
    )
    (repo / "frontend" / "src" / "app" / "page.tsx").write_text(
        "export default function P() { return <div />; }\n", encoding="utf-8"
    )

    db_a = tmp_path / "db_a.sqlite3"
    monkeypatch.setenv("WYTHE_DATABASE_URL", f"sqlite:///{db_a}")
    get_session_factory.cache_clear()
    initialize_database()
    with get_session_factory()() as sess_a:
        register_target(
            sess_a,
            TargetProjectCreate(slug="portable-repo", name="Portable", repo_path=str(repo)),
        )
        tgt_a = get_target_by_slug(sess_a, "portable-repo")
        assert tgt_a is not None
        update_rule_policy(
            sess_a,
            "TRUTH-004",
            RulePolicyUpdate(blocks_gate=True, severity="blocking", updated_by="arch-lead"),
        )
        create_policy_vocabulary(
            sess_a,
            PolicyVocabularyCreate(
                domain_pack="custom", token="TENANT_SLO_CAP", description="SLO cap"
            ),
        )
        rep_a = run_target_scan(sess_a, tgt_a, strict_gate=True)
        capture_ratchet_baselines(
            sess_a, tgt_a.id, rep_a, RatchetCaptureRequest(recorded_by="arch-lead")
        )
        record_audit_ruling(
            sess_a,
            tgt_a.id,
            audited_commit="deadbeef",
            payload=AuditRulingCreate(
                node_id="d:page:root",
                disposition="accepted_clean",
                summary="Verified clean root page.",
                recorded_by="arch-lead",
            ),
        )

    assert cli_main(["export-config", "portable-repo"]) == 0
    bundle_file = repo / ".wythe" / "governance.json"
    assert bundle_file.is_file()

    # Switch to brand-new isolated SQLite DB B (simulating fresh ephemeral CI runner)
    db_b = tmp_path / "db_b.sqlite3"
    monkeypatch.setenv("WYTHE_DATABASE_URL", f"sqlite:///{db_b}")
    get_session_factory.cache_clear()
    assert cli_main(["sync-config", str(repo)]) == 0

    with get_session_factory()() as sess_b:
        rules_b = {r.rule_code: r for r in list_rule_policies(sess_b)}
        assert rules_b["TRUTH-004"].blocks_gate is True
        vocabs_b = {v.token for v in list_policy_vocabularies(sess_b)}
        assert "TENANT_SLO_CAP" in vocabs_b
        tgt_b = get_target_by_slug(sess_b, "portable-repo")
        assert tgt_b is not None
        assert len(list_ratchet_baselines(sess_b, tgt_b.id)) == 18
        assert len(list_rulings(sess_b, tgt_b.id)) == 1
    get_session_factory.cache_clear()
