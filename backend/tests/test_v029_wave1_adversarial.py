"""Wave 1 adversarial regression suite for v0.2.9 security & epistemic hardening.

Covers live reproductions from the v0.2.8 adversarial audit:
- P0-1: Untrusted repo `core.fsmonitor` / `diff.external` host RCE blocked in `scan` & `diff`
- P0-2: `allow_local_plugins=False` blocks `.dist-info/entry_points.txt` inside repo/PYTHONPATH
- P0-3: Per-target `.wythe/governance.json` scoping, `--strict` immunity, slug-hijack & `O_NOFOLLOW`
- P0-4: `wythe diff` catches cross-file route deletion (`DISP-004`) & monorepo subdir violations
- P0-5: `wythe serve` Host allowlist, CSRF guard, `GET ?persist=true` rejection, `bundle_path` containment, & `focus --remote file://`
- P1-5: #104 `content_equality_only` / failed delivery dict / `agent-discordance` duplicate-receipt leak preservation
- P1-8 & P2-4: #103 secret snippet block, unknown backticked Atlas IDs, `sess.1` != `sess_1`, SQLite `#` `?mode=ro`, macOS `/tmp` bundle read
"""

from __future__ import annotations

import json
import sqlite3
import subprocess
import sys
from pathlib import Path

import pytest
from fastapi.testclient import TestClient

from app.adapters.db_catalog_probe import probe_live_catalog_tables
from app.adapters.plugin_registry import discover_plugins
from app.cli import main as cli_main
from app.core.clock import utc_now
from app.db.session import get_session_factory
from app.main import create_app, initialize_database
from app.schemas.atlas import PortableGovernanceBundle, PortableRuleOverride, TargetProjectCreate
from app.services.governance_service import get_target_by_slug, register_target
from app.services.investigation_service import (
    sanitize_session_file_token,
    validate_references_against_report,
)
from app.services.portable_config_service import (
    export_portable_bundle_to_disk,
    sync_portable_bundle_from_disk,
)
from app.services.scanner_service import run_target_scan
from app.services.understanding_service import (
    UnderstandingAnalyzeRequest,
    analyze_understanding_bundle,
    explain_outcome_lifecycle,
    read_understanding_bundle_file,
)
from wythe_plugin_agent_discordance.evaluator import evaluate_agent_discordance


def _init_git_repo(repo: Path) -> None:
    env = {
        "GIT_AUTHOR_NAME": "Test",
        "GIT_AUTHOR_EMAIL": "test@example.com",
        "GIT_COMMITTER_NAME": "Test",
        "GIT_COMMITTER_EMAIL": "test@example.com",
        "PATH": "/usr/bin:/bin:/usr/local/bin:/opt/homebrew/bin",
    }
    subprocess.run(["git", "init"], cwd=repo, check=True, env=env, capture_output=True)
    subprocess.run(["git", "add", "."], cwd=repo, check=True, env=env, capture_output=True)
    subprocess.run(
        ["git", "-c", "core.hooksPath=/dev/null", "commit", "-m", "init"],
        cwd=repo,
        check=True,
        env=env,
        capture_output=True,
    )


def test_p0_1_git_fsmonitor_and_external_diff_never_execute(
    isolated_db_url: str, tmp_path: Path
) -> None:
    assert isolated_db_url.startswith("sqlite:")
    repo = tmp_path / "untrusted_git"
    (repo / "backend" / "app").mkdir(parents=True)
    (repo / "backend" / "schema.sql").write_text("CREATE TABLE items (id INT PRIMARY KEY);\n")
    (repo / "backend" / "app" / "main.py").write_text("from fastapi import FastAPI\napp = FastAPI()\n")
    _init_git_repo(repo)

    sentinel = tmp_path / "RCE_FIRED"
    subprocess.run(
        ["git", "config", "core.fsmonitor", f"touch {sentinel} && echo"],
        cwd=repo,
        check=True,
    )
    subprocess.run(
        ["git", "config", "diff.external", f"touch {sentinel}"],
        cwd=repo,
        check=True,
    )
    (repo / "backend" / "app" / "main.py").write_text(
        "from fastapi import FastAPI\napp = FastAPI()\n# dirty\n"
    )

    assert cli_main(["scan", str(repo)]) == 0
    assert not sentinel.exists()
    assert cli_main(["diff", str(repo), "--base", "HEAD"]) == 2
    assert not sentinel.exists()


def test_p0_2_untrusted_dist_info_entry_point_blocked_by_default(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    evil_repo = tmp_path / "evil_plug_repo"
    dist_info = evil_repo / "evil_plug-0.1.dist-info"
    dist_info.mkdir(parents=True)
    sentinel = tmp_path / "PLUGIN_RCE"
    (evil_repo / "evil_mod.py").write_text(
        f"from pathlib import Path\nPath({str(sentinel)!r}).write_text('pwned')\nPLUG = None\n"
    )
    (dist_info / "METADATA").write_text("Metadata-Version: 2.1\nName: evil-plug\nVersion: 0.1\n")
    (dist_info / "entry_points.txt").write_text("[wythe.plugins]\nevil_plug = evil_mod:PLUG\n")

    monkeypatch.syspath_prepend(str(evil_repo))
    notes: list[str] = []
    specs = discover_plugins(repo_root=evil_repo, allow_local_plugins=False, notes_out=notes)
    assert not sentinel.exists()
    assert all(s.name != "evil_plug" for s in specs)
    assert any("blocked under allow_local_plugins=False" in n for n in notes)


def test_p0_3_per_target_governance_strict_immunity_slug_hijack_and_nofollow(
    isolated_db_url: str, tmp_path: Path
) -> None:
    assert isolated_db_url.startswith("sqlite:")
    initialize_database()

    victim = tmp_path / "victim_repo"
    attacker = tmp_path / "attacker_repo"
    for r in (victim, attacker):
        (r / "backend" / "app" / "services").mkdir(parents=True)
        (r / "backend" / "schema.sql").write_text("CREATE TABLE items (id INT PRIMARY KEY);\n")
        (r / "backend" / "app" / "main.py").write_text("from fastapi import FastAPI\napp = FastAPI()\n")
        (r / "backend" / "app" / "services" / "pol.py").write_text("SHADOW_WORKLOAD_CAP = 42\n")

    with get_session_factory()() as session:
        register_target(
            session,
            TargetProjectCreate(slug="victim-slug", name="Victim", repo_path=str(victim)),
        )
        # Direct cross-repo slug hijack via register_target must fail closed
        with pytest.raises(ValueError, match="refusing cross-repository slug hijack"):
            register_target(
                session,
                TargetProjectCreate(slug="victim-slug", name="Hijack", repo_path=str(attacker)),
            )

        register_target(
            session,
            TargetProjectCreate(slug="attacker-slug", name="Attacker", repo_path=str(attacker)),
        )
        t_victim = get_target_by_slug(session, "victim-slug")
        t_attacker = get_target_by_slug(session, "attacker-slug")
        assert t_victim is not None and t_attacker is not None

        # Attacker disables MANIP-001 in its governance bundle
        poison_bundle = PortableGovernanceBundle(
            target_slug="victim-slug",
            exported_at=utc_now(),
            rule_overrides=[
                PortableRuleOverride(
                    rule_code="MANIP-001",
                    severity="info",
                    enabled=False,
                    blocks_gate=False,
                    updated_by="attacker",
                )
            ],
        )
        sync_portable_bundle_from_disk(session, t_attacker, bundle=poison_bundle)

        # 1. Victim target is 100% unaffected even in non-strict mode!
        rep_victim = run_target_scan(session, t_victim, strict_gate=False, persist_snapshot=False)
        assert rep_victim.gate.verdict == "FAIL"
        assert any(f.rule_code == "MANIP-001" and f.blocks_gate for f in rep_victim.findings)

        # 2. `--strict` on attacker IGNORES `enabled=False`/`blocks_gate=False` relaxation!
        rep_att_strict = run_target_scan(session, t_attacker, strict_gate=True, persist_snapshot=False)
        assert rep_att_strict.gate.verdict == "FAIL"
        assert any(f.rule_code == "MANIP-001" and f.blocks_gate for f in rep_att_strict.findings)

        # 3. Symlink `.wythe/governance.json` export overwrite is blocked (`O_NOFOLLOW`)
        outside_secret = tmp_path / "outside_zshrc"
        outside_secret.write_text("KEEP_SAFE\n")
        (attacker / ".wythe").mkdir(exist_ok=True)
        (attacker / ".wythe" / "governance.json").symlink_to(outside_secret)
        with pytest.raises(ValueError, match="symlink"):
            export_portable_bundle_to_disk(session, t_attacker)
        assert outside_secret.read_text() == "KEEP_SAFE\n"


def test_p0_4_diff_catches_deleted_route_and_monorepo_subdir_violation(
    isolated_db_url: str, tmp_path: Path
) -> None:
    assert isolated_db_url.startswith("sqlite:")

    # 1. Deleting a backend FastAPI route breaks untouched frontend (`DISP-004`) -> diff MUST FAIL (exit 1)
    repo = tmp_path / "route_del_repo"
    (repo / "backend" / "app" / "api").mkdir(parents=True)
    (repo / "frontend" / "src" / "app").mkdir(parents=True)
    (repo / "backend" / "schema.sql").write_text("CREATE TABLE orders (id INT PRIMARY KEY);\n")
    routes_py = repo / "backend" / "app" / "api" / "routes.py"
    routes_py.write_text(
        "from fastapi import APIRouter\nrouter = APIRouter()\n"
        "@router.get('/orders')\ndef list_orders():\n    return []\n"
    )
    (repo / "backend" / "app" / "main.py").write_text(
        "from fastapi import FastAPI\nfrom app.api.routes import router\n"
        "app = FastAPI()\napp.include_router(router, prefix='/api/v1')\n"
    )
    (repo / "frontend" / "src" / "app" / "page.tsx").write_text(
        "export default function Page() { void fetch('/api/v1/orders'); return <div />; }\n"
    )
    _init_git_repo(repo)

    routes_py.write_text("from fastapi import APIRouter\nrouter = APIRouter()\n")
    diff_json = tmp_path / "del_diff.json"
    assert cli_main(["diff", str(repo), "--base", "HEAD", "--json", str(diff_json)]) == 1
    parsed = json.loads(diff_json.read_text())
    assert parsed["diff_verdict"] == "FAIL"
    assert any(f["rule_code"] == "DISP-004" for f in parsed["new_findings"])

    # 2. Monorepo subdirectory (`apps/web`) PR violation -> `--relative` & subtree base materialization catch it!
    mono = tmp_path / "monorepo"
    sub = mono / "apps" / "web"
    (sub / "backend" / "app" / "services").mkdir(parents=True)
    (sub / "frontend" / "src" / "app").mkdir(parents=True)
    (sub / "backend" / "schema.sql").write_text("CREATE TABLE items (id INT PRIMARY KEY);\n")
    svc_py = sub / "backend" / "app" / "services" / "clock_svc.py"
    svc_py.write_text("def ok():\n    return 1\n")
    (sub / "backend" / "app" / "main.py").write_text("from fastapi import FastAPI\napp = FastAPI()\n")
    (sub / "frontend" / "src" / "app" / "page.tsx").write_text(
        "export default function P() { return <div />; }\n"
    )
    _init_git_repo(mono)

    svc_py.write_text("from datetime import datetime\ndef bad():\n    return datetime.now()\n")
    mono_diff = tmp_path / "mono_diff.json"
    assert cli_main(["diff", str(sub), "--base", "HEAD", "--json", str(mono_diff)]) == 1
    mono_parsed = json.loads(mono_diff.read_text())
    assert mono_parsed["diff_verdict"] == "FAIL"
    assert mono_parsed["base_graph_status"] == "available"
    assert any(f["rule_code"] == "MANIP-002" for f in mono_parsed["new_findings"])


def test_p0_5_host_allowlist_csrf_get_persist_bundle_containment_and_focus_remote(
    isolated_db_url: str, tmp_path: Path
) -> None:
    assert isolated_db_url.startswith("sqlite:")
    app = create_app()
    with TestClient(app) as client:
        # 1. DNS-rebinding Host header rejected (`400`) + framing headers present
        rebind = client.get("/healthz", headers={"Host": "evil-rebinder.example:8780"})
        assert rebind.status_code == 400
        assert rebind.headers["X-Frame-Options"] == "DENY"
        assert "frame-ancestors 'none'" in rebind.headers["Content-Security-Policy"]

        # 2. Cross-site zero-preflight POST (`Sec-Fetch-Site: cross-site` or evil `Origin` or `text/plain`) -> `403`
        csrf_fetch = client.post(
            "/api/v1/targets/wythe/governance-sync?direction=export",
            headers={"Host": "127.0.0.1:8780", "Sec-Fetch-Site": "cross-site"},
        )
        assert csrf_fetch.status_code == 403

        csrf_origin = client.post(
            "/api/v1/scans/wythe",
            headers={"Host": "127.0.0.1:8780", "Origin": "https://attacker.example"},
        )
        assert csrf_origin.status_code == 403

        csrf_form = client.post(
            "/api/v1/scans/wythe",
            content="a=1",
            headers={"Host": "127.0.0.1:8780", "Content-Type": "text/plain"},
        )
        assert csrf_form.status_code == 403

        # 3. `GET /api/v1/scans/wythe?persist=true` forbidden (`400`)
        get_persist = client.get("/api/v1/scans/wythe?persist=true")
        assert get_persist.status_code == 400

        # 4. Arbitrary host `.json` read via `bundle_path` without `target_slug` rejected (`422`)
        secret_json = tmp_path / "host_secret.json"
        secret_json.write_text('{"secret_key": "DO_NOT_READ"}')
        unrooted_http = client.post(
            "/api/v1/understanding/analyze",
            json={"bundle_path": str(secret_json)},
        )
        assert unrooted_http.status_code == 422

    with pytest.raises(ValueError, match="registered target_slug"):
        analyze_understanding_bundle(UnderstandingAnalyzeRequest(bundle_path=str(secret_json)))

    # 5. `wythe focus --remote file://...` blocked (`exit 2`, never prints file contents)
    assert cli_main(["focus", "--remote", f"file://{secret_json}#", "--json"]) == 2


def test_p1_5_outcome_settlement_delivery_and_discordance_duplicate_receipt_guards() -> None:
    # 1. `content_equality_only=True` with zero receipts (`lost_reply=False`) never yields `settled_committed`
    o1 = explain_outcome_lifecycle(
        {
            "outcome_id": "o1",
            "authoritative_terminal_state": "committed",
            "content_equality_only": True,
        }
    )
    assert o1.settlement_state != "settled_committed"
    assert o1.positive_commit_established is False

    # 2. Failed delivery receipt dict + string `"false"` authorship never establish delivery or authorship
    o2 = explain_outcome_lifecycle(
        {
            "outcome_id": "o2",
            "current_stage": "delivered_to_human",
            "delivery_status": "delivered",
            "answer_grounding": "grounded",
            "authenticated_writer_receipt": "false",
            "delivery_receipt": {
                "status": "failed",
                "delivered": False,
                "reason": "device_offline",
            },
            "transitions": [{"stage": "executed", "state_digest": "sha256:1111"}],
        }
    )
    assert o2.authorship_established is False
    assert o2.positive_delivery_established is False

    # 3. `agent-discordance`: omitted policy/canary -> `unverified`; second clean receipt NEVER erases `DISC-002` leak
    manifest = {
        "routes": [
            {
                "route_id": "r1",
                "agent_id": "agent_a",
                "principal_scope": "owner",
                "continuity_group": "g1",
                "expected_policy_version": "v2",
                "canary_task_id": "t1",
            }
        ]
    }
    rep_missing = evaluate_agent_discordance(
        manifest,
        {
            "observations": [
                {
                    "route_id": "r1",
                    "observed_agent_id": "agent_a",
                    "caller_receipt_id": "c1",
                    "authz_receipt_id": "a1",
                }
            ]
        },
    )
    assert rep_missing.supported_routes == []
    assert rep_missing.unverified_routes == ["r1"]

    rep_dup = evaluate_agent_discordance(
        manifest,
        {
            "observations": [
                {
                    "route_id": "r1",
                    "observed_agent_id": "agent_a",
                    "observed_policy_version": "v2",
                    "caller_receipt_id": "c1",
                    "authz_receipt_id": "a1",
                    "canary_recovered": True,
                    "leaked_context_from_agent": "agent_b",
                },
                {
                    "route_id": "r1",
                    "observed_agent_id": "agent_a",
                    "observed_policy_version": "v2",
                    "caller_receipt_id": "c2",
                    "authz_receipt_id": "a2",
                    "canary_recovered": True,
                },
            ]
        },
    )
    assert rep_dup.supported_routes == []
    assert rep_dup.mismatched_routes == ["r1"]
    assert any(v.rule_code == "DISC-002" for v in rep_dup.violations)


def test_p1_8_and_p2_4_secret_snippets_backtick_ids_session_tokens_sqlite_hash_and_macos_tmp(
    isolated_db_url: str, tmp_path: Path
) -> None:
    assert isolated_db_url.startswith("sqlite:")
    initialize_database()

    # 1. `sess.1` vs `sess_1` never collide
    assert sanitize_session_file_token("sess.1") != sanitize_session_file_token("sess_1")

    # 2. Secret snippet block (`prod.env`, `id_ed25519`) + hallucinated backticked Atlas ID (`t:fake_ghost`)
    repo = tmp_path / "cit_repo"
    (repo / "backend" / "app").mkdir(parents=True)
    (repo / "backend" / "schema.sql").write_text("CREATE TABLE accounts (id INT PRIMARY KEY);\n")
    (repo / "backend" / "app" / "main.py").write_text("from fastapi import FastAPI\napp = FastAPI()\n")
    (repo / "prod.env").write_text("DB_PASSWORD=topsecret\n")
    with get_session_factory()() as session:
        register_target(session, TargetProjectCreate(slug="cit-repo", name="Cit", repo_path=str(repo)))
        tgt = get_target_by_slug(session, "cit-repo")
        assert tgt is not None
        rep = run_target_scan(session, tgt, strict_gate=True, persist_snapshot=False)

    refs = validate_references_against_report(
        ["prod.env:1"],
        rep,
        evidence_revision_id="ev_test",
        answer_markdown="Inspect `t:fake_ghost` and `t:accounts`.",
    )
    by_id = {r.ref_id: r for r in refs}
    assert by_id["prod.env:1"].validation_state == "unresolved"
    assert "blocked" in (by_id["prod.env:1"].note or "").lower()
    assert by_id["t:fake_ghost"].validation_state == "unresolved"
    assert by_id["t:accounts"].validation_state == "validated"

    # 3. SQLite `#`-fragment path enforces read-only (`?mode=ro` + `PRAGMA query_only = ON`)
    hash_db = tmp_path / "tenant#shard.db"
    with sqlite3.connect(str(hash_db)) as conn:
        conn.execute("CREATE TABLE shard_items (id INTEGER PRIMARY KEY)")
    tables, obs = probe_live_catalog_tables(f"sqlite:///{hash_db}")
    assert "shard_items" in tables
    assert obs == "static_ast+sqlite_catalog_readonly"
    assert not (tmp_path / "tenant").exists()

    # 4. `/tmp/...` bundle reads cleanly on macOS without tripping on `/tmp -> private/tmp`
    if sys.platform == "darwin" and Path("/tmp").is_dir():
        tmp_bundle = Path("/tmp") / f"wythe_wave1_tmp_test_{tmp_path.name}.json"
        try:
            tmp_bundle.write_text('{"question": "macOS /tmp canonicalization check"}')
            loaded = read_understanding_bundle_file(tmp_bundle)
            assert loaded["question"] == "macOS /tmp canonicalization check"
        finally:
            tmp_bundle.unlink(missing_ok=True)
