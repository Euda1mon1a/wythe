"""FastAPI endpoint and CLI exit-code integration tests."""

from __future__ import annotations

from pathlib import Path

from fastapi.testclient import TestClient

from app.cli import main as cli_main
from app.main import create_app


def test_http_api_surface_end_to_end(isolated_db_url: str) -> None:
    """Exercise targets, adapters, scans, history, rules, and rulings over FastAPI TestClient."""
    assert isolated_db_url.startswith("sqlite:")
    app = create_app()
    with TestClient(app) as client:
        health = client.get("/healthz")
        assert health.status_code == 200
        assert health.json() == {"status": "ok"}

        slots = client.get("/api/v1/adapters/slots")
        assert slots.status_code == 200
        slots_by_name = {s["name"]: s["implementation_status"] for s in slots.json()}
        assert slots_by_name["postgres-sqlalchemy"] == "implemented"
        assert slots_by_name["python-fastapi"] == "implemented"
        assert slots_by_name["typescript-nextjs"] == "implemented"
        assert slots_by_name["prisma-schema"] == "experimental"
        assert slots_by_name["go-http"] == "experimental"
        assert slots_by_name["rust-wasm"] == "experimental"
        assert slots_by_name["swift-vapor"] == "planned"

        profiles = client.get("/api/v1/adapters/profiles")
        assert profiles.status_code == 200
        profiles_by_slug = {p["slug"]: p for p in profiles.json()}
        assert profiles_by_slug["fastapi-sqlalchemy-nextjs"]["implementation_status"] == "implemented"
        assert profiles_by_slug["fastapi-sqlalchemy-nextjs"]["is_enabled"] is True
        assert profiles_by_slug["nextjs-prisma"]["implementation_status"] == "experimental"
        assert profiles_by_slug["rust-fullstack-wasm"]["implementation_status"] == "experimental"
        assert profiles_by_slug["postgres-swift-swiftui"]["implementation_status"] == "planned"
        exp_count = sum(
            1 for p in profiles.json() if p["implementation_status"] == "experimental"
        )
        assert exp_count == 17
        assert profiles_by_slug["python-services"]["implementation_status"] == "experimental"

        targets = client.get("/api/v1/targets")
        assert targets.status_code == 200
        assert any(t["slug"] == "wythe" for t in targets.json())

        scan_resp = client.get("/api/v1/scans/wythe")
        assert scan_resp.status_code == 200
        body = scan_resp.json()
        assert body["gate"]["verdict"] == "PASS"
        assert body["summary"]["truth_tables"] == 7
        assert len(body["chains"]) >= 20

        diff_resp = client.get("/api/v1/scans/wythe/diff?base_ref=HEAD")
        assert diff_resp.status_code == 200
        assert diff_resp.json()["diff_verdict"] in ("PASS", "FAIL")

        sarif_resp = client.get("/api/v1/scans/wythe/sarif")
        assert sarif_resp.status_code == 200
        assert sarif_resp.json()["version"] == "2.1.0"

        src_resp = client.get(
            "/api/v1/scans/wythe/source",
            params={"rel_path": "backend/app/main.py", "line": 15, "context": 5},
        )
        assert src_resp.status_code == 200
        src_body = src_resp.json()
        assert src_body["focus_line"] == 15
        assert src_body["language"] == "python"
        assert any(row["is_focus"] for row in src_body["lines"])

        traversal_resp = client.get(
            "/api/v1/scans/wythe/source",
            params={"rel_path": "../../etc/passwd", "line": 1},
        )
        assert traversal_resp.status_code == 403

        secret_resp = client.get(
            "/api/v1/scans/wythe/source",
            params={"rel_path": ".env", "line": 1},
        )
        assert secret_resp.status_code == 403

        bundle_resp = client.get("/api/v1/targets/wythe/governance-bundle")
        assert bundle_resp.status_code == 200
        assert len(bundle_resp.json()["vocabularies"]) >= 29

        vocabs_resp = client.get("/api/v1/vocabularies")
        assert vocabs_resp.status_code == 200
        assert len(vocabs_resp.json()) >= 29

        seal_resp = client.post("/api/v1/scans/wythe")
        assert seal_resp.status_code == 200
        first_snap_id = seal_resp.json()["snapshot_id"]
        assert first_snap_id is not None

        seal_resp_2 = client.post("/api/v1/scans/wythe")
        assert seal_resp_2.status_code == 200
        second_snap_id = seal_resp_2.json()["snapshot_id"]
        assert second_snap_id is not None

        compare_resp = client.get(
            f"/api/v1/scans/wythe/compare?base_id={first_snap_id}&head_id={second_snap_id}"
        )
        assert compare_resp.status_code == 200
        assert compare_resp.json()["added_nodes"] == []
        assert compare_resp.json()["edge_delta"] == 0

        history = client.get("/api/v1/scans/wythe/history")
        assert history.status_code == 200
        assert len(history.json()) >= 2

        rules = client.get("/api/v1/rules")
        assert rules.status_code == 200
        assert len(rules.json()) == 17

        patch_rule = client.patch(
            "/api/v1/rules/TRUTH-001",
            json={"severity": "info", "updated_by": "api-test"},
        )
        assert patch_rule.status_code == 200
        assert patch_rule.json()["severity"] == "info"

        create_ruling = client.post(
            "/api/v1/rulings/wythe",
            json={
                "node_id": "t:table:atlas_rule_policies",
                "disposition": "accepted_clean",
                "summary": "Authoritative policy catalog table.",
                "cutover_history": None,
                "recorded_by": "api-test",
            },
        )
        assert create_ruling.status_code == 201

        rulings = client.get("/api/v1/rulings/wythe")
        assert rulings.status_code == 200
        assert len(rulings.json()) == 1


def test_cli_exit_codes_pass_fail_and_missing_target(
    isolated_db_url: str, tmp_path: Path
) -> None:
    """Verify CLI gate returns 0 on clean pass, 1 on strict boundary violation, and 2 on missing target."""
    assert isolated_db_url.startswith("sqlite:")

    # 0: Self-dogfood strict gate passes.
    assert cli_main(["gate", "--strict", "wythe"]) == 0

    # 2: Non-existent slug/directory fails closed with operational exit code 2.
    assert cli_main(["gate", "nonexistent-target-slug-xyz"]) == 2

    # 1: Ad-hoc directory with unbacked frontend endpoint fails strict gate with exit code 1.
    bad_repo = tmp_path / "bad_cli_repo"
    (bad_repo / "backend" / "app").mkdir(parents=True)
    (bad_repo / "frontend" / "src" / "app").mkdir(parents=True)
    (bad_repo / "backend" / "app" / "main.py").write_text(
        "from fastapi import FastAPI\napp = FastAPI()\n", encoding="utf-8"
    )
    (bad_repo / "frontend" / "src" / "app" / "page.tsx").write_text(
        "export default function P() { fetch('/api/v1/ghost'); return null; }\n",
        encoding="utf-8",
    )
    assert cli_main(["gate", "--strict", str(bad_repo)]) == 1
