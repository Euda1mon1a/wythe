"""P0 regressions: Wiretap F5 caller attribution (#105), F3 citations (#103), and F12/F13 cache invariants."""

from __future__ import annotations

import json
import os
from pathlib import Path
from types import SimpleNamespace

import pytest
from fastapi.testclient import TestClient
from sqlalchemy.orm import Session
from test_seat_selection_ux_and_cache import _write_barrel_reexport_repo
from test_wave5_shared_investigation import (
    TINY_PNG_A,
    TINY_WEBP_B,
    _register_repo,
    _write_synthetic_policy_repo,
)

import app as app_pkg
from app.adapters.plugin_registry import stratum_artifacts_scope
from app.main import create_app
from app.schemas.atlas import AtlasEdge, AtlasNode
from app.services import investigation_service
from app.services.governance_service import get_target_by_slug
from app.services.investigation_service import (
    build_evidence_identity,
    clear_scan_reuse_cache,
    get_or_run_cached_scan,
    validate_references_against_report,
)
from app.services.scanner_service import run_target_scan
from wythe_plugin_wiretap.otel_ebpf import correlate_traces_and_flows, parse_otel_traces
from wythe_plugin_wiretap.plugin import correlate_wiretap_companions


def _make_node(nid: str, tier: str, subkind: str, label: str, **extra: object) -> AtlasNode:
    return AtlasNode(
        id=nid,
        tier=tier,  # type: ignore[arg-type]
        subkind=subkind,  # type: ignore[arg-type]
        label=label,
        source_file=str(extra.pop("source_file", f"{label}.py")),
        summary="synthetic fixture",
        **extra,  # type: ignore[arg-type]
    )


def test_f5_endpoint_only_and_unrelated_sql_spans_never_credit_unproven_callers(
    tmp_path: Path,
) -> None:
    """Verify F5 (#105): unattributed/unrelated spans record `node_hits`==1 and 0 corroborated edges."""
    repo = _write_synthetic_policy_repo(tmp_path / "f5-repo", init_git=False)
    nodes = [
        _make_node("d:a", "display", "page", "page_a"),
        _make_node("d:b", "display", "page", "page_b"),
        _make_node(
            "m:route",
            "manipulate",
            "route",
            "route",
            http_paths=["/api/v1/items"],
            http_methods=["GET"],
        ),
        _make_node("m:a", "manipulate", "service", "service_a"),
        _make_node("m:b", "manipulate", "service", "service_b"),
        _make_node("t:items", "truth", "table", "items"),
    ]
    edges = [
        AtlasEdge(
            id=f"e:{caller}->route",
            source_id=caller,
            target_id="m:route",
            kind="queries_endpoint",
            verification="verified",
            evidence_note="static",
        )
        for caller in ("d:a", "d:b")
    ] + [
        AtlasEdge(
            id=f"e:{caller}->items",
            source_id=caller,
            target_id="t:items",
            kind="reads_truth",
            verification="verified",
            evidence_note="static",
            symbol_links=[f"read_from_{caller.split(':')[1]}->*"],
        )
        for caller in ("m:a", "m:b")
    ]
    report = SimpleNamespace(nodes=nodes, edges=edges, chains=[])

    def _run_single_span(span_name: str, kind_val: int | str, attrs: dict[str, str]) -> dict[str, object]:
        otel_path = tmp_path / f"{span_name}.json"
        otel_path.write_text(
            json.dumps(
                {
                    "resourceSpans": [
                        {
                            "resource": {
                                "attributes": [
                                    {"key": "service.name", "value": {"stringValue": "unrelated_service"}}
                                ]
                            },
                            "scopeSpans": [
                                {
                                    "spans": [
                                        {
                                            "name": span_name,
                                            "traceId": "0123456789abcdef0123456789abcdef",
                                            "spanId": "0123456789abcdef",
                                            "kind": kind_val,
                                            "attributes": [
                                                {"key": k, "value": {"stringValue": v}}
                                                for k, v in attrs.items()
                                            ],
                                        }
                                    ]
                                }
                            ],
                        }
                    ]
                }
            ),
            encoding="utf-8",
        )
        trs, _ = parse_otel_traces(otel_path)
        comp = correlate_wiretap_companions(repo, report, otel_traces_path=otel_path, probe_local_ports=False)
        assert comp["traces_and_flows"]["corroborated_edge_count"] == 0  # type: ignore[index]
        return correlate_traces_and_flows(report, trs)

    http_res = _run_single_span("single_server_span", 2, {"http.method": "GET", "http.route": "/api/v1/items"})
    assert http_res["corroborated_edge_count"] == 0
    assert http_res["node_hit_counts"] == {"m:route": 1}

    sql_res = _run_single_span(
        "unrelated_sql_span", 3, {"db.system": "postgresql", "db.statement": "SELECT id FROM items"}
    )
    assert sql_res["corroborated_edge_count"] == 0
    assert sql_res["node_hit_counts"] == {"t:items": 1}

    # Positive parent-child trace & code.filepath attribution credits ONLY the true caller edge!
    linked_path = tmp_path / "linked_trace.json"
    linked_path.write_text(
        json.dumps(
            {
                "spans": [
                    {
                        "name": "fetch items",
                        "traceId": "aaaa1111bbbb2222cccc3333dddd4444",
                        "spanId": "1111222233334444",
                        "kind": "SPAN_KIND_CLIENT",
                        "service_name": "page_a",
                        "attributes": {"http.method": "GET", "http.route": "/api/v1/items"},
                    },
                    {
                        "name": "GET /api/v1/items",
                        "traceId": "aaaa1111bbbb2222cccc3333dddd4444",
                        "spanId": "5555666677778888",
                        "parentSpanId": "1111222233334444",
                        "kind": 2,
                        "service_name": "items_backend",
                        "attributes": {"http.method": "GET", "http.route": "/api/v1/items"},
                    },
                    {
                        "name": "SELECT items",
                        "traceId": "aaaa1111bbbb2222cccc3333dddd4444",
                        "spanId": "9999aaaabbbbcccc",
                        "parentSpanId": "5555666677778888",
                        "kind": 3,
                        "service_name": "items_backend",
                        "attributes": {
                            "db.system": "postgresql",
                            "db.statement": "SELECT id FROM items",
                            "code.filepath": "service_a.py",
                            "code.function": "read_from_a",
                        },
                    },
                ]
            }
        ),
        encoding="utf-8",
    )
    linked_trs, _ = parse_otel_traces(linked_path)
    assert linked_trs[0].span_kind == "CLIENT"
    assert linked_trs[1].span_kind == "SERVER"
    assert linked_trs[1].parent_span_id == "1111222233334444"
    linked_res = correlate_traces_and_flows(report, linked_trs)
    credited_ids = {e["edge_id"] for e in linked_res["corroborated_edges"]}  # type: ignore[index]
    assert credited_ids == {"e:d:a->route", "e:m:a->items"}


def test_f3_snippet_bounds_staleness_and_scoped_capture_wiretap_validation(
    isolated_db_url: str,
    db_session: Session,
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Verify F3 (#103): reject fabricated/cross-session/out-of-bounds/stale citations; validate real ones."""
    assert isolated_db_url.startswith("sqlite:")
    state_dir = tmp_path / "f3-state"
    state_dir.mkdir()
    monkeypatch.setenv("WYTHE_STATE_DIR", str(state_dir))

    repo_a = _write_synthetic_policy_repo(tmp_path / "repo-a", init_git=True)
    repo_b = _write_synthetic_policy_repo(tmp_path / "repo-b", init_git=True)
    (repo_a / "backend" / "app" / "empty_mod.py").write_text("", encoding="utf-8")
    os.symlink(repo_a / "backend" / "app" / "main.py", repo_a / "backend" / "app" / "sym_main.py")

    app = create_app()
    with TestClient(app) as client:
        _register_repo(client, "audit-a", repo_a)
        _register_repo(client, "audit-b", repo_b)

        for sid in ("session-a", "session-b"):
            assert client.post(
                "/api/v1/investigations",
                json={"target_slug": "audit-a", "session_id": sid, "client_id": f"{sid}-browser"},
            ).status_code == 200
        assert client.post(
            "/api/v1/investigations",
            json={"target_slug": "audit-b", "session_id": "session-other", "client_id": "other-browser"},
        ).status_code == 200

        ack_a = client.post(
            "/api/v1/ui-focus",
            json={
                "active_slug": "audit-a",
                "session_id": "session-a",
                "client_id": "session-a-browser",
                "selected_node_id": "t:quota_policies",
                "camera_revision": 1,
                "snapshot_data_url": TINY_PNG_A,
            },
        ).json()
        ack_b = client.post(
            "/api/v1/ui-focus",
            json={
                "active_slug": "audit-a",
                "session_id": "session-b",
                "client_id": "session-b-browser",
                "selected_node_id": "m:service:quota_service",
                "camera_revision": 1,
                "snapshot_data_url": TINY_WEBP_B,
            },
        ).json()
        snap_a_name = Path(ack_a["snapshot_path"]).name
        snap_b_name = Path(ack_b["snapshot_path"]).name

        turn_res = client.post(
            "/api/v1/investigations/session-a/turns",
            json={
                "question": "What evidence supports this?",
                "answer_markdown": "Checking citations.",
                "referenced_ids": [
                    "capture:never-created",
                    "wiretap:never-created",
                    "wt:wiretap:port:99:9999",
                    "z3:m:route:main:port:99:9999",
                    "backend/app/main.py:0",
                    "backend/app/main.py:999999",
                    "backend/app/empty_mod.py:1",
                    "backend/app/sym_main.py:1",
                    snap_b_name,
                    f"capture:{snap_b_name}",
                    snap_a_name,
                    f"capture:{snap_a_name}",
                    "backend/app/main.py:1",
                ],
            },
        )
        assert turn_res.status_code == 200, turn_res.text
        refs = {r["ref_id"]: r for r in turn_res.json()["validated_references"]}

        for bad_id in (
            "capture:never-created",
            "wiretap:never-created",
            "wt:wiretap:port:99:9999",
            "z3:m:route:main:port:99:9999",
            "backend/app/main.py:0",
            "backend/app/main.py:999999",
            "backend/app/empty_mod.py:1",
            "backend/app/sym_main.py:1",
            snap_b_name,
            f"capture:{snap_b_name}",
        ):
            assert refs[bad_id]["validation_state"] == "unresolved", f"{bad_id} -> {refs[bad_id]}"
            assert refs[bad_id]["epistemic_kind"] == "static_inference", f"{bad_id} -> {refs[bad_id]}"

        assert refs[snap_a_name]["validation_state"] == "validated"
        assert refs[snap_a_name]["epistemic_kind"] == "runtime_capture"
        assert refs[f"capture:{snap_a_name}"]["validation_state"] == "validated"
        assert refs["backend/app/main.py:1"]["validation_state"] == "validated"
        assert refs["backend/app/main.py:1"]["epistemic_kind"] == "observation"

    # Cross-target capture reuse & stale report snippet rejection
    target_a = get_target_by_slug(db_session, "audit-a")
    target_b = get_target_by_slug(db_session, "audit-b")
    assert target_a is not None and target_b is not None
    rep_a = get_or_run_cached_scan(db_session, target_a)
    ev_a = build_evidence_identity(rep_a)
    rep_b = get_or_run_cached_scan(db_session, target_b)
    ev_b = build_evidence_identity(rep_b)

    cross_target_refs = validate_references_against_report(
        [snap_a_name],
        rep_b,
        evidence_revision_id=ev_b.evidence_revision_id,
        target_slug="audit-b",
        session_id="session-a",
    )
    assert cross_target_refs[0].validation_state == "unresolved"
    assert cross_target_refs[0].epistemic_kind == "static_inference"

    # Mutate `main.py` on disk without rescanning `rep_a` -> `rep_a` is now stale vs worktree!
    (repo_a / "backend" / "app" / "main.py").write_text(
        (repo_a / "backend" / "app" / "main.py").read_text(encoding="utf-8") + "\n# mutated after scan\n",
        encoding="utf-8",
    )
    stale_snip = validate_references_against_report(
        ["backend/app/main.py:1"],
        rep_a,
        evidence_revision_id=ev_a.evidence_revision_id,
        target_slug="audit-a",
        session_id="session-a",
    )
    assert stale_snip[0].validation_state == "unresolved"
    assert stale_snip[0].epistemic_kind == "static_inference"
    assert stale_snip[0].note

    # Active wiretap artifacts resolve real IDs and still reject fabricated `wiretap:never-created`
    (repo_b / "compose.yaml").write_text(
        "services:\n  api:\n    ports:\n      - '127.0.0.1:8780:8780'\n", encoding="utf-8"
    )
    otel_f = tmp_path / "otel.json"
    otel_f.write_text('{"spans": [{"name": "GET /api/v1/quotas", "attributes": {"http.route": "/api/v1/quotas"}}]}', encoding="utf-8")
    lis_f = tmp_path / "listeners.json"
    lis_f.write_text('[{"protocol": "tcp", "bind_address": "0.0.0.0", "port": 8780, "command": "api", "pid": 10}]', encoding="utf-8")
    with stratum_artifacts_scope(otel_traces=str(otel_f), port_listeners=str(lis_f)):
        rep_wt = get_or_run_cached_scan(db_session, target_b, force_rescan=True)
        ev_wt = build_evidence_identity(rep_wt)
        wt_refs = {
            r.ref_id: r
            for r in validate_references_against_report(
                [
                    "wiretap:otel_traces",
                    "wt:wiretap:port:1:8780",
                    "z3:m:compose:compose.yaml:api:port:1:8780",
                    "wiretap:never-created",
                    "z3:m:compose:compose.yaml:api:port:1:9999",
                ],
                rep_wt,
                evidence_revision_id=ev_wt.evidence_revision_id,
                target_slug="audit-b",
            )
        }
        assert wt_refs["wiretap:otel_traces"].validation_state == "validated"
        assert wt_refs["wt:wiretap:port:1:8780"].validation_state == "validated"
        assert wt_refs["z3:m:compose:compose.yaml:api:port:1:8780"].validation_state == "validated"
        assert wt_refs["wiretap:never-created"].validation_state == "unresolved"
        assert wt_refs["z3:m:compose:compose.yaml:api:port:1:9999"].validation_state == "unresolved"


def test_f12_versioned_analyzer_contract_and_unstamped_legacy_rescan(
    isolated_db_url: str,
    db_session: Session,
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Verify F12: analyzer contract binds version/core/plugins and unstamped or upgraded snapshots rescan."""
    assert isolated_db_url.startswith("sqlite:")
    state_dir = tmp_path / "f12-state"
    state_dir.mkdir()
    monkeypatch.setenv("WYTHE_STATE_DIR", str(state_dir))
    repo_dir = _write_barrel_reexport_repo(tmp_path / "f12-repo")

    sig = investigation_service._compute_analyzer_contract_signature(repo_root=repo_dir)
    assert sig[0] == app_pkg.__version__
    assert isinstance(sig[1], str) and len(sig[1]) == 64
    assert isinstance(sig[2], tuple)
    assert sig[3] is False
    assert sig[4] == ()

    app = create_app()
    with TestClient(app) as client:
        assert client.post(
            "/api/v1/targets",
            json={"slug": "f12-lab", "name": "F12 Lab", "repo_path": str(repo_dir)},
        ).status_code in (200, 201)
        assert client.post("/api/v1/scans/f12-lab").status_code == 200

    target = get_target_by_slug(db_session, "f12-lab")
    assert target is not None

    scan_count = 0
    orig_scan = investigation_service.run_target_scan

    def _counted_scan(*args: object, **kwargs: object) -> object:
        nonlocal scan_count
        scan_count += 1
        return orig_scan(*args, **kwargs)  # type: ignore[arg-type]

    monkeypatch.setattr(investigation_service, "run_target_scan", _counted_scan)

    # 1. Exact matching stamp hydrates cleanly with 0 rescans
    clear_scan_reuse_cache()
    hydrated = get_or_run_cached_scan(db_session, target, strict_gate=True)
    assert hydrated.snapshot_id is not None
    assert scan_count == 0

    # 2. Upgrade / version change invalidates persisted stamp and forces rescan
    clear_scan_reuse_cache()
    monkeypatch.setattr(app_pkg, "__version__", "99.0.0-upgraded")
    upgraded = get_or_run_cached_scan(db_session, target, strict_gate=True)
    assert scan_count == 1
    assert upgraded.content_digest == hydrated.content_digest
    monkeypatch.undo()
    monkeypatch.setenv("WYTHE_STATE_DIR", str(state_dir))
    monkeypatch.setattr(investigation_service, "run_target_scan", _counted_scan)

    # 3. Unstamped legacy snapshot (stamp row absent) MUST rescan rather than hydrating blindly
    conn = investigation_service.open_investigation_connection(create=False)
    assert conn is not None
    try:
        conn.execute("DELETE FROM scan_snapshot_stamps")
    finally:
        conn.close()
    clear_scan_reuse_cache()
    get_or_run_cached_scan(db_session, target, strict_gate=True)
    assert scan_count == 2


def test_f13_pre_scan_input_state_prevents_stale_stamp_race_and_torn_cache(
    isolated_db_url: str,
    db_session: Session,
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Verify F13: mid-scan file changes withhold both SQLite snapshot stamps and `_SCAN_REUSE_CACHE`."""
    assert isolated_db_url.startswith("sqlite:")
    state_dir = tmp_path / "f13-state"
    state_dir.mkdir()
    monkeypatch.setenv("WYTHE_STATE_DIR", str(state_dir))
    repo_dir = _write_barrel_reexport_repo(tmp_path / "f13-repo")

    app = create_app()
    with TestClient(app) as client:
        assert client.post(
            "/api/v1/targets",
            json={"slug": "f13-lab", "name": "F13 Lab", "repo_path": str(repo_dir)},
        ).status_code in (200, 201)

    target = get_target_by_slug(db_session, "f13-lab")
    assert target is not None

    # Reproduce exact `cache-probes.py` stamp race: unlink `unused_calc.py` right before stamp write!
    orig_stamp = investigation_service.record_persisted_snapshot_stamp

    def _delayed_stamp(*args: object, **kwargs: object) -> None:
        (repo_dir / "backend" / "app" / "pkg" / "unused_calc.py").unlink()
        orig_stamp(*args, **kwargs)  # type: ignore[arg-type]

    monkeypatch.setattr(investigation_service, "record_persisted_snapshot_stamp", _delayed_stamp)
    raced_snap = run_target_scan(db_session, target, strict_gate=True, persist_snapshot=True)
    monkeypatch.setattr(investigation_service, "record_persisted_snapshot_stamp", orig_stamp)

    assert any("unused_calc" in n.source_file for n in raced_snap.nodes)
    clear_scan_reuse_cache()
    after_race = get_or_run_cached_scan(db_session, target, strict_gate=True)
    forced_fresh = get_or_run_cached_scan(db_session, target, strict_gate=True, force_rescan=True)
    assert after_race.content_digest == forced_fresh.content_digest != raced_snap.content_digest
    assert not any("unused_calc" in n.source_file for n in after_race.nodes)

    # Also verify mid-scan edit during `get_or_run_cached_scan` withholds `_SCAN_REUSE_CACHE`
    clear_scan_reuse_cache()
    orig_scan = investigation_service.run_target_scan

    def _mutating_scan(*args: object, **kwargs: object) -> object:
        rep = orig_scan(*args, **kwargs)  # type: ignore[arg-type]
        (repo_dir / "backend" / "app" / "extra_after.py").write_text("X = 1\n", encoding="utf-8")
        return rep

    monkeypatch.setattr(investigation_service, "run_target_scan", _mutating_scan)
    get_or_run_cached_scan(db_session, target, strict_gate=True)
    assert len(investigation_service._SCAN_REUSE_CACHE) == 0
