"""Regression tests for v0.2.5 follow-up P1 fixes (F1 dialect-ambiguous SQL redaction & F2 settlement validation)."""

from __future__ import annotations

import json
import sqlite3
import sys
from pathlib import Path
from types import SimpleNamespace

import pytest
from fastapi.testclient import TestClient

from app.main import create_app, initialize_database
from app.schemas.atlas import AtlasEdge, AtlasNode

REPO_ROOT = Path(__file__).resolve().parents[2]
WIRETAP_SRC = REPO_ROOT / "plugins" / "wythe-plugin-wiretap" / "src"


def _correlate_wiretap_companions(*args: object, **kwargs: object) -> dict[str, object]:
    if str(WIRETAP_SRC) not in sys.path:
        sys.path.insert(0, str(WIRETAP_SRC))
    from wythe_plugin_wiretap import correlate_wiretap_companions

    return correlate_wiretap_companions(*args, **kwargs)


def _minimal_atlas_report() -> SimpleNamespace:
    nodes = [
        AtlasNode(
            id="m:svc",
            tier="manipulate",
            subkind="service",
            label="svc",
            source_file="svc.py",
            summary="synthetic service",
        ),
        AtlasNode(
            id="t:items",
            tier="truth",
            subkind="table",
            label="items",
            source_file="schema.sql",
            summary="synthetic table",
        ),
    ]
    edges = [
        AtlasEdge(
            id="e:read",
            source_id="m:svc",
            target_id="t:items",
            kind="reads_truth",
            verification="verified",
            evidence_note="static",
        )
    ]
    return SimpleNamespace(nodes=nodes, edges=edges, chains=[])


@pytest.mark.parametrize(
    "dialect",
    [
        None,
        "",
        "   ",
        "unknown",
        "jdbc",
        "odbc",
        "duckdb",
        "clickhouse",
        "sqlite",
        "sqlite3",
        "mysql",
        "mariadb",
        "postgresql",
        "oracle",
        "mssql",
    ],
)
def test_f1_missing_blank_unknown_and_known_dialects_redact_double_quoted_literals(
    tmp_path: Path,
    dialect: str | None,
) -> None:
    """Ensure `SELECT \"<literal>\" FROM items` leaves 0 literal chars across all dialects."""
    marker = "SYNTHETIC_PRIVATE_VALUE_4521"
    sql = f'SELECT "{marker}" FROM items'
    mem_db = sqlite3.connect(":memory:")
    mem_db.executescript("CREATE TABLE items(id INTEGER); INSERT INTO items VALUES (1);")
    assert mem_db.execute(sql).fetchone()[0] == marker
    mem_db.close()

    report = _minimal_atlas_report()
    attrs: list[dict[str, object]] = [{"key": "db.statement", "value": {"stringValue": sql}}]
    if dialect is not None:
        attrs.append({"key": "db.system", "value": {"stringValue": dialect}})

    otel_capture = tmp_path / f"otel_{(dialect or 'omitted').strip() or 'blank'}.json"
    otel_capture.write_text(
        json.dumps(
            {
                "resourceSpans": [
                    {
                        "resource": {
                            "attributes": [{"key": "service.name", "value": {"stringValue": "svc"}}]
                        },
                        "scopeSpans": [{"spans": [{"name": "query", "attributes": attrs}]}],
                    }
                ]
            }
        ),
        encoding="utf-8",
    )

    ebpf_capture = tmp_path / "ebpf_missing_dialect.jsonl"
    ebpf_rec: dict[str, object] = {"service_name": "svc", "l7": {"sql": {"sql": sql}}}
    if dialect is not None:
        ebpf_rec["db.system"] = dialect
    ebpf_capture.write_text(json.dumps(ebpf_rec) + "\n", encoding="utf-8")

    output = _correlate_wiretap_companions(
        tmp_path,
        report,
        otel_traces_path=otel_capture,
        ebpf_flows_path=ebpf_capture,
        probe_local_ports=False,
    )
    serialized = json.dumps(output)
    assert marker not in serialized
    tf = output["traces_and_flows"]
    assert tf["corroborated_edge_count"] == 1
    samples = tf["sample_transitions"]
    assert len(samples) == 2
    assert all(s["db_operation"] == "SELECT" and s["db_table"] == "items" for s in samples)


def test_f1_ambiguous_dialect_quoted_tables_hash_comments_backslash_and_span_name(
    tmp_path: Path,
) -> None:
    """Fail closed on quoted table clauses, `#` comments, & backslash quotes when dialect is ambiguous."""
    report = _minimal_atlas_report()
    otel_capture = tmp_path / "otel_ambiguous_guards.json"
    spans = [
        {
            "name": "dq_table_no_dialect",
            "attributes": [
                {"key": "db.statement", "value": {"stringValue": 'SELECT * FROM "SYNTHETIC_PRIVATE_TBL_1"'}}
            ],
        },
        {
            "name": "bt_table_unknown_dialect",
            "attributes": [
                {"key": "db.system", "value": {"stringValue": "unknown"}},
                {"key": "db.statement", "value": {"stringValue": "SELECT * FROM `SYNTHETIC_PRIVATE_TBL_2`"}},
            ],
        },
        {
            "name": "br_table_jdbc_dialect",
            "attributes": [
                {"key": "db.system", "value": {"stringValue": "jdbc"}},
                {"key": "db.statement", "value": {"stringValue": "SELECT * FROM [SYNTHETIC_PRIVATE_TBL_3]"}},
            ],
        },
        {
            "name": "qual_dq_table_odbc_dialect",
            "attributes": [
                {"key": "db.system", "value": {"stringValue": "odbc"}},
                {
                    "key": "db.statement",
                    "value": {"stringValue": 'SELECT * FROM pub_ns."SYNTHETIC_PRIVATE_TBL_4"'},
                },
            ],
        },
        {
            "name": "hash_comment_no_dialect",
            "attributes": [
                {"key": "db.statement", "value": {"stringValue": "SELECT 1 # SYNTHETIC_HASH_COMMENT_5"}}
            ],
        },
        {
            "name": "hash_comment_after_unquoted_table",
            "attributes": [
                {
                    "key": "db.statement",
                    "value": {"stringValue": "SELECT id FROM items # SYNTHETIC_HASH_COMMENT_6"},
                }
            ],
        },
        {
            "name": "backslash_before_quote_no_dialect",
            "attributes": [
                {
                    "key": "db.statement",
                    "value": {
                        "stringValue": 'SELECT id FROM items WHERE a = \'dir\\\\\' AND b = "SYNTHETIC_BS_VAL_7"'
                    },
                }
            ],
        },
        {
            "name": 'SELECT "SYNTHETIC_SPAN_NAME_VAL_8" FROM items',
            "attributes": [],
        },
        {
            "name": "quoted_explicit_table_attr",
            "attributes": [
                {"key": "db.operation", "value": {"stringValue": "SELECT"}},
                {"key": "db.sql.table", "value": {"stringValue": '"SYNTHETIC_ATTR_TBL_9"'}},
            ],
        },
    ]
    otel_capture.write_text(
        json.dumps(
            {
                "resourceSpans": [
                    {
                        "resource": {
                            "attributes": [{"key": "service.name", "value": {"stringValue": "svc"}}]
                        },
                        "scopeSpans": [{"spans": spans}],
                    }
                ]
            }
        ),
        encoding="utf-8",
    )
    output = _correlate_wiretap_companions(
        tmp_path,
        report,
        otel_traces_path=otel_capture,
        probe_local_ports=False,
    )
    serialized = json.dumps(output)
    for forbidden in (
        "SYNTHETIC_PRIVATE_TBL_1",
        "SYNTHETIC_PRIVATE_TBL_2",
        "SYNTHETIC_PRIVATE_TBL_3",
        "SYNTHETIC_PRIVATE_TBL_4",
        "SYNTHETIC_HASH_COMMENT_5",
        "SYNTHETIC_HASH_COMMENT_6",
        "SYNTHETIC_BS_VAL_7",
        "SYNTHETIC_SPAN_NAME_VAL_8",
        "SYNTHETIC_ATTR_TBL_9",
    ):
        assert forbidden not in serialized

    span_sql_matches = [
        s
        for s in output["traces_and_flows"]["sample_transitions"]
        if s["redacted_summary"] == "SELECT '?' FROM items"
    ]
    assert len(span_sql_matches) == 1
    assert span_sql_matches[0]["db_table"] == "items"


@pytest.mark.parametrize(
    ("case_label", "outcome_payload"),
    [
        (
            "producer_label_only",
            {
                "current_stage": "executed",
                "transport_timeout_or_lost_reply": True,
                "authoritative_terminal_state": "committed",
                "settlement_producer": "writer-a",
            },
        ),
        (
            "receipt_status_not_found_no_id",
            {
                "current_stage": "executed",
                "transport_timeout_or_lost_reply": True,
                "authoritative_terminal_state": "committed",
                "settlement_receipt": {"status": "not_found"},
            },
        ),
        (
            "old_settled_at_timestamp_only",
            {
                "current_stage": "executed",
                "transport_timeout_or_lost_reply": True,
                "authoritative_terminal_state": "committed",
                "settled_at": "2020-01-01T00:00:00Z",
            },
        ),
        (
            "receipt_with_id_and_link_but_not_found",
            {
                "request_id": "req-1",
                "transport_timeout_or_lost_reply": True,
                "authoritative_terminal_state": "committed",
                "settlement_receipt": {"receipt_id": "r1", "request_id": "req-1", "status": "not_found"},
            },
        ),
        (
            "receipt_with_id_and_link_but_found_false",
            {
                "request_id": "req-1",
                "transport_timeout_or_lost_reply": True,
                "authoritative_terminal_state": "committed",
                "settlement_receipt": {
                    "receipt_id": "r1",
                    "request_id": "req-1",
                    "status": "committed",
                    "found": False,
                },
            },
        ),
        (
            "receipt_with_id_and_link_but_unavailable",
            {
                "request_id": "req-1",
                "transport_timeout_or_lost_reply": True,
                "authoritative_terminal_state": "committed",
                "settlement_receipt": {"receipt_id": "r1", "request_id": "req-1", "status": "unavailable"},
            },
        ),
        (
            "receipt_with_id_and_link_but_failed",
            {
                "request_id": "req-1",
                "transport_timeout_or_lost_reply": True,
                "authoritative_terminal_state": "committed",
                "settlement_receipt": {"receipt_id": "r1", "request_id": "req-1", "status": "failed"},
            },
        ),
        (
            "nested_settlement_evidence_unavailable",
            {
                "transport_timeout_or_lost_reply": True,
                "authoritative_terminal_state": "committed",
                "settlement_receipt_id": "r-nested-1",
                "settlement_evidence": {"receipt": {"status": "unavailable"}},
                "transitions": [
                    {"stage": "executed", "state_digest": "vec-1"},
                    {
                        "stage": "authoritatively_settled",
                        "predecessor_state_digest": "vec-1",
                        "state_digest": "vec-2",
                    },
                ],
            },
        ),
        (
            "bare_unlinked_settlement_receipt_id",
            {
                "request_id": "req-1",
                "transport_timeout_or_lost_reply": True,
                "authoritative_terminal_state": "committed",
                "settlement_receipt_id": "r-unlinked",
            },
        ),
        (
            "mismatched_request_id",
            {
                "request_id": "req-alpha",
                "transport_timeout_or_lost_reply": True,
                "authoritative_terminal_state": "committed",
                "settlement_receipt": {
                    "receipt_id": "r1",
                    "status": "committed",
                    "request_id": "req-beta",
                },
            },
        ),
        (
            "mismatched_attempt_id",
            {
                "request_id": "req-1",
                "attempt_id": "att-1",
                "transport_timeout_or_lost_reply": True,
                "authoritative_terminal_state": "committed",
                "settlement_receipt": {
                    "receipt_id": "r1",
                    "status": "committed",
                    "request_id": "req-1",
                    "attempt_id": "att-2",
                },
            },
        ),
        (
            "mismatched_operation_id",
            {
                "operation_id": "op-1",
                "transport_timeout_or_lost_reply": True,
                "authoritative_terminal_state": "committed",
                "settlement_receipt": {
                    "receipt_id": "r1",
                    "status": "committed",
                    "operation_id": "op-2",
                },
            },
        ),
        (
            "bare_authenticated_writer_receipt",
            {
                "current_stage": "executed",
                "transport_timeout_or_lost_reply": True,
                "authoritative_terminal_state": "committed",
                "authenticated_writer_receipt": True,
            },
        ),
        (
            "placeholder_not_found_receipt_id",
            {
                "request_id": "req-1",
                "transport_timeout_or_lost_reply": True,
                "authoritative_terminal_state": "committed",
                "settlement_receipt": {
                    "receipt_id": "not_found",
                    "status": "committed",
                    "request_id": "req-1",
                },
            },
        ),
        (
            "pre_loss_grant_receipt_before_timeout",
            {
                "current_stage": "executed",
                "authoritative_terminal_state": "committed",
                "operation_id": "op-1",
                "transitions": [
                    {
                        "stage": "granted_not_executed",
                        "operation_id": "op-1",
                        "receipt": {
                            "receipt_id": "grant-1",
                            "status": "accepted",
                            "operation_id": "op-1",
                        },
                    },
                    {
                        "stage": "committed_unacknowledged",
                        "transport_timeout_or_lost_reply": True,
                        "operation_id": "op-1",
                    },
                ],
            },
        ),
        (
            "lost_step_own_receipt",
            {
                "current_stage": "executed",
                "authoritative_terminal_state": "committed",
                "operation_id": "op-1",
                "transitions": [
                    {
                        "stage": "executed",
                        "transport_timeout_or_lost_reply": True,
                        "operation_id": "op-1",
                        "receipt": {
                            "receipt_id": "exec-1",
                            "status": "accepted",
                            "operation_id": "op-1",
                        },
                    }
                ],
            },
        ),
        (
            "digest_plus_lookup_not_found",
            {
                "operation_id": "op-1",
                "transport_timeout_or_lost_reply": True,
                "authoritative_terminal_state": "committed",
                "settlement_receipt": {
                    "receipt_id": "r-1",
                    "operation_id": "op-1",
                    "state_digest": "dig-1",
                    "lookup": "not_found",
                },
            },
        ),
        (
            "digest_plus_error_unavailable",
            {
                "operation_id": "op-1",
                "transport_timeout_or_lost_reply": True,
                "authoritative_terminal_state": "committed",
                "settlement_receipt": {
                    "receipt_id": "r-1",
                    "operation_id": "op-1",
                    "settlement_digest": "dig-1",
                    "error_code": "unavailable",
                },
            },
        ),
        (
            "state_digest_only_no_status",
            {
                "operation_id": "op-1",
                "transport_timeout_or_lost_reply": True,
                "authoritative_terminal_state": "committed",
                "settlement_receipt": {
                    "receipt_id": "r-1",
                    "operation_id": "op-1",
                    "state_digest": "dig-1",
                },
            },
        ),
        (
            "unchanged_state_digest_eq_pre_loss_no_status",
            {
                "operation_id": "op-1",
                "pre_loss_state_digest": "dig-same",
                "transport_timeout_or_lost_reply": True,
                "authoritative_terminal_state": "committed",
                "settlement_receipt": {
                    "receipt_id": "r-1",
                    "operation_id": "op-1",
                    "predecessor_state_digest": "dig-same",
                    "state_digest": "dig-same",
                },
            },
        ),
        (
            "unchanged_state_digest_eq_pre_loss_even_with_committed_status",
            {
                "operation_id": "op-1",
                "pre_loss_state_digest": "dig-same",
                "transport_timeout_or_lost_reply": True,
                "authoritative_terminal_state": "committed",
                "settlement_receipt": {
                    "receipt_id": "r-1",
                    "status": "committed",
                    "operation_id": "op-1",
                    "predecessor_state_digest": "dig-same",
                    "state_digest": "dig-same",
                },
            },
        ),
        (
            "top_level_generic_receipt_not_settlement",
            {
                "current_stage": "executed",
                "operation_id": "op-1",
                "transport_timeout_or_lost_reply": True,
                "authoritative_terminal_state": "committed",
                "receipt": {
                    "receipt_id": "exec-1",
                    "status": "accepted",
                    "operation_id": "op-1",
                },
            },
        ),
    ],
)
def test_f2_descriptive_negative_and_unlinked_settlement_payloads_fail_closed(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    case_label: str,
    outcome_payload: dict[str, object],
) -> None:
    """Verify non-settlement metadata, negative statuses, & unlinked/mismatched receipts never clear lost_reply."""
    monkeypatch.setenv("WYTHE_STATE_DIR", str(tmp_path / f"state_{case_label}"))
    monkeypatch.setenv("WYTHE_DATABASE_URL", f"sqlite:///{tmp_path / f'{case_label}.db'}")
    initialize_database()

    with TestClient(create_app()) as client:
        resp = client.post(
            "/api/v1/understanding/analyze",
            json={"bundle": {"outcomes": [outcome_payload]}},
        )
        assert resp.status_code == 200, resp.text
        body = resp.json()

    out = body["outcome_lifecycles"][0]
    assert out["current_stage"] == "committed_unacknowledged", case_label
    assert out["settlement_state"] == "indeterminate_requires_settlement", case_label
    assert out["blind_retry_prohibited"] is True, case_label
    links = {lnk["link_key"]: lnk for lnk in body["links"]}
    assert links["committed_result"]["state"] == "unresolved", case_label
    assert "blind write retries are prohibited" in body["consequence_headline"].lower()


def test_f2_positive_linked_structured_receipt_and_transition_controls(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Verify positive settlement with valid receipt ID, settled status, and concrete linkage resolves."""
    monkeypatch.setenv("WYTHE_STATE_DIR", str(tmp_path / "state_pos"))
    monkeypatch.setenv("WYTHE_DATABASE_URL", f"sqlite:///{tmp_path / 'f2_pos.db'}")
    initialize_database()

    with TestClient(create_app()) as client:
        committed_resp = client.post(
            "/api/v1/understanding/analyze",
            json={
                "bundle": {
                    "outcomes": [
                        {
                            "outcome_id": "write-op-100",
                            "operation_id": "op-100",
                            "request_id": "req-100",
                            "current_stage": "executed",
                            "transport_timeout_or_lost_reply": True,
                            "authoritative_terminal_state": "committed",
                            "settlement_receipt": {
                                "receipt_id": "lock-rcpt-100",
                                "status": "committed",
                                "operation_id": "op-100",
                                "request_id": "req-100",
                                "settlement_digest": "dig-after-100",
                            },
                        }
                    ]
                }
            },
        )
        assert committed_resp.status_code == 200, committed_resp.text
        comm_body = committed_resp.json()
        comm_out = comm_body["outcome_lifecycles"][0]
        assert comm_out["current_stage"] == "authoritatively_settled"
        assert comm_out["settlement_state"] == "settled_committed"
        assert comm_out["blind_retry_prohibited"] is False
        comm_links = {lnk["link_key"]: lnk for lnk in comm_body["links"]}
        assert comm_links["committed_result"]["state"] == "supported"

        aborted_resp = client.post(
            "/api/v1/understanding/analyze",
            json={
                "bundle": {
                    "outcomes": [
                        {
                            "outcome_id": "write-op-101",
                            "attempt_id": "att-101",
                            "current_stage": "executed",
                            "transport_timeout_or_lost_reply": True,
                            "authoritative_terminal_state": "rolled_back",
                            "reconciliation_receipt": {
                                "lock_id": "pub-lock-101",
                                "status": "rolled_back",
                                "attempt_id": "att-101",
                            },
                        }
                    ]
                }
            },
        )
        assert aborted_resp.status_code == 200, aborted_resp.text
        ab_body = aborted_resp.json()
        ab_out = ab_body["outcome_lifecycles"][0]
        assert ab_out["current_stage"] == "authoritatively_settled"
        assert ab_out["settlement_state"] == "settled_aborted"
        assert ab_out["blind_retry_prohibited"] is False
