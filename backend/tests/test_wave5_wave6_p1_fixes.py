"""Regression tests for v0.2.3 Wave 5/6 P1 fixes (F1 SQL redaction & F2 lost-reply invariant)."""

from __future__ import annotations

import json
import sys
from pathlib import Path
from types import SimpleNamespace

import pytest
from fastapi.testclient import TestClient

REPO_ROOT = Path(__file__).resolve().parents[2]
WIRETAP_SRC = REPO_ROOT / "plugins" / "wythe-plugin-wiretap" / "src"
if str(WIRETAP_SRC) not in sys.path:
    sys.path.insert(0, str(WIRETAP_SRC))

from app.main import create_app, initialize_database
from app.schemas.atlas import AtlasEdge, AtlasNode
from wythe_plugin_wiretap import (
    _redact_sql_statement,
    correlate_traces_and_flows,
    correlate_wiretap_companions,
    parse_ebpf_flows,
    parse_otel_traces,
    redact_sql_statement,
)


def test_f1_sql_lexical_redactor_dialects_and_fail_closed_guards() -> None:
    """Verify single-pass SQL lexical redaction across PG, MySQL, SQLite, ANSI & fail-closed cases."""
    # 1. PostgreSQL dollar-quoted literals ($$...$$ and $tag$...$tag$) + numeric IN list
    marker = "SYNTHETIC_RECORD_MARKER_7391"
    red_pg, changed_pg = _redact_sql_statement(
        f"SELECT id, col_1 FROM items WHERE name = $tag${marker}$tag$ "
        "AND note = $$dollar_body_secret_441$$ "
        "AND payload = $a_1$inner $$ and $other$ secret_992$a_1$ "
        "AND id IN (987654321, -424242) AND tenant_id = $1",
        db_system="postgresql",
    )
    assert changed_pg is True
    assert "$REDACTED$" in red_pg
    assert "$1" in red_pg
    assert "col_1" in red_pg
    for forbidden in (
        marker,
        "dollar_body_secret_441",
        "secret_992",
        "987654321",
        "424242",
    ):
        assert forbidden not in red_pg

    # 2. Single-quoted & prefixed string/hex/bit/unicode/charset literals
    prefixed_sql = (
        "SELECT id FROM items WHERE a = 'plain_sec_11' "
        "AND b = 'doubled''quote_sec_22' "
        "AND c = E'escaped\\'quote_sec_33' "
        "AND d = N'nat_sec_44' "
        "AND e = X'deadbeef55' "
        "AND f = B'10101100' "
        "AND g = U&'uni_sec_66' "
        "AND h = _utf8mb4'charset_sec_77'"
    )
    red_pref, changed_pref = redact_sql_statement(prefixed_sql)
    assert changed_pref is True
    for forbidden in (
        "plain_sec_11",
        "quote_sec_22",
        "quote_sec_33",
        "nat_sec_44",
        "deadbeef55",
        "10101100",
        "uni_sec_66",
        "charset_sec_77",
    ):
        assert forbidden not in red_pref

    # 3. Comments (-- EOL, /* ... */, nested PG /* /* ... */ */, MySQL #)
    comment_sql = (
        "/* outer_sec_1 /* nested_sec_2 */ trailing_sec_3 */ "
        "SELECT /* inline_sec_4 */ id FROM items -- eol_sec_5\n"
        "WHERE active = TRUE AND archived = FALSE"
    )
    red_cmt, changed_cmt = _redact_sql_statement(comment_sql, db_system="postgresql")
    assert changed_cmt is True
    for forbidden in ("outer_sec_1", "nested_sec_2", "trailing_sec_3", "inline_sec_4", "eol_sec_5", "TRUE", "FALSE"):
        assert forbidden not in red_cmt

    mysql_cmt, _ = _redact_sql_statement(
        'SELECT "dq_select_sec" FROM "items" WHERE "dq_lhs_sec" = name AND name = "dq_rhs_sec" # hash_sec_99',
        db_system="mysql",
    )
    assert '"items"' in mysql_cmt
    for forbidden in ("dq_select_sec", "dq_lhs_sec", "dq_rhs_sec", "hash_sec_99"):
        assert forbidden not in mysql_cmt

    # 4. Multi-row VALUES, LIMIT/OFFSET, BETWEEN, floats, hex, UUID, ARRAY
    numeric_sql = (
        "INSERT INTO [items] (`id`, `label`, `score`, `ratio`, `mask`, `uid`, `arr`) "
        "VALUES (11111, 'tok_a', 99.5, 1.23e-4, 0xdeadbeef, 550e8400-e29b-41d4-a716-446655440000, ARRAY[7654321]), "
        "(22222, 'tok_b', -0.75, 4.5e+6, 0b101101, 'str_uuid', ARRAY[8765432]); "
        "SELECT id FROM items WHERE qty BETWEEN 12345 AND 67890 LIMIT 777 OFFSET 888"
    )
    red_num, _ = _redact_sql_statement(numeric_sql, db_system="sqlite")
    assert "[items]" in red_num and "`id`" in red_num
    for forbidden in (
        "11111",
        "22222",
        "tok_a",
        "tok_b",
        "99.5",
        "1.23",
        "deadbeef",
        "550e8400",
        "446655440000",
        "7654321",
        "8765432",
        "12345",
        "67890",
        "777",
        "888",
    ):
        assert forbidden not in red_num

    # 5. Unclosed, ambiguous, verb-less, control-byte & oversized SQL fail closed
    unclosed_cases = [
        ("SELECT id FROM items WHERE name = $tag$unclosed_sec_a", "SELECT items [sql_statement_omitted_unparsed]"),
        ("SELECT id FROM items WHERE name = $$unclosed_sec_b", "SELECT items [sql_statement_omitted_unparsed]"),
        ("SELECT id FROM items WHERE name = $bad_tag", "SELECT items [sql_statement_omitted_unparsed]"),
        ("SELECT id FROM items WHERE name = 'unclosed_sec_c", "SELECT items [sql_statement_omitted_unparsed]"),
        ("SELECT id FROM items WHERE name = E'unclosed_sec_d\\'", "SELECT items [sql_statement_omitted_unparsed]"),
        ("SELECT id FROM items /* unclosed_sec_e", "SELECT items [sql_statement_omitted_unparsed]"),
        ("SELECT id FROM items /* outer /* inner */ unclosed_sec_f", "SELECT items [sql_statement_omitted_unparsed]"),
        ('SELECT id FROM items WHERE col = "unclosed_sec_g', "SELECT items [sql_statement_omitted_unparsed]"),
        ("SELECT id FROM `unclosed_sec_h", "SELECT [sql_statement_omitted_unparsed]"),
        ("SELECT id FROM [unclosed_sec_i", "SELECT [sql_statement_omitted_unparsed]"),
        ("SELECT id FROM items WHERE id IN (987654321, 55555", "SELECT items [sql_statement_omitted_unparsed]"),
        ("unrecognized_non_sql_secret_9911", "[sql_statement_omitted_unparsed]"),
        ("SELECT id FROM items WHERE x = 'ok'\x00raw_ctrl_sec", "[sql_statement_omitted_unparsed]"),
        ("SELECT id FROM items WHERE pad = '" + ("z" * 70000) + "'", "[sql_statement_omitted_unparsed]"),
    ]
    for bad_sql, expected_omitted in unclosed_cases:
        out_sql, was_red = _redact_sql_statement(bad_sql)
        assert was_red is True
        assert out_sql == expected_omitted
        assert "unclosed_sec" not in out_sql
        assert "987654321" not in out_sql
        assert "9911" not in out_sql


def test_f1_otel_ebpf_and_public_companion_json_retain_zero_sql_literals(tmp_path: Path) -> None:
    """Ensure zero literal values survive across parse_otel_traces, parse_ebpf_flows & companions."""
    nodes = [
        AtlasNode(
            id="m:service_a",
            tier="manipulate",
            subkind="service",
            label="service_a",
            source_file="service_a.py",
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
            id="e:service_a->items:read",
            source_id="m:service_a",
            target_id="t:items",
            kind="reads_truth",
            verification="verified",
            evidence_note="static",
        ),
        AtlasEdge(
            id="e:service_a->items:write",
            source_id="m:service_a",
            target_id="t:items",
            kind="writes_truth",
            verification="verified",
            evidence_note="static",
        ),
    ]
    report = SimpleNamespace(nodes=nodes, edges=edges, chains=[])

    marker = "SYNTHETIC_RECORD_MARKER_7391"
    otel_path = tmp_path / "otel.json"
    otel_path.write_text(
        json.dumps(
            {
                "resourceSpans": [
                    {
                        "resource": {
                            "attributes": [
                                {"key": "service.name", "value": {"stringValue": "service_a"}}
                            ]
                        },
                        "scopeSpans": [
                            {
                                "spans": [
                                    {
                                        "name": "pg_dollar_and_in",
                                        "attributes": [
                                            {"key": "db.system", "value": {"stringValue": "postgresql"}},
                                            {
                                                "key": "db.statement",
                                                "value": {
                                                    "stringValue": (
                                                        "/* FROM leaked_comment_tbl */ SELECT id FROM items "
                                                        f"WHERE name = $tag${marker}$tag$ AND id IN (987654321, -424242)"
                                                    )
                                                },
                                            },
                                        ],
                                    },
                                    {
                                        "name": "mysql_double_quoted",
                                        "attributes": [
                                            {"key": "db.system", "value": {"stringValue": "mysql"}},
                                            {
                                                "key": "db.statement",
                                                "value": {
                                                    "stringValue": (
                                                        'SELECT id FROM items WHERE code = "mysql_dq_secret_551" '
                                                        "LIMIT 777 OFFSET 888"
                                                    )
                                                },
                                            },
                                        ],
                                    },
                                    {
                                        "name": "unclosed_dollar_span",
                                        "attributes": [
                                            {"key": "db.system", "value": {"stringValue": "postgresql"}},
                                            {
                                                "key": "db.statement",
                                                "value": {
                                                    "stringValue": "SELECT id FROM items WHERE raw = $tag$unclosed_span_sec_882"
                                                },
                                            },
                                        ],
                                    },
                                ]
                            }
                        ],
                    }
                ]
            }
        ),
        encoding="utf-8",
    )

    ebpf_path = tmp_path / "ebpf.jsonl"
    ebpf_path.write_text(
        "\n".join(
            [
                json.dumps(
                    {
                        "service_name": "service_a",
                        "l7": {
                            "sql": {
                                "sql": (
                                    "INSERT INTO items (id, name) VALUES "
                                    "(11111, 'ebpf_tok_a'), (22222, 'ebpf_tok_b'), (33333, 'ebpf_tok_c')"
                                )
                            }
                        },
                    }
                ),
                json.dumps(
                    {
                        "service_name": "service_a",
                        "l7": {"sql": {"sql": "SELECT id FROM items -- ebpf_comment_sec_774"}},
                    }
                ),
            ]
        )
        + "\n",
        encoding="utf-8",
    )

    otel_tr, otel_red = parse_otel_traces(otel_path)
    ebpf_tr, ebpf_red = parse_ebpf_flows(ebpf_path)
    assert otel_red >= 3 and ebpf_red >= 2
    assert [(t.db_operation, t.db_table) for t in otel_tr] == [
        ("SELECT", "items"),
        ("SELECT", "items"),
        ("SELECT", "items"),
    ]
    assert [(t.db_operation, t.db_table) for t in ebpf_tr] == [
        ("INSERT", "items"),
        ("SELECT", "items"),
    ]

    corr = correlate_traces_and_flows(report, [*otel_tr, *ebpf_tr])
    assert corr["corroborated_edge_count"] == 2
    companion = correlate_wiretap_companions(
        tmp_path,
        report,
        otel_traces_path=otel_path,
        ebpf_flows_path=ebpf_path,
        probe_local_ports=False,
    )
    serialized = json.dumps({"corr": corr, "companion": companion})
    for secret_tok in (
        marker,
        "leaked_comment_tbl",
        "987654321",
        "424242",
        "mysql_dq_secret_551",
        "777",
        "888",
        "unclosed_span_sec_882",
        "11111",
        "22222",
        "33333",
        "ebpf_tok_a",
        "ebpf_tok_b",
        "ebpf_tok_c",
        "ebpf_comment_sec_774",
    ):
        assert secret_tok not in serialized


@pytest.mark.parametrize(
    "claimed_stage",
    [
        "executed",
        "committed",
        "authoritatively_settled",
        "delivered_to_human",
        "candidate_sealed",
        "",
        None,
    ],
)
def test_f2_lost_reply_invariant_across_all_producer_stages_via_analyze_api(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    claimed_stage: str | None,
) -> None:
    """Verify unresolved transport loss overrides optimistic stages across public analyze API."""
    monkeypatch.setenv("WYTHE_STATE_DIR", str(tmp_path / "state"))
    monkeypatch.setenv("WYTHE_DATABASE_URL", f"sqlite:///{tmp_path / 'f2.db'}")
    initialize_database()

    outcome_payload: dict[str, object] = {
        "outcome_id": "write-attempt-1",
        "transport_timeout_or_lost_reply": True,
        "delivery_status": "delivered",
    }
    if claimed_stage is not None:
        outcome_payload["current_stage"] = claimed_stage

    with TestClient(create_app()) as client:
        resp = client.post("/api/v1/understanding/analyze", json={"bundle": {"outcomes": [outcome_payload]}})
        assert resp.status_code == 200, resp.text
        body = resp.json()

    out = body["outcome_lifecycles"][0]
    assert out["current_stage"] == "committed_unacknowledged"
    assert out["producer_claimed_stage"] == (claimed_stage if claimed_stage else None)
    assert out["settlement_state"] == "indeterminate_requires_settlement"
    assert out["blind_retry_prohibited"] is True

    links_by_key = {lnk["link_key"]: lnk for lnk in body["links"]}
    assert links_by_key["committed_result"]["state"] == "unresolved"
    assert links_by_key["human_visible_result"]["state"] != "supported"
    assert "indeterminate" in body["consequence_headline"].lower()
    assert "blind write retries are prohibited" in body["consequence_headline"].lower()
    assert "indeterminate" in body["last_supported_cause"].lower()
    assert "blind write retries are prohibited" in body["last_supported_cause"].lower()
    assert "authoritative_lock_settlement_receipt" in body["overall_missing_joins"]
    assert (
        "indeterminate_settlement_blind_retry_prohibited_until_authoritative_reconciliation"
        in body["overall_missing_joins"]
    )


def test_f2_conflicting_terminal_states_and_positive_authoritative_settlement(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Verify conflicting terminal evidence forces retry prohibition while clean settlement passes."""
    monkeypatch.setenv("WYTHE_STATE_DIR", str(tmp_path / "state_c"))
    monkeypatch.setenv("WYTHE_DATABASE_URL", f"sqlite:///{tmp_path / 'f2_c.db'}")
    initialize_database()

    conflict_bundles = [
        {"current_stage": "committed", "authoritative_terminal_state": "rejected"},
        {"current_stage": "delivered_to_human", "authoritative_terminal_state": "rolled_back"},
        {"transport_timeout_or_lost_reply": True, "authoritative_terminal_state": "committed"},
        {
            "transport_timeout_or_lost_reply": True,
            "authoritative_terminal_state": "committed",
            "content_equality_only": True,
            "settlement_receipt_id": "rcpt-eq-only",
        },
        {
            "authoritative_terminal_state": "committed",
            "settlement_receipt_id": "rcpt-1",
            "transitions": [
                {"stage": "authoritatively_settled", "state_digest": "dig-alpha"},
                {"stage": "authoritatively_settled", "state_digest": "dig-beta"},
            ],
        },
        {
            "transitions": [
                {"stage": "committed", "state_digest": "dig-one"},
                {"stage": "committed", "state_digest": "dig-two"},
            ]
        },
    ]

    with TestClient(create_app()) as client:
        for item in conflict_bundles:
            resp = client.post("/api/v1/understanding/analyze", json={"bundle": {"outcomes": [item]}})
            assert resp.status_code == 200, resp.text
            body = resp.json()
            out = body["outcome_lifecycles"][0]
            assert out["current_stage"] == "committed_unacknowledged"
            assert out["settlement_state"] == "indeterminate_requires_settlement"
            assert out["blind_retry_prohibited"] is True
            links = {lnk["link_key"]: lnk for lnk in body["links"]}
            assert links["committed_result"]["state"] == "unresolved"
            assert links["human_visible_result"]["state"] != "supported"
            assert "blind write retries are prohibited" in body["consequence_headline"].lower()

        # Positive control: genuine non-conflicting settlement after lost reply clears uncertainty
        settled_ok = client.post(
            "/api/v1/understanding/analyze",
            json={
                "bundle": {
                    "outcomes": [
                        {
                            "outcome_id": "settled-after-timeout",
                            "transport_timeout_or_lost_reply": True,
                            "authoritative_terminal_state": "committed",
                            "settlement_receipt_id": "lock-rcpt-200",
                            "authenticated_writer_receipt": True,
                            "transitions": [
                                {"stage": "executed", "state_digest": "vec-1"},
                                {
                                    "stage": "authoritatively_settled",
                                    "predecessor_state_digest": "vec-1",
                                    "state_digest": "vec-2-committed",
                                },
                            ],
                        }
                    ]
                }
            },
        )
        assert settled_ok.status_code == 200, settled_ok.text
        ok_body = settled_ok.json()
        ok_out = ok_body["outcome_lifecycles"][0]
        assert ok_out["current_stage"] == "authoritatively_settled"
        assert ok_out["settlement_state"] == "settled_committed"
        assert ok_out["blind_retry_prohibited"] is False
        ok_links = {lnk["link_key"]: lnk for lnk in ok_body["links"]}
        assert ok_links["committed_result"]["state"] == "supported"


def test_f1_round2_quote_parity_oracle_q_currency_sqlite_between_and_span_name(
    tmp_path: Path,
) -> None:
    """Cover quote-parity backslash inversions, q'[...]', $currency, SQLite BETWEEN, & span.name."""
    nodes = [
        AtlasNode(
            id="m:service_a",
            tier="manipulate",
            subkind="service",
            label="service_a",
            source_file="service_a.py",
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
            id="e:service_a->items:read",
            source_id="m:service_a",
            target_id="t:items",
            kind="reads_truth",
            verification="verified",
            evidence_note="static",
        )
    ]
    report = SimpleNamespace(nodes=nodes, edges=edges, chains=[])

    # Unambiguous even-backslash string still redacts cleanly without failing closed
    even_bs, even_changed = _redact_sql_statement(
        "SELECT id FROM items WHERE dir = 'C:\\\\Users\\\\' AND code = 'EVEN_BS_SEC_1000'",
        db_system="postgresql",
    )
    assert even_changed is True
    assert "[sql_statement_omitted_unparsed]" not in even_bs
    assert "EVEN_BS_SEC_1000" not in even_bs

    otel_path = tmp_path / "adv_otel.json"
    otel_path.write_text(
        json.dumps(
            {
                "resourceSpans": [
                    {
                        "resource": {
                            "attributes": [
                                {"key": "service.name", "value": {"stringValue": "service_a"}}
                            ]
                        },
                        "scopeSpans": [
                            {
                                "spans": [
                                    {
                                        "name": "pg_odd_backslash_inversion",
                                        "attributes": [
                                            {"key": "db.system", "value": {"stringValue": "postgresql"}},
                                            {
                                                "key": "db.statement",
                                                "value": {
                                                    "stringValue": (
                                                        "SELECT id FROM items WHERE name = "
                                                        "'foo\\''ADV_PG_BACKSLASH_LEAK_1001' -- '"
                                                    )
                                                },
                                            },
                                        ],
                                    },
                                    {
                                        "name": "pg_multiline_backslash_inversion",
                                        "attributes": [
                                            {"key": "db.system", "value": {"stringValue": "postgresql"}},
                                            {
                                                "key": "db.statement",
                                                "value": {
                                                    "stringValue": (
                                                        "SELECT id FROM items WHERE a = 'C:\\Users\\'\n"
                                                        "AND name = 'ADV_PG_MULTILINE_LEAK_1002' -- '"
                                                    )
                                                },
                                            },
                                        ],
                                    },
                                    {
                                        "name": "mysql_dq_backslash_inversion",
                                        "attributes": [
                                            {"key": "db.system", "value": {"stringValue": "mysql"}},
                                            {
                                                "key": "db.statement",
                                                "value": {
                                                    "stringValue": (
                                                        'SELECT id FROM items WHERE a = "C:\\dir\\" '
                                                        'AND b = "ADV_MYSQL_DQ_LEAK_1003" -- "'
                                                    )
                                                },
                                            },
                                        ],
                                    },
                                    {
                                        "name": "oracle_q_quote",
                                        "attributes": [
                                            {"key": "db.system", "value": {"stringValue": "oracle"}},
                                            {
                                                "key": "db.statement",
                                                "value": {
                                                    "stringValue": (
                                                        "SELECT id FROM items WHERE name = "
                                                        "q'[a'ADV_ORACLE_Q_LEAK_1004'b]'"
                                                    )
                                                },
                                            },
                                        ],
                                    },
                                    {
                                        "name": "currency_and_oversized_dollar",
                                        "attributes": [
                                            {"key": "db.system", "value": {"stringValue": "postgresql"}},
                                            {
                                                "key": "db.statement",
                                                "value": {
                                                    "stringValue": (
                                                        "SELECT id FROM items WHERE salary = $987654321.55 "
                                                        "AND bonus = $87654321 AND code = $00777 AND ok_param = $2"
                                                    )
                                                },
                                            },
                                        ],
                                    },
                                    {
                                        "name": "sqlite_between_dq",
                                        "attributes": [
                                            {"key": "db.system", "value": {"stringValue": "sqlite"}},
                                            {
                                                "key": "db.statement",
                                                "value": {
                                                    "stringValue": (
                                                        "SELECT id FROM items WHERE code BETWEEN "
                                                        '"ADV_SQLITE_DQ_1006A" AND "ADV_SQLITE_DQ_1006B"'
                                                    )
                                                },
                                            },
                                        ],
                                    },
                                    {
                                        "name": "SELECT id FROM items WHERE name = 'ADV_SPAN_NAME_LEAK_1005'",
                                        "attributes": [
                                            {"key": "peer.service", "value": {"stringValue": "postgres"}}
                                        ],
                                    },
                                ]
                            }
                        ],
                    }
                ]
            }
        ),
        encoding="utf-8",
    )

    companion = correlate_wiretap_companions(
        tmp_path,
        report,
        otel_traces_path=otel_path,
        probe_local_ports=False,
    )
    serialized = json.dumps(companion)
    for forbidden in (
        "ADV_PG_BACKSLASH_LEAK_1001",
        "ADV_PG_MULTILINE_LEAK_1002",
        "ADV_MYSQL_DQ_LEAK_1003",
        "ADV_ORACLE_Q_LEAK_1004",
        "ADV_SPAN_NAME_LEAK_1005",
        "ADV_SQLITE_DQ_1006A",
        "ADV_SQLITE_DQ_1006B",
        "987654321",
        "87654321",
        "00777",
    ):
        assert forbidden not in serialized


def test_f2_round2_empty_settlement_meta_timed_out_transition_and_masked_digest_conflicts(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Reject empty/falsy settlement fields, timed-out transitions, & masked/chained digest conflicts."""
    monkeypatch.setenv("WYTHE_STATE_DIR", str(tmp_path / "state_r2"))
    monkeypatch.setenv("WYTHE_DATABASE_URL", f"sqlite:///{tmp_path / 'f2_r2.db'}")
    initialize_database()

    bypass_attempts = [
        {"transport_timeout_or_lost_reply": True, "authoritative_terminal_state": "committed", "settlement_receipt_id": ""},
        {"transport_timeout_or_lost_reply": True, "authoritative_terminal_state": "committed", "settlement_receipt_id": "   "},
        {"transport_timeout_or_lost_reply": True, "authoritative_terminal_state": "committed", "settlement_evidence": {}},
        {"transport_timeout_or_lost_reply": True, "authoritative_terminal_state": "committed", "settlement_receipt": False},
        {"transport_timeout_or_lost_reply": True, "authoritative_terminal_state": "committed", "state_digest": "pre-loss-d1"},
        {"transport_timeout_or_lost_reply": True, "authoritative_terminal_state": "committed", "authority_ref": "ISSUE-99"},
        {
            "authoritative_terminal_state": "committed",
            "transitions": [
                {"stage": "committed", "request_id": "req-1", "transport_timeout_or_lost_reply": True}
            ],
        },
        {
            "authoritative_terminal_state": "committed",
            "transitions": [
                {"stage": "authoritatively_settled", "state_digest": "vec-early"},
                {"stage": "committed_unacknowledged", "transport_timeout_or_lost_reply": True},
            ],
        },
        {
            "authoritative_terminal_state": "committed",
            "settlement_receipt_id": "rcpt-masked",
            "transitions": [
                {"stage": "committed", "state_digest": "same-state", "terminal_digest": "term-alpha"},
                {"stage": "committed", "state_digest": "same-state", "terminal_digest": "term-beta"},
            ],
        },
        {
            "authoritative_terminal_state": "committed",
            "settlement_digest": "dig-A",
            "terminal_digest": "dig-B",
        },
        {
            "authoritative_terminal_state": "committed",
            "settlement_receipt_id": "rcpt-chained-settled",
            "transitions": [
                {"stage": "authoritatively_settled", "state_digest": "dig-alpha"},
                {
                    "stage": "authoritatively_settled",
                    "predecessor_state_digest": "dig-alpha",
                    "state_digest": "dig-beta",
                },
            ],
        },
    ]

    with TestClient(create_app()) as client:
        for payload in bypass_attempts:
            resp = client.post("/api/v1/understanding/analyze", json={"bundle": {"outcomes": [payload]}})
            assert resp.status_code == 200, resp.text
            body = resp.json()
            out = body["outcome_lifecycles"][0]
            assert out["current_stage"] == "committed_unacknowledged"
            assert out["settlement_state"] == "indeterminate_requires_settlement"
            assert out["blind_retry_prohibited"] is True
            links = {lnk["link_key"]: lnk for lnk in body["links"]}
            assert links["committed_result"]["state"] == "unresolved"
            assert links["human_visible_result"]["state"] != "supported"
            assert "blind write retries are prohibited" in body["consequence_headline"].lower()
