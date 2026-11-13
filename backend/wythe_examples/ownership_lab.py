"""Replay a fixed ownership regression against only Wythe's shipped example routers."""

from __future__ import annotations

import hashlib
from collections.abc import Iterator
from contextlib import contextmanager
from pathlib import Path

from fastapi import FastAPI
from fastapi.testclient import TestClient
from sqlalchemy import create_engine, select
from sqlalchemy.orm import Session, sessionmaker
from sqlalchemy.pool import StaticPool

from app import __version__
from app.schemas.security import OwnershipCase, OwnershipDemoReport, OwnershipExampleRun
from app.services.ownership_service import inspect_record_ownership
from wythe_examples import ownership_repaired, ownership_vulnerable
from wythe_examples.ownership_common import Base, Record, get_session


def initial_records() -> list[dict]:
    return [
        {"id": 1, "owner_id": 1, "title": "First example"},
        {"id": 2, "owner_id": 2, "title": "Second example"},
    ]


@contextmanager
def example_client(variant: str) -> Iterator[tuple[TestClient, sessionmaker]]:
    if variant not in ("vulnerable", "repaired"):
        raise ValueError("Only the two shipped ownership examples can run")
    engine = create_engine(
        "sqlite://", connect_args={"check_same_thread": False}, poolclass=StaticPool,
    )
    try:
        Base.metadata.create_all(engine)
        factory = sessionmaker(bind=engine)
        with factory() as db:
            db.add_all(Record(**row) for row in initial_records())
            db.commit()

        def session_dependency() -> Iterator[Session]:
            with factory() as db:
                yield db

        application = FastAPI()
        application.dependency_overrides[get_session] = session_dependency
        application.include_router(
            ownership_vulnerable.router if variant == "vulnerable" else ownership_repaired.router,
        )
        with TestClient(application, raise_server_exceptions=False) as client:
            yield client, factory
    finally:
        engine.dispose()


def read_records(factory: sessionmaker) -> list[dict]:
    with factory() as db:
        return [{"id": row.id, "owner_id": row.owner_id, "title": row.title}
                for row in db.scalars(select(Record).order_by(Record.id)).all()]


def run_example(variant: str) -> OwnershipExampleRun:
    cases = []
    specifications = (
        ("owner_1_updates_own", "demo-user-1", 1, 200, False),
        ("owner_2_updates_own", "demo-user-2", 2, 200, False),
        ("user_2_cannot_update_1", "demo-user-2", 1, 403, False),
        ("user_1_cannot_update_2", "demo-user-1", 2, 403, False),
        ("missing_identity", None, 1, 401, False),
        ("unknown_identity", "demo-unknown", 1, 401, False),
        ("missing_record", "demo-user-1", 999, 404, False),
        ("cannot_replace_owner", "demo-user-1", 1, 422, True),
    )
    for name, principal, record_id, expected_status, replace_owner in specifications:
        expected = initial_records()
        if expected_status == 200:
            expected[record_id - 1]["title"] = "Updated example"
        payload = {"title": "Updated example"}
        if replace_owner:
            payload["owner_id"] = 2
        headers = {"Authorization": f"Bearer {principal}"} if principal else {}
        # Every request starts from fresh records; no case can hide another case's mutation.
        with example_client(variant) as (client, factory):
            response = client.patch(f"/records/{record_id}", headers=headers, json=payload)
            observed = read_records(factory)  # new session, after the response completed
        cases.append(OwnershipCase(
            name=name, principal=principal, record_id=record_id,
            expected_status=expected_status, observed_status=response.status_code,
            expected_records=expected, observed_records=observed,
            passed=response.status_code == expected_status and observed == expected,
        ))
    crossed_owner = any(
        c.name in ("user_2_cannot_update_1", "user_1_cannot_update_2")
        and c.observed_records != c.expected_records for c in cases
    )
    result = ("violated" if crossed_owner else
              "holds_for_tested_cases" if all(c.passed for c in cases) else "inconclusive")
    evidence = inspect_record_ownership(
        Path(__file__).parent, handler=f"ownership_{variant}.py:update_record",
        record="record", principal="user.id", owner_field="owner_id",
    )
    return OwnershipExampleRun(
        variant=variant, invariant_result=result, cases=cases, source_evidence=evidence,
    )


def run_ownership_demo() -> OwnershipDemoReport:
    before = run_example("vulnerable")
    after = run_example("repaired")
    failures = {c.name for c in before.cases if not c.passed}
    expected_failures = {"user_2_cannot_update_1", "user_1_cannot_update_2"}
    sources = ("ownership_common.py", "ownership_vulnerable.py", "ownership_repaired.py", "ownership_lab.py")
    hashes = {name: hashlib.sha256((Path(__file__).parent / name).read_bytes()).hexdigest()
              for name in sources}
    return OwnershipDemoReport(
        wythe_version=__version__, source_hashes=hashes, before=before, after=after,
        regression_passed=(before.invariant_result == "violated" and failures == expected_failures
                           and all(c.passed for c in after.cases)),
        limitations=[
            "Only these synthetic endpoints, identities, records and request cases were exercised.",
            "The fixed public demo tokens are fixture identities, not production authentication guidance.",
            "No target repository, real credentials, external database, socket or live server is used.",
            "Concurrency, other roles/endpoints, row-level policies and detection telemetry were not tested.",
            "Hashes identify example source bytes; this JSON is not a signed or tamper-evident audit ledger.",
        ],
    )
