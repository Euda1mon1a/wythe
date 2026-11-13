"""Evidence contracts for the experimental, opt-in ownership workflow."""

from __future__ import annotations

from typing import Literal

from pydantic import BaseModel, Field


class OwnershipEvidence(BaseModel):
    kind: Literal[
        "route", "dependency", "record_lookup", "record_write", "persistence_call",
        "owner_comparison", "ownership_rejection",
    ]
    line: int
    end_line: int
    expression: str
    placement: Literal["direct", "conditional", "inactive"] = "direct"
    detail: str


class OwnershipReport(BaseModel):
    schema_version: int = 1
    maturity: Literal["experimental"] = "experimental"
    observation_source: Literal["static_ast"] = "static_ast"
    invariant: str = "One user cannot modify another user's record."
    invariant_result: Literal["unknown"] = "unknown"
    target_code_executed: Literal[False] = False
    target_database_contacted: Literal[False] = False
    source_file: str
    source_sha256: str
    handler: str
    record: str
    principal: str
    owner_field: str
    evidence: list[OwnershipEvidence] = Field(default_factory=list)
    unknowns: list[str] = Field(default_factory=list)


class OwnershipCase(BaseModel):
    name: str
    principal: str | None
    record_id: int
    expected_status: int
    observed_status: int
    expected_records: list[dict]
    observed_records: list[dict]
    passed: bool


class OwnershipExampleRun(BaseModel):
    variant: Literal["vulnerable", "repaired"]
    invariant_result: Literal["violated", "holds_for_tested_cases", "inconclusive"]
    cases: list[OwnershipCase]
    source_evidence: OwnershipReport


class OwnershipDemoReport(BaseModel):
    schema_version: int = 1
    maturity: Literal["experimental"] = "experimental"
    observation_source: Literal["builtin_asgi_test"] = "builtin_asgi_test"
    invariant: str = "One user cannot modify another user's record."
    scope: str = "Shipped synthetic examples only; fresh in-memory SQLite per case."
    target_code_executed: Literal[False] = False
    network_requests_sent: Literal[False] = False
    wythe_version: str
    source_hashes: dict[str, str]
    before: OwnershipExampleRun
    after: OwnershipExampleRun
    regression_passed: bool
    limitations: list[str]
