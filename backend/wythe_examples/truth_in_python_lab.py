"""Synthetic 'Truth in Python' compute/warehouse quota fixture & cross-surface drift lab.

Materializes a self-contained, non-routable 3-tier repository exercising all 7 policy
consumption cases alongside cross-surface rule drift across SQL DDL (`32`), declarative
JSON registry (`28`), Python validator (`40`), local overwrite (`50`), solver builder,
and React UI helper (`36`).
"""

from __future__ import annotations

import ast
import json
import re
import subprocess
from dataclasses import asdict, dataclass
from pathlib import Path

SQL_MIGRATION_001 = """\
CREATE TABLE batch_quota_policies (
    id INTEGER PRIMARY KEY,
    name VARCHAR(120) NOT NULL,
    max_batch_quota INTEGER NOT NULL DEFAULT 32
);

CREATE TABLE cooldown_policies (
    id INTEGER PRIMARY KEY,
    name VARCHAR(120) NOT NULL,
    min_cooldown_minutes INTEGER NOT NULL DEFAULT 0
);

CREATE TABLE quota_dispatch_ledger (
    id INTEGER PRIMARY KEY,
    policy_id INTEGER NOT NULL REFERENCES batch_quota_policies(id),
    applied_quota INTEGER NOT NULL
);
"""

QUOTA_REGISTRY_JSON = {
    "jobs": {
        "warehouse_batch_dispatcher": {
            "enabled": True,
            "max_batch_quota": 28,
            "min_cooldown_minutes": 10,
            "command": "python -m app.services.case7_solver_and_algorithms",
        }
    }
}

MODELS_INIT_PY = """\
from app.models.quota_models import BatchQuotaPolicy, CooldownPolicy, QuotaDispatchLedger

__all__ = ["BatchQuotaPolicy", "CooldownPolicy", "QuotaDispatchLedger"]
"""

QUOTA_MODELS_PY = """\
from sqlalchemy import ForeignKey, Integer, String
from sqlalchemy.orm import DeclarativeBase, Mapped, mapped_column


class Base(DeclarativeBase):
    pass


class BatchQuotaPolicy(Base):
    __tablename__ = "batch_quota_policies"

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    name: Mapped[str] = mapped_column(String(120), nullable=False)
    max_batch_quota: Mapped[int] = mapped_column(Integer, default=32, nullable=False)


class CooldownPolicy(Base):
    __tablename__ = "cooldown_policies"

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    name: Mapped[str] = mapped_column(String(120), nullable=False)
    min_cooldown_minutes: Mapped[int] = mapped_column(Integer, default=0, nullable=False)


class QuotaDispatchLedger(Base):
    __tablename__ = "quota_dispatch_ledger"

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    policy_id: Mapped[int] = mapped_column(ForeignKey("batch_quota_policies.id"), nullable=False)
    applied_quota: Mapped[int] = mapped_column(Integer, nullable=False)
"""

CASE1_CONSUMED_PY = """\
\"\"\"Case 1: Consumed policy field controlling guard, write sink, and return.\"\"\"

from sqlalchemy import select
from app.models.quota_models import BatchQuotaPolicy, QuotaDispatchLedger


def enforce_consumed_quota(db, requested_units: int) -> int:
    row = db.scalars(select(BatchQuotaPolicy)).one()
    if requested_units > row.max_batch_quota:
        raise ValueError("Requested units exceed configured batch quota")
    db.add(QuotaDispatchLedger(policy_id=1, applied_quota=row.max_batch_quota))
    return row.max_batch_quota
"""

CASE2_BYPASSED_PY = """\
\"\"\"Case 2: Bypassed policy field — reads `.id`/`.name` and enforces hardcoded `40`.\"\"\"

from sqlalchemy import select
from app.models.quota_models import BatchQuotaPolicy


def validate_hardcoded_quota(db, requested_units: int) -> dict[str, object]:
    row = db.scalars(select(BatchQuotaPolicy)).one()
    if requested_units > 40:
        raise ValueError(f"Policy {row.name} ({row.id}) capped at hardcoded 40")
    return {"id": row.id, "name": row.name, "enforced_quota": 40}
"""

CASE3_FALLBACK_PY = """\
\"\"\"Case 3: Explicit missing-value fallback (`is not None else 25`).\"\"\"

from sqlalchemy import select
from app.models.quota_models import BatchQuotaPolicy


def resolve_quota_with_explicit_fallback(db) -> int:
    row = db.scalars(select(BatchQuotaPolicy)).one()
    effective_quota = row.max_batch_quota if row.max_batch_quota is not None else 25
    return effective_quota
"""

CASE4A_ZERO_PRESERVED_PY = """\
\"\"\"Case 4a: Explicit `is not None` guard preserving valid `0` cooldown policy.\"\"\"

from sqlalchemy import select
from app.models.quota_models import CooldownPolicy


def resolve_cooldown_preserving_zero(db) -> int:
    row = db.scalars(select(CooldownPolicy)).one()
    cooldown = row.min_cooldown_minutes if row.min_cooldown_minutes is not None else 15
    return cooldown
"""

CASE4B_ZERO_CLOBBERED_PY = """\
\"\"\"Case 4b: Truthiness `or 15` fallback silently clobbering valid `0` cooldown policy.\"\"\"

from sqlalchemy import select
from app.models.quota_models import CooldownPolicy


def resolve_cooldown_clobbering_zero(db) -> int:
    row = db.scalars(select(CooldownPolicy)).one()
    cooldown = row.min_cooldown_minutes or 15
    return cooldown
"""

CASE5_SHADOWED_PY = """\
\"\"\"Case 5: Local variable `limit` reads policy field then is overwritten by `50`.\"\"\"

from sqlalchemy import select
from app.models.quota_models import BatchQuotaPolicy


def evaluate_shadowed_quota(db, requested_units: int) -> dict[str, object]:
    row = db.scalars(select(BatchQuotaPolicy)).one()
    limit = row.max_batch_quota
    limit = 50
    if requested_units > limit:
        return {"id": row.id, "allowed": False, "limit": limit}
    return {"id": row.id, "allowed": True, "limit": limit}
"""

CASE6_OPAQUE_DYNAMIC_PY = """\
\"\"\"Case 6: Opaque external helper handoff and dynamic `getattr` lookup.\"\"\"

from sqlalchemy import select
from external_quota_engine import opaque_external_fn
from app.models.quota_models import BatchQuotaPolicy


def delegate_opaque_and_dynamic_quota(db, dynamic_attr: str = "max_batch_quota") -> object:
    row = db.scalars(select(BatchQuotaPolicy)).one()
    dyn_val = getattr(row, dynamic_attr)
    return opaque_external_fn(row, preview=dyn_val)
"""

CASE7_ALGORITHMIC_SOLVER_PY = """\
\"\"\"Case 7: Legitimate unit/protocol/algorithmic constants + CP solver constraint.\"\"\"

from sqlalchemy import select
from app.models.quota_models import BatchQuotaPolicy

SECONDS_PER_HOUR = 3600
MIB_BYTES = 1024 * 1024
HTTP_RETRY_BACKOFF = 2


def binary_search_slot(slots: list[int], target: int) -> int:
    lo = 0
    hi = len(slots) - 1
    while lo <= hi:
        mid = (lo + hi) // 2
        if slots[mid] == target:
            return mid
        if slots[mid] < target:
            lo = mid + 1
        else:
            hi = mid - 1
    return -1


def build_quota_solver_constraints(db, solver, batch_var, payload_bytes: int) -> dict[str, int]:
    row = db.scalars(select(BatchQuotaPolicy)).one()
    solver.Add(batch_var <= row.max_batch_quota)
    payload_mib = payload_bytes // MIB_BYTES
    window_seconds = SECONDS_PER_HOUR // HTTP_RETRY_BACKOFF
    return {"quota": row.max_batch_quota, "payload_mib": payload_mib, "window_s": window_seconds}
"""

ROUTES_QUOTAS_PY = """\
from fastapi import APIRouter
from app.services.case1_consumed_enforcer import enforce_consumed_quota
from app.services.case2_bypassed_validator import validate_hardcoded_quota
from app.services.case3_missing_fallback import resolve_quota_with_explicit_fallback
from app.services.case4a_zero_preserved import resolve_cooldown_preserving_zero
from app.services.case4b_zero_clobbered import resolve_cooldown_clobbering_zero
from app.services.case5_shadowed_local import evaluate_shadowed_quota
from app.services.case6_opaque_dynamic import delegate_opaque_and_dynamic_quota
from app.services.case7_solver_and_algorithms import build_quota_solver_constraints

router = APIRouter(prefix="/api/quotas", tags=["quotas"])


@router.post("/enforce")
def post_enforce_quota(requested_units: int = 10, db=None):
    return {"applied": enforce_consumed_quota(db, requested_units)}


@router.get("/validate")
def get_validate_quota(requested_units: int = 10, db=None):
    return validate_hardcoded_quota(db, requested_units)


@router.get("/fallback")
def get_fallback_quota(db=None):
    return {"effective_quota": resolve_quota_with_explicit_fallback(db)}


@router.get("/cooldown-safe")
def get_cooldown_safe(db=None):
    return {"cooldown_minutes": resolve_cooldown_preserving_zero(db)}


@router.get("/cooldown-clobber")
def get_cooldown_clobber(db=None):
    return {"cooldown_minutes": resolve_cooldown_clobbering_zero(db)}


@router.get("/shadow")
def get_shadow_quota(requested_units: int = 10, db=None):
    return evaluate_shadowed_quota(db, requested_units)


@router.get("/dynamic")
def get_dynamic_quota(db=None):
    return {"result": delegate_opaque_and_dynamic_quota(db)}


@router.post("/solver")
def post_solver_constraints(payload_bytes: int = 1048576, db=None, solver=None):
    return build_quota_solver_constraints(db, solver, 0, payload_bytes)
"""

MAIN_PY = """\
from fastapi import FastAPI
from app.api.routes import quotas

app = FastAPI(title="Synthetic Warehouse Quota Service")
app.include_router(quotas.router)
"""

UI_POLICY_TS = """\
export const MAX_BATCH_CAPACITY = 36;

export function describeBatchQuotaRule(): string {
  return `Client UI enforces max batch quota of ${MAX_BATCH_CAPACITY} units.`;
}
"""

UI_PAGE_TSX = """\
import { MAX_BATCH_CAPACITY, describeBatchQuotaRule } from "../lib/quotaUiPolicy";

export default async function WarehouseQuotaDashboardPage() {
  const validationRes = await fetch("/api/quotas/validate");
  const fallbackRes = await fetch("/api/quotas/fallback");
  const validationJson = await validationRes.json();
  const fallbackJson = await fallbackRes.json();
  return (
    <main aria-label="Warehouse Quota Policy Inspector">
      <h1>Warehouse Batch Quota Dashboard</h1>
      <p>{describeBatchQuotaRule()} (limit {MAX_BATCH_CAPACITY})</p>
      <pre>{JSON.stringify({ validationJson, fallbackJson })}</pre>
    </main>
  );
}
"""


@dataclass(frozen=True)
class CrossSurfacePolicyAssertion:
    """Single surface encoding a version of the `max_batch_quota` domain rule."""

    surface: str
    rel_path: str
    line: int
    encoded_value: int
    role: str


def materialize_truth_in_python_fixture(
    dest_dir: Path | str,
    *,
    init_git: bool = False,
) -> Path:
    """Materialize the reusable 7-case 'Truth in Python' + cross-surface drift fixture."""
    root = Path(dest_dir)
    for subdir in (
        "backend/migrations",
        "backend/app/models",
        "backend/app/services",
        "backend/app/api/routes",
        "config",
        "frontend/src/app",
        "frontend/src/lib",
    ):
        (root / subdir).mkdir(parents=True, exist_ok=True)

    files_to_write: dict[str, str] = {
        "backend/migrations/001_batch_quota_policies.sql": SQL_MIGRATION_001,
        "config/quota_policy_registry.json": json.dumps(QUOTA_REGISTRY_JSON, indent=2) + "\n",
        "backend/app/__init__.py": "",
        "backend/app/models/__init__.py": MODELS_INIT_PY,
        "backend/app/models/quota_models.py": QUOTA_MODELS_PY,
        "backend/app/services/__init__.py": "",
        "backend/app/services/case1_consumed_enforcer.py": CASE1_CONSUMED_PY,
        "backend/app/services/case2_bypassed_validator.py": CASE2_BYPASSED_PY,
        "backend/app/services/case3_missing_fallback.py": CASE3_FALLBACK_PY,
        "backend/app/services/case4a_zero_preserved.py": CASE4A_ZERO_PRESERVED_PY,
        "backend/app/services/case4b_zero_clobbered.py": CASE4B_ZERO_CLOBBERED_PY,
        "backend/app/services/case5_shadowed_local.py": CASE5_SHADOWED_PY,
        "backend/app/services/case6_opaque_dynamic.py": CASE6_OPAQUE_DYNAMIC_PY,
        "backend/app/services/case7_solver_and_algorithms.py": CASE7_ALGORITHMIC_SOLVER_PY,
        "backend/app/api/__init__.py": "",
        "backend/app/api/routes/__init__.py": "",
        "backend/app/api/routes/quotas.py": ROUTES_QUOTAS_PY,
        "backend/app/main.py": MAIN_PY,
        "frontend/package.json": json.dumps(
            {
                "name": "warehouse-quota-ui",
                "private": True,
                "dependencies": {"next": "15.0.0", "react": "19.0.0"},
            },
            indent=2,
        )
        + "\n",
        "frontend/src/lib/quotaUiPolicy.ts": UI_POLICY_TS,
        "frontend/src/app/page.tsx": UI_PAGE_TSX,
    }
    for rel_path, content in files_to_write.items():
        (root / rel_path).write_text(content, encoding="utf-8")

    if init_git:
        subprocess.run(["git", "init", "-q"], cwd=root, check=True)
        subprocess.run(
            ["git", "config", "user.email", "214782221+Euda1mon1a@users.noreply.github.com"],
            cwd=root,
            check=True,
        )
        subprocess.run(["git", "config", "user.name", "Euda1mon1a"], cwd=root, check=True)
        subprocess.run(["git", "add", "."], cwd=root, check=True)
        subprocess.run(["git", "commit", "-q", "-m", "chore: seed synthetic quota fixture"], cwd=root, check=True)

    return root


def audit_cross_surface_policy_drift(repo_dir: Path | str) -> dict[str, object]:
    """Extract and compare `max_batch_quota` rule values across SQL, JSON, Python, and UI."""
    root = Path(repo_dir)
    assertions: list[CrossSurfacePolicyAssertion] = []

    sql_rel = "backend/migrations/001_batch_quota_policies.sql"
    sql_path = root / sql_rel
    if sql_path.is_file():
        for idx, line in enumerate(sql_path.read_text(encoding="utf-8").splitlines(), start=1):
            m = re.search(
                r"max_batch_quota\s+INTEGER\s+NOT\s+NULL\s+DEFAULT\s+(\d+)",
                line,
                re.IGNORECASE,
            )
            if m:
                assertions.append(
                    CrossSurfacePolicyAssertion(
                        surface="sql_schema_default",
                        rel_path=sql_rel,
                        line=idx,
                        encoded_value=int(m.group(1)),
                        role="authoritative_schema_default",
                    )
                )

    reg_rel = "config/quota_policy_registry.json"
    reg_path = root / reg_rel
    if reg_path.is_file():
        reg_text = reg_path.read_text(encoding="utf-8")
        reg_data = json.loads(reg_text)
        job_cfg = reg_data.get("jobs", {}).get("warehouse_batch_dispatcher", {})
        if isinstance(job_cfg.get("max_batch_quota"), int):
            reg_line = next(
                (i for i, ln in enumerate(reg_text.splitlines(), 1) if "max_batch_quota" in ln),
                1,
            )
            assertions.append(
                CrossSurfacePolicyAssertion(
                    surface="json_policy_registry",
                    rel_path=reg_rel,
                    line=reg_line,
                    encoded_value=int(job_cfg["max_batch_quota"]),
                    role="declarative_registry_override",
                )
            )

    py_checks = (
        ("python_validator_bypass", "backend/app/services/case2_bypassed_validator.py", "hardcoded_validator_cap"),
        ("python_missing_fallback", "backend/app/services/case3_missing_fallback.py", "explicit_null_fallback"),
        ("python_shadowed_local", "backend/app/services/case5_shadowed_local.py", "shadowed_local_overwrite"),
    )
    for surf, rel_p, role in py_checks:
        fp = root / rel_p
        if not fp.is_file():
            continue
        tree = ast.parse(fp.read_text(encoding="utf-8"))
        for node in ast.walk(tree):
            if (
                isinstance(node, ast.Constant)
                and isinstance(node.value, int)
                and not isinstance(node.value, bool)
                and node.value >= 20
            ):
                assertions.append(
                    CrossSurfacePolicyAssertion(
                        surface=surf,
                        rel_path=rel_p,
                        line=getattr(node, "lineno", 1),
                        encoded_value=int(node.value),
                        role=role,
                    )
                )
                break

    ui_rel = "frontend/src/lib/quotaUiPolicy.ts"
    ui_path = root / ui_rel
    if ui_path.is_file():
        for idx, line in enumerate(ui_path.read_text(encoding="utf-8").splitlines(), start=1):
            m = re.search(r"MAX_BATCH_CAPACITY\s*=\s*(\d+)", line)
            if m:
                assertions.append(
                    CrossSurfacePolicyAssertion(
                        surface="react_ui_helper",
                        rel_path=ui_rel,
                        line=idx,
                        encoded_value=int(m.group(1)),
                        role="client_ui_shadow",
                    )
                )

    distinct_vals = sorted({a.encoded_value for a in assertions})
    return {
        "rule_name": "max_batch_quota",
        "has_conflict": len(distinct_vals) > 1,
        "distinct_values": distinct_vals,
        "surface_count": len(assertions),
        "surfaces": [asdict(a) for a in assertions],
    }
