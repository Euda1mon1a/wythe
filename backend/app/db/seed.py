"""Idempotent database bootstrap seeding initial stack profiles, rules, and local targets.

Existing human-modified rows in PostgreSQL/SQLite are never overwritten by bootstrap.
"""

from __future__ import annotations

from pathlib import Path

from sqlalchemy import select
from sqlalchemy.orm import Session

from app.core.clock import utc_now, utc_today
from app.models import PolicyVocabulary, RulePolicy, StackProfile, TargetProject

INITIAL_STACK_PROFILES: tuple[dict[str, object], ...] = (
    {
        "slug": "fastapi-sqlalchemy-nextjs",
        "label": "PostgreSQL/SQLite + FastAPI/SQLAlchemy + Next.js/TypeScript",
        "truth_adapter": "postgres-sqlalchemy",
        "manipulator_adapter": "python-fastapi",
        "display_adapter": "typescript-nextjs",
        "implementation_status": "implemented",
        "is_enabled": True,
        "description": (
            "SQLAlchemy/Alembic relational truth, "
            "Python/FastAPI manipulation, and Next.js/TypeScript/OpenAPI display."
        ),
    },
    {
        "slug": "nextjs-prisma",
        "label": "Full-Stack Next.js + Prisma (PostgreSQL/MySQL/SQLite)",
        "truth_adapter": "prisma-schema",
        "manipulator_adapter": "typescript-node",
        "display_adapter": "typescript-nextjs",
        "implementation_status": "experimental",
        "is_enabled": True,
        "description": "Prisma schema.prisma + SQL migrations, Next.js route.ts/Node handlers, and Next.js App/Pages UI.",
    },
    {
        "slug": "postgres-drizzle-nextjs",
        "label": "PostgreSQL/MySQL/SQLite + Drizzle/Node + Next.js/TypeScript",
        "truth_adapter": "drizzle-orm",
        "manipulator_adapter": "typescript-node",
        "display_adapter": "typescript-nextjs",
        "implementation_status": "experimental",
        "is_enabled": True,
        "description": "Full-TypeScript Drizzle pgTable/mysqlTable/sqliteTable + Node/Next.js route manipulation + Next.js display.",
    },
    {
        "slug": "node-prisma-react",
        "label": "Node/Express/Hono/NestJS + Prisma + React/Vite SPA",
        "truth_adapter": "prisma-schema",
        "manipulator_adapter": "typescript-node",
        "display_adapter": "typescript-react",
        "implementation_status": "experimental",
        "is_enabled": True,
        "description": "Prisma schema truth, Express/Fastify/Hono/NestJS backend manipulation, and React/Vite SPA display.",
    },
    {
        "slug": "node-drizzle-react",
        "label": "Node/Express/Hono/NestJS + Drizzle + React/Vite SPA",
        "truth_adapter": "drizzle-orm",
        "manipulator_adapter": "typescript-node",
        "display_adapter": "typescript-react",
        "implementation_status": "experimental",
        "is_enabled": True,
        "description": "Drizzle ORM truth, TypeScript Node backend manipulation, and React/Vite/TanStack Router display.",
    },
    {
        "slug": "fastapi-react-spa",
        "label": "SQLAlchemy + Python/FastAPI + React/Vite SPA",
        "truth_adapter": "postgres-sqlalchemy",
        "manipulator_adapter": "python-fastapi",
        "display_adapter": "typescript-react",
        "implementation_status": "experimental",
        "is_enabled": True,
        "description": "SQLAlchemy/Alembic truth, FastAPI manipulation, and React/Vite/Remix SPA display.",
    },
    {
        "slug": "fastapi-vue",
        "label": "SQLAlchemy + Python/FastAPI + Vue 3 / Nuxt",
        "truth_adapter": "postgres-sqlalchemy",
        "manipulator_adapter": "python-fastapi",
        "display_adapter": "vue-sfc",
        "implementation_status": "experimental",
        "is_enabled": True,
        "description": "SQLAlchemy/Alembic truth, FastAPI manipulation, and Vue 3 / Nuxt SFC display.",
    },
    {
        "slug": "fastapi-sveltekit",
        "label": "SQLAlchemy + Python/FastAPI + SvelteKit",
        "truth_adapter": "postgres-sqlalchemy",
        "manipulator_adapter": "python-fastapi",
        "display_adapter": "sveltekit",
        "implementation_status": "experimental",
        "is_enabled": True,
        "description": "SQLAlchemy/Alembic truth, FastAPI manipulation, and Svelte 5 / SvelteKit display.",
    },
    {
        "slug": "django-react",
        "label": "Django ORM + Django/DRF/Ninja + React/TypeScript",
        "truth_adapter": "django-orm",
        "manipulator_adapter": "python-django",
        "display_adapter": "typescript-react",
        "implementation_status": "experimental",
        "is_enabled": True,
        "description": "Django models/migrations truth, Django URLs/DRF/Ninja manipulation, and React SPA display.",
    },
    {
        "slug": "django-vue",
        "label": "Django ORM + Django/DRF/Ninja + Vue 3 / Nuxt",
        "truth_adapter": "django-orm",
        "manipulator_adapter": "python-django",
        "display_adapter": "vue-sfc",
        "implementation_status": "experimental",
        "is_enabled": True,
        "description": "Django models/migrations truth, Django URLs/DRF/Ninja manipulation, and Vue 3 / Nuxt SFC display.",
    },
    {
        "slug": "postgres-go-react",
        "label": "SQL DDL/sqlc + Go (net/http, chi, gin, echo) + React/TypeScript",
        "truth_adapter": "sql-ddl",
        "manipulator_adapter": "go-http",
        "display_adapter": "typescript-react",
        "implementation_status": "experimental",
        "is_enabled": True,
        "description": "SQL DDL/migrations + sqlc truth, Go HTTP router/service manipulation, and React/Vite SPA display.",
    },
    {
        "slug": "go-sqlc-sveltekit",
        "label": "SQL DDL/sqlc + Go (net/http, chi, gin, echo) + SvelteKit",
        "truth_adapter": "sql-ddl",
        "manipulator_adapter": "go-http",
        "display_adapter": "sveltekit",
        "implementation_status": "experimental",
        "is_enabled": True,
        "description": "SQL DDL/migrations + sqlc truth, Go HTTP router/service manipulation, and SvelteKit display.",
    },
    {
        "slug": "rust-axum-react",
        "label": "Rust (sqlx/Diesel/SeaORM) + Rust (axum/actix-web/Tauri) + React/Vite SPA",
        "truth_adapter": "rust-sql",
        "manipulator_adapter": "rust-http",
        "display_adapter": "typescript-react",
        "implementation_status": "experimental",
        "is_enabled": True,
        "description": "sqlx/Diesel/SeaORM truth, Rust axum/actix-web/Tauri manipulation, and React/Vite or Tauri SPA display.",
    },
    {
        "slug": "rust-axum-nextjs",
        "label": "Rust (sqlx/Diesel/SeaORM) + Rust (axum/actix-web/Tauri) + Next.js/TypeScript",
        "truth_adapter": "rust-sql",
        "manipulator_adapter": "rust-http",
        "display_adapter": "typescript-nextjs",
        "implementation_status": "experimental",
        "is_enabled": True,
        "description": "sqlx/Diesel/SeaORM truth, Rust axum/actix-web manipulation, and Next.js App/Pages Router display.",
    },
    {
        "slug": "rust-axum-sveltekit",
        "label": "Rust (sqlx/Diesel/SeaORM) + Rust (axum/actix-web/Tauri) + SvelteKit",
        "truth_adapter": "rust-sql",
        "manipulator_adapter": "rust-http",
        "display_adapter": "sveltekit",
        "implementation_status": "experimental",
        "is_enabled": True,
        "description": "sqlx/Diesel/SeaORM truth, Rust axum/actix-web or Tauri command manipulation, and SvelteKit display.",
    },
    {
        "slug": "rust-fullstack-wasm",
        "label": "Pure Rust Full-Stack (sqlx/Diesel/SeaORM + axum/actix-web + Leptos/Dioxus/Yew WASM)",
        "truth_adapter": "rust-sql",
        "manipulator_adapter": "rust-http",
        "display_adapter": "rust-wasm",
        "implementation_status": "experimental",
        "is_enabled": True,
        "description": "100% Rust 3-tier stack: sqlx/Diesel/SeaORM truth, axum/actix-web manipulation, and Leptos/Dioxus/Yew WASM UI.",
    },
    {
        "slug": "postgres-drizzle-sveltekit",
        "label": "PostgreSQL/MySQL/SQLite + Drizzle/Node + SvelteKit",
        "truth_adapter": "drizzle-orm",
        "manipulator_adapter": "typescript-node",
        "display_adapter": "sveltekit",
        "implementation_status": "experimental",
        "is_enabled": True,
        "description": "Drizzle ORM schema truth, SvelteKit +page.server.ts/+server.ts manipulation, and Svelte 5 / SvelteKit display.",
    },
    {
        "slug": "postgres-swift-swiftui",
        "label": "PostgreSQL + Swift/Vapor + SwiftUI",
        "truth_adapter": "postgres-sqlalchemy",
        "manipulator_adapter": "swift-vapor",
        "display_adapter": "swiftui",
        "implementation_status": "planned",
        "is_enabled": False,
        "description": "Planned extension slot for typed Swift server handlers and native SwiftUI clients.",
    },
)

INITIAL_RULE_POLICIES: tuple[dict[str, object], ...] = (
    {
        "rule_code": "TRUTH-001",
        "tier": "truth",
        "category": "orphaned_truth",
        "title": "Persisted input table has zero verified readers",
        "rationale": "An input table that no backend manipulator reads is an unconsumed chapter in the rulebook.",
        "severity": "warning",
        "enabled": True,
        "blocks_gate": False,
    },
    {
        "rule_code": "TRUTH-002",
        "tier": "truth",
        "category": "schema_drift",
        "title": "ORM model and SQL schema/catalog mismatch",
        "rationale": "Authoritative tables in SQLAlchemy models, schema.sql, and pg_catalog must agree.",
        "severity": "blocking",
        "enabled": True,
        "blocks_gate": True,
    },
    {
        "rule_code": "TRUTH-003",
        "tier": "truth",
        "category": "unguarded_write",
        "title": "Table mutated directly from HTTP route without service/DB door",
        "rationale": "Database truth writes belong behind explicit transactional service doors or SQL write-lane functions.",
        "severity": "blocking",
        "enabled": True,
        "blocks_gate": True,
    },
    {
        "rule_code": "TRUTH-004",
        "tier": "truth",
        "category": "ephemeral_shadow_truth",
        "title": "Unbounded Redis write without TTL risks volatile shadow truth",
        "rationale": "Redis is an ephemeral cache/broker; SET/HSET writes without explicit TTL risk split-brain shadow truth outside durable SQL.",
        "severity": "warning",
        "enabled": True,
        "blocks_gate": False,
    },
    {
        "rule_code": "TRUTH-005",
        "tier": "truth",
        "category": "unmigrated_truth",
        "title": "Table exists in the live database but no migration or schema.sql creates it",
        "rationale": "A table that only exists live cannot be rebuilt from source; it was created out of band or its DDL is not recognized.",
        "severity": "warning",
        "enabled": True,
        "blocks_gate": False,
    },
    {
        "rule_code": "MANIP-001",
        "tier": "manipulate",
        "category": "policy_in_code",
        "title": "Mutable domain policy or threshold constant hardcoded in Python",
        "rationale": "Thresholds, capacities, weights, and editable vocabularies belong in PostgreSQL truth, not Python literals.",
        "severity": "blocking",
        "enabled": True,
        "blocks_gate": True,
    },
    {
        "rule_code": "MANIP-002",
        "tier": "manipulate",
        "category": "raw_host_clock",
        "title": "Direct host date.today() or naive datetime.now()/utcnow() in manipulation code",
        "rationale": "Domain manipulation must read time from a single program/database clock authority.",
        "severity": "blocking",
        "enabled": True,
        "blocks_gate": True,
    },
    {
        "rule_code": "MANIP-003",
        "tier": "manipulate",
        "category": "inert_mechanism",
        "title": "Manipulator module has no verified inbound route, CLI, or service caller",
        "rationale": "Named mechanisms that nothing calls give false confidence even when unit tests pass.",
        "severity": "warning",
        "enabled": True,
        "blocks_gate": False,
    },
    {
        "rule_code": "DISP-001",
        "tier": "display",
        "category": "client_policy_shadow",
        "title": "Display tier defines domain policy thresholds or vocabulary shadows",
        "rationale": "TypeScript displays truth; it must not invent parallel policy maps or capacity calculations.",
        "severity": "blocking",
        "enabled": True,
        "blocks_gate": True,
    },
    {
        "rule_code": "DISP-002",
        "tier": "display",
        "category": "raw_browser_clock",
        "title": "Display tier uses raw new Date() as today or UTC ISO date slicing",
        "rationale": "Client clock slicing shifts calendar days across time zones; format server-supplied instants explicitly.",
        "severity": "blocking",
        "enabled": True,
        "blocks_gate": True,
    },
    {
        "rule_code": "DISP-003",
        "tier": "display",
        "category": "untyped_contract",
        "title": "Frontend API adapter bypasses OpenAPI-generated schema types",
        "rationale": "Frontend API clients should bind to generated OpenAPI types so contract drift fails compilation.",
        "severity": "warning",
        "enabled": True,
        "blocks_gate": False,
    },
    {
        "rule_code": "DISP-004",
        "tier": "display",
        "category": "unbacked_endpoint",
        "title": "Display API call targets an HTTP route absent from backend router graph",
        "rationale": "Every frontend query or mutation path must resolve to a real backend route handler.",
        "severity": "blocking",
        "enabled": True,
        "blocks_gate": True,
    },
    {
        "rule_code": "DISP-005",
        "tier": "display",
        "category": "unaccessible_surface",
        "title": "Display markup violates core WCAG accessibility semantics",
        "rationale": "Tier 3 displays truth to all humans; images need alt text, controls need accessible names, and click targets need keyboard semantics.",
        "severity": "warning",
        "enabled": True,
        "blocks_gate": False,
    },
    {
        "rule_code": "DISP-006",
        "tier": "display",
        "category": "unresolved_endpoint",
        "title": "Display API call path is built at runtime and cannot be resolved statically",
        "rationale": "A path segment filled in at runtime may match a real route; Wythe reports it for review instead of calling it broken.",
        "severity": "warning",
        "enabled": True,
        "blocks_gate": False,
    },
    {
        "rule_code": "DISP-007",
        "tier": "display",
        "category": "unreachable_unbacked_endpoint",
        "title": "Unbacked API call in code that no page or layout reaches",
        "rationale": "A call to a missing route that no entry point can trigger is dead code to remove or repoint, not a user-facing outage.",
        "severity": "warning",
        "enabled": True,
        "blocks_gate": False,
    },
)

INITIAL_VOCABULARY_ITEMS: tuple[tuple[str, str, str], ...] = (
    ("scheduling", "WEIGHT", "Objective/preference weight belonging in persisted policy truth."),
    ("scheduling", "CAPACITY", "Slot or resource capacity ceiling."),
    ("scheduling", "PENALTY", "Soft-constraint penalty coefficient."),
    ("scheduling", "RATIO", "Supervision or staffing ratio rule."),
    ("scheduling", "DUTY_HOUR", "ACGME/program duty-hour cap."),
    ("scheduling", "WORK_HOUR", "Work-hour envelope threshold."),
    ("scheduling", "WORKLOAD", "Workload target or ceiling."),
    ("scheduling", "SHIFT_CAP", "Maximum shift count rule."),
    ("scheduling", "HOUR_LIMIT", "Single-period hour limit."),
    ("scheduling", "HOURS_LIMIT", "Multi-period hours limit."),
    ("scheduling", "CLINIC_MAX", "Upper clinic half-day bound."),
    ("scheduling", "CLINIC_MIN", "Lower clinic half-day bound."),
    ("scheduling", "WEEKLY_MAX", "Weekly maximum policy bound."),
    ("scheduling", "WEEKLY_MIN", "Weekly minimum policy bound."),
    ("scheduling", "CALL_CAP", "Call frequency cap."),
    ("scheduling", "SUPERVISION", "Attending-to-learner supervision requirement."),
    ("scheduling", "CADENCE", "Recurrence/cadence interval rule."),
    ("scheduling", "CUTOFF_DAYS", "Operational cutoff window in days."),
    ("scheduling", "THRESHOLD", "Domain decision threshold."),
    ("fintech", "FEE_BPS", "Basis-point fee schedule belonging in ledger/pricing tables."),
    ("fintech", "MARGIN_FLOOR", "Minimum margin floor policy."),
    ("fintech", "LTV_CAP", "Loan-to-value risk cap."),
    ("fintech", "MAX_SLIPPAGE", "Execution slippage ceiling."),
    ("commerce", "DISCOUNT_CAP", "Promotional discount ceiling."),
    ("commerce", "FREE_SHIPPING_MIN", "Order minimum for free-shipping eligibility."),
    ("commerce", "MARKUP_PCT", "Pricing markup percentage rule."),
    ("saas", "QUOTA_LIMIT", "Tenant plan quota limit."),
    ("saas", "SEAT_CAP", "Subscription seat ceiling."),
    ("saas", "BURST_CEILING", "Rate/burst entitlement ceiling."),
)


def seed_catalog_if_needed(session: Session) -> None:
    """Insert missing catalog profiles, rules, and default workspace targets without overwriting."""
    now = utc_now()
    today = utc_today()

    existing_profiles = {
        p.slug: p for p in session.scalars(select(StackProfile)).all()
    }
    for item in INITIAL_STACK_PROFILES:
        slug = str(item["slug"])
        prev = existing_profiles.get(slug)
        if prev is None:
            session.add(StackProfile(**item, created_at=now))
        elif prev.implementation_status != item["implementation_status"] and item[
            "implementation_status"
        ] in ("implemented", "experimental"):
            was_planned = prev.implementation_status == "planned"
            prev.label = str(item["label"])
            prev.truth_adapter = str(item["truth_adapter"])
            prev.manipulator_adapter = str(item["manipulator_adapter"])
            prev.display_adapter = str(item["display_adapter"])
            prev.implementation_status = str(item["implementation_status"])
            if was_planned or prev.implementation_status == "implemented":
                prev.is_enabled = bool(item["is_enabled"])
            prev.description = str(item["description"])

    existing_rules = set(session.scalars(select(RulePolicy.rule_code)).all())
    for item in INITIAL_RULE_POLICIES:
        if item["rule_code"] not in existing_rules:
            session.add(
                RulePolicy(
                    **item,
                    effective_from=today,
                    updated_by="system-seed",
                    updated_at=now,
                )
            )

    existing_vocabs = {
        (v.domain_pack, v.token)
        for v in session.scalars(select(PolicyVocabulary)).all()
    }
    for pack, token, desc in INITIAL_VOCABULARY_ITEMS:
        if (pack, token) not in existing_vocabs:
            session.add(
                PolicyVocabulary(
                    domain_pack=pack,
                    token=token,
                    description=desc,
                    is_enabled=True,
                    created_by="system-seed",
                    created_at=now,
                )
            )
    session.flush()

    existing_targets = set(session.scalars(select(TargetProject.slug)).all())
    self_repo = Path(__file__).resolve().parents[3]
    if "wythe" not in existing_targets and (self_repo / "backend" / "schema.sql").is_file():
        session.add(
            TargetProject(
                slug="wythe",
                name="Wythe (Self-Dogfood)",
                repo_path=str(self_repo),
                stack_profile_slug="fastapi-sqlalchemy-nextjs",
                backend_subdir="backend",
                frontend_subdir="frontend",
                legacy_snapshot_relpath=None,
                description="Reference 3-tier app proving DB truth, Python manipulation, and TypeScript display.",
                is_active=True,
                created_by="system-seed",
                created_at=now,
                updated_at=now,
            )
        )
    session.commit()
