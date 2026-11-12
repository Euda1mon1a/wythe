"""Seed DISP-005 WCAG display rule, postgres-drizzle-sveltekit, and canonical OSS profile slugs."""

from __future__ import annotations

import sqlalchemy as sa

from alembic import op
from app.core.clock import utc_now, utc_today
from app.db.seed import INITIAL_RULE_POLICIES, INITIAL_STACK_PROFILES

revision = "20261111_0005"
down_revision = "20261111_0004"
branch_labels = None
depends_on = None


def upgrade() -> None:
    bind = op.get_bind()
    now = utc_now()
    today = utc_today()

    existing_rules = {
        row[0]
        for row in bind.execute(sa.text("SELECT rule_code FROM atlas_rule_policies")).fetchall()
    }
    for item in INITIAL_RULE_POLICIES:
        if item["rule_code"] not in existing_rules:
            bind.execute(
                sa.text(
                    "INSERT INTO atlas_rule_policies "
                    "(rule_code, tier, category, title, rationale, severity, enabled, blocks_gate, effective_from, updated_by, updated_at) "
                    "VALUES (:rule_code, :tier, :category, :title, :rationale, :severity, :enabled, :blocks_gate, :effective_from, :updated_by, :updated_at)"
                ),
                {
                    **item,
                    "effective_from": today,
                    "updated_by": "alembic-0005",
                    "updated_at": now,
                },
            )

    existing_profiles = {
        row[0]
        for row in bind.execute(sa.text("SELECT slug FROM atlas_stack_profiles")).fetchall()
    }
    for prof in INITIAL_STACK_PROFILES:
        if prof["slug"] not in existing_profiles:
            bind.execute(
                sa.text(
                    "INSERT INTO atlas_stack_profiles "
                    "(slug, label, truth_adapter, manipulator_adapter, display_adapter, implementation_status, is_enabled, description, created_at) "
                    "VALUES (:slug, :label, :truth_adapter, :manipulator_adapter, :display_adapter, :implementation_status, :is_enabled, :description, :created_at)"
                ),
                {**prof, "created_at": now},
            )


def downgrade() -> None:
    bind = op.get_bind()
    bind.execute(sa.text("DELETE FROM atlas_rule_policies WHERE rule_code = 'DISP-005'"))
    bind.execute(
        sa.text(
            "DELETE FROM atlas_stack_profiles WHERE slug IN ('postgres-drizzle-sveltekit', 'postgres-swift-swiftui')"
        )
    )
