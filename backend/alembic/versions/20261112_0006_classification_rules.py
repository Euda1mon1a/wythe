"""Seed TRUTH-005, DISP-006 and DISP-007 classification rules into existing catalogs."""

from __future__ import annotations

import sqlalchemy as sa

from alembic import op
from app.core.clock import utc_now, utc_today
from app.db.seed import INITIAL_RULE_POLICIES

revision = "20261112_0006"
down_revision = "20261111_0005"
branch_labels = None
depends_on = None

_NEW_RULES = ("TRUTH-005", "DISP-006", "DISP-007")


def upgrade() -> None:
    bind = op.get_bind()
    now = utc_now()
    today = utc_today()
    existing_rules = {
        row[0]
        for row in bind.execute(sa.text("SELECT rule_code FROM atlas_rule_policies")).fetchall()
    }
    for item in INITIAL_RULE_POLICIES:
        if item["rule_code"] in _NEW_RULES and item["rule_code"] not in existing_rules:
            bind.execute(
                sa.text(
                    "INSERT INTO atlas_rule_policies "
                    "(rule_code, tier, category, title, rationale, severity, enabled, blocks_gate, effective_from, updated_by, updated_at) "
                    "VALUES (:rule_code, :tier, :category, :title, :rationale, :severity, :enabled, :blocks_gate, :effective_from, :updated_by, :updated_at)"
                ),
                {
                    **item,
                    "effective_from": today,
                    "updated_by": "alembic-0006",
                    "updated_at": now,
                },
            )


def downgrade() -> None:
    bind = op.get_bind()
    bind.execute(
        sa.text(
            "DELETE FROM atlas_rule_policies WHERE rule_code IN ('TRUTH-005', 'DISP-006', 'DISP-007')"
        )
    )
