"""Add atlas_policy_vocabularies table and TRUTH-004 ephemeral Redis rule."""

from __future__ import annotations

import sqlalchemy as sa

from alembic import op
from app.core.clock import utc_now, utc_today
from app.db.seed import INITIAL_RULE_POLICIES, INITIAL_VOCABULARY_ITEMS

revision = "20261111_0004"
down_revision = "20261111_0003"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.create_table(
        "atlas_policy_vocabularies",
        sa.Column("id", sa.Integer(), primary_key=True, autoincrement=True),
        sa.Column("domain_pack", sa.String(length=32), nullable=False),
        sa.Column("token", sa.String(length=64), nullable=False),
        sa.Column("description", sa.Text(), nullable=False, server_default=""),
        sa.Column("is_enabled", sa.Boolean(), nullable=False, server_default=sa.true()),
        sa.Column("created_by", sa.String(length=64), nullable=False, server_default="system-seed"),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.UniqueConstraint("domain_pack", "token", name="uq_policy_vocab_pack_token"),
    )
    op.create_index("ix_atlas_policy_vocabularies_domain_pack", "atlas_policy_vocabularies", ["domain_pack"])
    op.create_index("ix_atlas_policy_vocabularies_token", "atlas_policy_vocabularies", ["token"])

    bind = op.get_bind()
    now = utc_now()
    today = utc_today()

    rules_tbl = sa.table(
        "atlas_rule_policies",
        sa.column("rule_code", sa.String),
        sa.column("tier", sa.String),
        sa.column("category", sa.String),
        sa.column("title", sa.String),
        sa.column("rationale", sa.Text),
        sa.column("severity", sa.String),
        sa.column("enabled", sa.Boolean),
        sa.column("blocks_gate", sa.Boolean),
        sa.column("effective_from", sa.Date),
        sa.column("updated_by", sa.String),
        sa.column("updated_at", sa.DateTime(timezone=True)),
    )
    existing_rules = {row.rule_code for row in bind.execute(sa.select(rules_tbl.c.rule_code))}
    for item in INITIAL_RULE_POLICIES:
        if item["rule_code"] == "TRUTH-004" and "TRUTH-004" not in existing_rules:
            bind.execute(
                rules_tbl.insert().values(
                    **item,
                    effective_from=today,
                    updated_by="system-seed",
                    updated_at=now,
                )
            )

    vocab_tbl = sa.table(
        "atlas_policy_vocabularies",
        sa.column("domain_pack", sa.String),
        sa.column("token", sa.String),
        sa.column("description", sa.Text),
        sa.column("is_enabled", sa.Boolean),
        sa.column("created_by", sa.String),
        sa.column("created_at", sa.DateTime(timezone=True)),
    )
    for pack, token, desc in INITIAL_VOCABULARY_ITEMS:
        bind.execute(
            vocab_tbl.insert().values(
                domain_pack=pack,
                token=token,
                description=desc,
                is_enabled=True,
                created_by="system-seed",
                created_at=now,
            )
        )


def downgrade() -> None:
    rules_tbl = sa.table("atlas_rule_policies", sa.column("rule_code", sa.String))
    op.execute(rules_tbl.delete().where(rules_tbl.c.rule_code == "TRUTH-004"))
    op.drop_index("ix_atlas_policy_vocabularies_token", table_name="atlas_policy_vocabularies")
    op.drop_index("ix_atlas_policy_vocabularies_domain_pack", table_name="atlas_policy_vocabularies")
    op.drop_table("atlas_policy_vocabularies")
