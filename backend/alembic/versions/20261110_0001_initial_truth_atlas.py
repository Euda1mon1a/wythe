"""Initial Truth Atlas domain tables and immutable scan guard."""

from __future__ import annotations

import sqlalchemy as sa

from alembic import op

revision = "20261110_0001"
down_revision = None
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.create_table(
        "atlas_stack_profiles",
        sa.Column("id", sa.Integer(), primary_key=True, autoincrement=True),
        sa.Column("slug", sa.String(64), nullable=False, unique=True),
        sa.Column("label", sa.String(128), nullable=False),
        sa.Column("truth_adapter", sa.String(64), nullable=False),
        sa.Column("manipulator_adapter", sa.String(64), nullable=False),
        sa.Column("display_adapter", sa.String(64), nullable=False),
        sa.Column("implementation_status", sa.String(32), nullable=False),
        sa.Column("is_enabled", sa.Boolean(), nullable=False),
        sa.Column("description", sa.Text(), nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
    )
    op.create_table(
        "atlas_targets",
        sa.Column("id", sa.Integer(), primary_key=True, autoincrement=True),
        sa.Column("slug", sa.String(64), nullable=False, unique=True),
        sa.Column("name", sa.String(128), nullable=False),
        sa.Column("repo_path", sa.Text(), nullable=False),
        sa.Column("stack_profile_slug", sa.String(64), sa.ForeignKey("atlas_stack_profiles.slug"), nullable=False),
        sa.Column("backend_subdir", sa.String(128), nullable=False),
        sa.Column("frontend_subdir", sa.String(128), nullable=False),
        sa.Column("legacy_snapshot_relpath", sa.Text(), nullable=True),
        sa.Column("description", sa.Text(), nullable=False),
        sa.Column("is_active", sa.Boolean(), nullable=False),
        sa.Column("created_by", sa.String(64), nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("updated_at", sa.DateTime(timezone=True), nullable=False),
    )
    op.create_table(
        "atlas_rule_policies",
        sa.Column("id", sa.Integer(), primary_key=True, autoincrement=True),
        sa.Column("rule_code", sa.String(32), nullable=False, unique=True),
        sa.Column("tier", sa.String(24), nullable=False),
        sa.Column("category", sa.String(64), nullable=False),
        sa.Column("title", sa.String(160), nullable=False),
        sa.Column("rationale", sa.Text(), nullable=False),
        sa.Column("severity", sa.String(24), nullable=False),
        sa.Column("enabled", sa.Boolean(), nullable=False),
        sa.Column("blocks_gate", sa.Boolean(), nullable=False),
        sa.Column("effective_from", sa.Date(), nullable=False),
        sa.Column("effective_until", sa.Date(), nullable=True),
        sa.Column("updated_by", sa.String(64), nullable=False),
        sa.Column("updated_at", sa.DateTime(timezone=True), nullable=False),
    )
    op.create_table(
        "atlas_scan_snapshots",
        sa.Column("id", sa.Integer(), primary_key=True, autoincrement=True),
        sa.Column("target_id", sa.Integer(), sa.ForeignKey("atlas_targets.id"), nullable=False),
        sa.Column("source_commit", sa.String(64), nullable=False),
        sa.Column("observation_source", sa.String(64), nullable=False),
        sa.Column("observed_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("valid_until", sa.DateTime(timezone=True), nullable=False),
        sa.Column("content_digest", sa.String(64), nullable=False),
        sa.Column("truth_node_count", sa.Integer(), nullable=False),
        sa.Column("manipulator_node_count", sa.Integer(), nullable=False),
        sa.Column("display_node_count", sa.Integer(), nullable=False),
        sa.Column("verified_edge_count", sa.Integer(), nullable=False),
        sa.Column("blocking_finding_count", sa.Integer(), nullable=False),
        sa.Column("warning_finding_count", sa.Integer(), nullable=False),
        sa.Column("payload_json", sa.Text(), nullable=False),
    )
    op.create_table(
        "atlas_ratchet_baselines",
        sa.Column("id", sa.Integer(), primary_key=True, autoincrement=True),
        sa.Column("target_id", sa.Integer(), sa.ForeignKey("atlas_targets.id"), nullable=False),
        sa.Column("rule_code", sa.String(32), sa.ForeignKey("atlas_rule_policies.rule_code"), nullable=False),
        sa.Column("max_allowed_count", sa.Integer(), nullable=False),
        sa.Column("recorded_commit", sa.String(64), nullable=False),
        sa.Column("recorded_by", sa.String(64), nullable=False),
        sa.Column("recorded_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("note", sa.Text(), nullable=False),
        sa.UniqueConstraint("target_id", "rule_code", name="uq_ratchet_target_rule"),
    )
    op.create_table(
        "atlas_audit_rulings",
        sa.Column("id", sa.Integer(), primary_key=True, autoincrement=True),
        sa.Column("target_id", sa.Integer(), sa.ForeignKey("atlas_targets.id"), nullable=False),
        sa.Column("node_id", sa.String(160), nullable=False),
        sa.Column("disposition", sa.String(48), nullable=False),
        sa.Column("summary", sa.Text(), nullable=False),
        sa.Column("cutover_history", sa.Text(), nullable=True),
        sa.Column("audited_commit", sa.String(64), nullable=False),
        sa.Column("audited_at", sa.Date(), nullable=False),
        sa.Column("effective_from", sa.Date(), nullable=False),
        sa.Column("effective_until", sa.Date(), nullable=True),
        sa.Column("recorded_by", sa.String(64), nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
    )


def downgrade() -> None:
    op.drop_table("atlas_audit_rulings")
    op.drop_table("atlas_ratchet_baselines")
    op.drop_table("atlas_scan_snapshots")
    op.drop_table("atlas_rule_policies")
    op.drop_table("atlas_targets")
    op.drop_table("atlas_stack_profiles")
