"""Add Rust 3-tier stack profiles (`rust-sql`, `rust-http`, `rust-wasm`) to catalog."""

from __future__ import annotations

import sqlalchemy as sa

from alembic import op
from app.core.clock import utc_now
from app.db.seed import INITIAL_STACK_PROFILES

revision = "20261111_0003"
down_revision = "20261111_0002"
branch_labels = None
depends_on = None

_RUST_SLUGS = (
    "rust-axum-react",
    "rust-axum-nextjs",
    "rust-axum-sveltekit",
    "rust-fullstack-wasm",
)


def upgrade() -> None:
    bind = op.get_bind()
    profiles_tbl = sa.table(
        "atlas_stack_profiles",
        sa.column("slug", sa.String),
        sa.column("label", sa.String),
        sa.column("truth_adapter", sa.String),
        sa.column("manipulator_adapter", sa.String),
        sa.column("display_adapter", sa.String),
        sa.column("implementation_status", sa.String),
        sa.column("is_enabled", sa.Boolean),
        sa.column("description", sa.Text),
        sa.column("created_at", sa.DateTime(timezone=True)),
    )
    existing = {row.slug for row in bind.execute(sa.select(profiles_tbl.c.slug))}
    now = utc_now()
    for item in INITIAL_STACK_PROFILES:
        slug = str(item["slug"])
        if slug in _RUST_SLUGS and slug not in existing:
            bind.execute(profiles_tbl.insert().values(**item, created_at=now))


def downgrade() -> None:
    profiles_tbl = sa.table("atlas_stack_profiles", sa.column("slug", sa.String))
    op.execute(profiles_tbl.delete().where(profiles_tbl.c.slug.in_(_RUST_SLUGS)))
