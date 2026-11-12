"""Promote multi-language stack profiles in atlas_stack_profiles catalog."""

from __future__ import annotations

import sqlalchemy as sa

from alembic import op
from app.core.clock import utc_now
from app.db.seed import INITIAL_STACK_PROFILES

revision = "20261111_0002"
down_revision = "20261110_0001"
branch_labels = None
depends_on = None


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
    existing = {
        row.slug: row.implementation_status
        for row in bind.execute(sa.select(profiles_tbl.c.slug, profiles_tbl.c.implementation_status))
    }
    now = utc_now()
    for item in INITIAL_STACK_PROFILES:
        slug = str(item["slug"])
        if slug not in existing:
            bind.execute(profiles_tbl.insert().values(**item, created_at=now))
        elif existing[slug] == "planned" and item["implementation_status"] == "implemented":
            bind.execute(
                profiles_tbl.update()
                .where(profiles_tbl.c.slug == slug)
                .values(
                    label=item["label"],
                    truth_adapter=item["truth_adapter"],
                    manipulator_adapter=item["manipulator_adapter"],
                    display_adapter=item["display_adapter"],
                    implementation_status="implemented",
                    is_enabled=item["is_enabled"],
                    description=item["description"],
                )
            )


def downgrade() -> None:
    added_slugs = (
        "nextjs-prisma",
        "node-prisma-react",
        "node-drizzle-react",
        "fastapi-react-spa",
        "fastapi-vue",
        "fastapi-sveltekit",
        "django-react",
        "django-vue",
        "go-sqlc-sveltekit",
    )
    profiles_tbl = sa.table("atlas_stack_profiles", sa.column("slug", sa.String))
    op.execute(profiles_tbl.delete().where(profiles_tbl.c.slug.in_(added_slugs)))
