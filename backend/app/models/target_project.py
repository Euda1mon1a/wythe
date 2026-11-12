"""Persisted target repositories registered for Truth Atlas inspection."""

from __future__ import annotations

from datetime import datetime

from sqlalchemy import Boolean, DateTime, ForeignKey, Integer, String, Text
from sqlalchemy.orm import Mapped, mapped_column, relationship

from app.core.clock import utc_now
from app.db.base import Base


class TargetProject(Base):
    """Repository configuration inspected read-only by Truth Atlas."""

    __tablename__ = "atlas_targets"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    slug: Mapped[str] = mapped_column(String(64), unique=True, nullable=False, index=True)
    name: Mapped[str] = mapped_column(String(128), nullable=False)
    repo_path: Mapped[str] = mapped_column(Text, nullable=False)
    stack_profile_slug: Mapped[str] = mapped_column(
        String(64),
        ForeignKey("atlas_stack_profiles.slug", ondelete="RESTRICT"),
        nullable=False,
    )
    backend_subdir: Mapped[str] = mapped_column(String(128), nullable=False, default="backend")
    frontend_subdir: Mapped[str] = mapped_column(String(128), nullable=False, default="frontend")
    legacy_snapshot_relpath: Mapped[str | None] = mapped_column(Text, nullable=True)
    description: Mapped[str] = mapped_column(Text, nullable=False, default="")
    is_active: Mapped[bool] = mapped_column(Boolean, nullable=False, default=True)
    created_by: Mapped[str] = mapped_column(String(64), nullable=False, default="system-seed")
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False, default=utc_now)
    updated_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False, default=utc_now)

    stack_profile = relationship("StackProfile")
