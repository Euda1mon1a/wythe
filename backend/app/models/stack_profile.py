"""Persisted catalog of 3-tier language/framework stack profiles."""

from __future__ import annotations

from datetime import datetime

from sqlalchemy import Boolean, DateTime, Integer, String, Text
from sqlalchemy.orm import Mapped, mapped_column

from app.core.clock import utc_now
from app.db.base import Base


class StackProfile(Base):
    """Catalog row defining a Truth + Manipulate + Display adapter triad."""

    __tablename__ = "atlas_stack_profiles"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    slug: Mapped[str] = mapped_column(String(64), unique=True, nullable=False, index=True)
    label: Mapped[str] = mapped_column(String(128), nullable=False)
    truth_adapter: Mapped[str] = mapped_column(String(64), nullable=False)
    manipulator_adapter: Mapped[str] = mapped_column(String(64), nullable=False)
    display_adapter: Mapped[str] = mapped_column(String(64), nullable=False)
    implementation_status: Mapped[str] = mapped_column(String(32), nullable=False)
    is_enabled: Mapped[bool] = mapped_column(Boolean, nullable=False, default=True)
    description: Mapped[str] = mapped_column(Text, nullable=False)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False, default=utc_now)
