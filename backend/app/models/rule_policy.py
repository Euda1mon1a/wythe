"""Persisted domain rule policy catalog — editable in DB without code deployment."""

from __future__ import annotations

from datetime import date, datetime

from sqlalchemy import Boolean, Date, DateTime, Integer, String, Text
from sqlalchemy.orm import Mapped, mapped_column

from app.core.clock import utc_now, utc_today
from app.db.base import Base


class RulePolicy(Base):
    """Authoritative policy row governing a Truth, Manipulate, or Display check."""

    __tablename__ = "atlas_rule_policies"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    rule_code: Mapped[str] = mapped_column(String(32), unique=True, nullable=False, index=True)
    tier: Mapped[str] = mapped_column(String(24), nullable=False, index=True)
    category: Mapped[str] = mapped_column(String(64), nullable=False)
    title: Mapped[str] = mapped_column(String(160), nullable=False)
    rationale: Mapped[str] = mapped_column(Text, nullable=False)
    severity: Mapped[str] = mapped_column(String(24), nullable=False)
    enabled: Mapped[bool] = mapped_column(Boolean, nullable=False, default=True)
    blocks_gate: Mapped[bool] = mapped_column(Boolean, nullable=False, default=True)
    effective_from: Mapped[date] = mapped_column(Date, nullable=False, default=utc_today)
    effective_until: Mapped[date | None] = mapped_column(Date, nullable=True)
    updated_by: Mapped[str] = mapped_column(String(64), nullable=False, default="system-seed")
    updated_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False, default=utc_now)
