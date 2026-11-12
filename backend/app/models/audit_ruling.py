"""Dated human ownership rulings and transition provenance (kept separate from status)."""

from __future__ import annotations

from datetime import date, datetime

from sqlalchemy import Date, DateTime, ForeignKey, Integer, String, Text
from sqlalchemy.orm import Mapped, mapped_column

from app.core.clock import utc_now, utc_today
from app.db.base import Base


class AuditRuling(Base):
    """Explicit owner/auditor ruling or cutover provenance anchored to a graph node."""

    __tablename__ = "atlas_audit_rulings"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    target_id: Mapped[int] = mapped_column(
        Integer,
        ForeignKey("atlas_targets.id", ondelete="CASCADE"),
        nullable=False,
        index=True,
    )
    node_id: Mapped[str] = mapped_column(String(160), nullable=False, index=True)
    disposition: Mapped[str] = mapped_column(String(48), nullable=False)
    summary: Mapped[str] = mapped_column(Text, nullable=False)
    cutover_history: Mapped[str | None] = mapped_column(Text, nullable=True)
    audited_commit: Mapped[str] = mapped_column(String(64), nullable=False)
    audited_at: Mapped[date] = mapped_column(Date, nullable=False, default=utc_today)
    effective_from: Mapped[date] = mapped_column(Date, nullable=False, default=utc_today)
    effective_until: Mapped[date | None] = mapped_column(Date, nullable=True)
    recorded_by: Mapped[str] = mapped_column(String(64), nullable=False)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False, default=utc_now)
