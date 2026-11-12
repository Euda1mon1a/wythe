"""Persisted domain policy vocabulary tokens — customizable per industry/project in DB truth."""

from __future__ import annotations

from datetime import datetime

from sqlalchemy import Boolean, DateTime, Integer, String, Text, UniqueConstraint
from sqlalchemy.orm import Mapped, mapped_column

from app.core.clock import utc_now
from app.db.base import Base


class PolicyVocabulary(Base):
    """Authoritative token substring used by MANIP-001 & DISP-001 shadow-policy detectors."""

    __tablename__ = "atlas_policy_vocabularies"
    __table_args__ = (
        UniqueConstraint("domain_pack", "token", name="uq_policy_vocab_pack_token"),
    )

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    domain_pack: Mapped[str] = mapped_column(String(32), nullable=False, index=True)
    token: Mapped[str] = mapped_column(String(64), nullable=False, index=True)
    description: Mapped[str] = mapped_column(Text, nullable=False, default="")
    is_enabled: Mapped[bool] = mapped_column(Boolean, nullable=False, default=True)
    created_by: Mapped[str] = mapped_column(String(64), nullable=False, default="system-seed")
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False, default=utc_now)
