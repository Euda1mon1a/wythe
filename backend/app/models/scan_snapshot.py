"""Immutable scan receipts and ratchets stored in database truth."""

from __future__ import annotations

from datetime import datetime

from sqlalchemy import DateTime, ForeignKey, Integer, String, Text, UniqueConstraint
from sqlalchemy.orm import Mapped, mapped_column

from app.core.clock import utc_now
from app.db.base import Base


class ScanSnapshot(Base):
    """Immutable observation record of a 3-tier Truth Atlas scan."""

    __tablename__ = "atlas_scan_snapshots"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    target_id: Mapped[int] = mapped_column(
        Integer,
        ForeignKey("atlas_targets.id", ondelete="CASCADE"),
        nullable=False,
        index=True,
    )
    source_commit: Mapped[str] = mapped_column(String(64), nullable=False)
    observation_source: Mapped[str] = mapped_column(String(64), nullable=False)
    observed_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False, default=utc_now)
    valid_until: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)
    content_digest: Mapped[str] = mapped_column(String(64), nullable=False)
    truth_node_count: Mapped[int] = mapped_column(Integer, nullable=False)
    manipulator_node_count: Mapped[int] = mapped_column(Integer, nullable=False)
    display_node_count: Mapped[int] = mapped_column(Integer, nullable=False)
    verified_edge_count: Mapped[int] = mapped_column(Integer, nullable=False)
    blocking_finding_count: Mapped[int] = mapped_column(Integer, nullable=False)
    warning_finding_count: Mapped[int] = mapped_column(Integer, nullable=False)
    payload_json: Mapped[str] = mapped_column(Text, nullable=False)


class RatchetBaseline(Base):
    """Authorized debt ceiling per target and rule so legacy counts can only ratchet down."""

    __tablename__ = "atlas_ratchet_baselines"
    __table_args__ = (
        UniqueConstraint("target_id", "rule_code", name="uq_ratchet_target_rule"),
    )

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    target_id: Mapped[int] = mapped_column(
        Integer,
        ForeignKey("atlas_targets.id", ondelete="CASCADE"),
        nullable=False,
        index=True,
    )
    rule_code: Mapped[str] = mapped_column(
        String(32),
        ForeignKey("atlas_rule_policies.rule_code", ondelete="CASCADE"),
        nullable=False,
    )
    max_allowed_count: Mapped[int] = mapped_column(Integer, nullable=False)
    recorded_commit: Mapped[str] = mapped_column(String(64), nullable=False)
    recorded_by: Mapped[str] = mapped_column(String(64), nullable=False)
    recorded_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False, default=utc_now)
    note: Mapped[str] = mapped_column(Text, nullable=False, default="")
