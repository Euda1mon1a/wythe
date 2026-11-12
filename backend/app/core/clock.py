"""Single source of time for Truth Atlas backend operations."""

from __future__ import annotations

from datetime import UTC, date, datetime, timedelta


def utc_now() -> datetime:
    """Return an aware UTC instant."""
    return datetime.now(UTC)


def utc_today() -> date:
    """Return the current UTC calendar date from the shared clock module."""
    return utc_now().date()


def valid_until_from(observed_at: datetime, ttl_seconds: int = 3600) -> datetime:
    """Compute bounded freshness expiry from an observation timestamp."""
    return observed_at + timedelta(seconds=ttl_seconds)
