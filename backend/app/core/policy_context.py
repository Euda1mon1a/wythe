"""Scoped execution context supplying DB-backed policy vocabulary tokens to tier adapters."""

from __future__ import annotations

from collections.abc import Iterator
from contextlib import contextmanager
from contextvars import ContextVar

DEFAULT_FALLBACK_TOKENS: tuple[str, ...] = (
    "WEIGHT",
    "CAPACITY",
    "PENALTY",
    "RATIO",
    "DUTY_HOUR",
    "WORK_HOUR",
    "WORKLOAD",
    "SHIFT_CAP",
    "HOUR_LIMIT",
    "HOURS_LIMIT",
    "CLINIC_MAX",
    "CLINIC_MIN",
    "WEEKLY_MAX",
    "WEEKLY_MIN",
    "CALL_CAP",
    "SUPERVISION",
    "CADENCE",
    "CUTOFF_DAYS",
    "THRESHOLD",
)

_ACTIVE_TOKENS: ContextVar[tuple[str, ...] | None] = ContextVar(
    "truth_atlas_active_policy_tokens", default=None
)


def get_active_policy_tokens() -> tuple[str, ...]:
    """Return active uppercase policy tokens from DB truth (or fallback defaults outside scans)."""
    override = _ACTIVE_TOKENS.get()
    return override if override is not None else DEFAULT_FALLBACK_TOKENS


@contextmanager
def policy_tokens_scope(tokens: tuple[str, ...]) -> Iterator[None]:
    """Bind DB-queried `PolicyVocabulary` tokens for the duration of a target scan."""
    handle = _ACTIVE_TOKENS.set(tokens)
    try:
        yield
    finally:
        _ACTIVE_TOKENS.reset(handle)
