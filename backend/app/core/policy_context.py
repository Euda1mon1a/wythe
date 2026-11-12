"""Scoped execution context supplying DB-backed policy vocabulary tokens to tier adapters."""

from __future__ import annotations

import functools
import re
from collections.abc import Iterable, Iterator
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


@functools.lru_cache(maxsize=512)
def _policy_token_re(token: str) -> re.Pattern[str]:
    """Match a policy token on whole `_`-separated name segments, allowing a plural.

    `RATIO` matches `REVIEW_RATIO` and `PGY1_RATIOS` but not `DURATION`, `ITERATIONS` or
    `GENERATION`. A token with a leading or trailing `_` (e.g. `_CODES`) keeps requiring a
    segment on that side.
    """
    core = token.strip("_")
    if not core:
        return re.compile(r"(?!)")
    head = "_" if token.startswith("_") else "(?:^|_)"
    tail = "_" if token.endswith("_") else "(?:_|$)"
    stem = re.escape(core)
    if core.endswith("Y"):
        stem = re.escape(core[:-1]) + "(?:Y|IES)"
    else:
        stem += "(?:S|ES)?"
    return re.compile(f"{head}{stem}{tail}")


def name_has_policy_token(name: str, tokens: Iterable[str]) -> bool:
    return any(_policy_token_re(tok).search(name) for tok in tokens)
