"""Runtime configuration for Wythe (infrastructure wiring, not domain policy)."""

from __future__ import annotations

import os
from dataclasses import dataclass
from pathlib import Path

DEFAULT_STATE_DIR = Path.home() / ".local" / "state" / "wythe"


@dataclass(frozen=True)
class Settings:
    """Infrastructure connection and bind settings."""

    database_url: str
    api_host: str
    api_port: int
    cors_origins: tuple[str, ...]
    state_dir: Path = DEFAULT_STATE_DIR
    allowed_hosts: tuple[str, ...] = ("127.0.0.1", "localhost", "::1", "[::1]")


def _env_with_legacy(primary: str, legacy: str, default: str) -> str:
    return os.getenv(primary) or os.getenv(legacy) or default


def load_settings() -> Settings:
    """Resolve runtime bind and database URL from environment with safe loopback defaults."""
    explicit_db = os.getenv("WYTHE_DATABASE_URL") or os.getenv("TRUTH_ATLAS_DATABASE_URL")
    explicit_state = os.getenv("WYTHE_STATE_DIR") or os.getenv("TRUTH_ATLAS_STATE_DIR")
    default_state = Path.home() / ".local" / "state" / "wythe"
    if explicit_db:
        database_url = explicit_db
        if explicit_state:
            state_dir = Path(explicit_state)
            state_dir.mkdir(parents=True, exist_ok=True)
        elif explicit_db.startswith("sqlite:///") and ":memory:" not in explicit_db:
            state_dir = Path(explicit_db.removeprefix("sqlite:///")).expanduser().resolve().parent
        else:
            state_dir = default_state
    else:
        state_dir = Path(explicit_state) if explicit_state else default_state
        state_dir.mkdir(parents=True, exist_ok=True)
        database_url = f"sqlite:///{(state_dir / 'wythe.db').as_posix()}"
    api_host = _env_with_legacy("WYTHE_HOST", "TRUTH_ATLAS_HOST", "127.0.0.1")
    api_port = int(_env_with_legacy("WYTHE_PORT", "TRUTH_ATLAS_PORT", "8780"))
    raw_origins = _env_with_legacy(
        "WYTHE_CORS_ORIGINS",
        "TRUTH_ATLAS_CORS_ORIGINS",
        "http://127.0.0.1:3780,http://localhost:3780",
    )
    origins = tuple(origin.strip() for origin in raw_origins.split(",") if origin.strip())
    raw_allowed = os.getenv("WYTHE_ALLOWED_HOSTS", "")
    host_list: list[str] = ["127.0.0.1", "localhost", "::1", "[::1]"]
    if api_host and api_host not in ("0.0.0.0", "::", "*", *host_list):
        host_list.append(api_host.strip().lower())
    for item in raw_allowed.split(","):
        cleaned = item.strip().lower()
        if cleaned and cleaned not in host_list:
            host_list.append(cleaned)
    return Settings(
        database_url=database_url,
        api_host=api_host,
        api_port=api_port,
        cors_origins=origins,
        state_dir=state_dir,
        allowed_hosts=tuple(host_list),
    )
