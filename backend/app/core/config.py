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


def _env_with_legacy(primary: str, legacy: str, default: str) -> str:
    return os.getenv(primary) or os.getenv(legacy) or default


def load_settings() -> Settings:
    """Resolve runtime bind and database URL from environment with safe loopback defaults."""
    state_dir = Path(_env_with_legacy("WYTHE_STATE_DIR", "TRUTH_ATLAS_STATE_DIR", str(DEFAULT_STATE_DIR)))
    state_dir.mkdir(parents=True, exist_ok=True)
    default_sqlite = f"sqlite:///{(state_dir / 'wythe.db').as_posix()}"
    database_url = _env_with_legacy("WYTHE_DATABASE_URL", "TRUTH_ATLAS_DATABASE_URL", default_sqlite)
    api_host = _env_with_legacy("WYTHE_HOST", "TRUTH_ATLAS_HOST", "127.0.0.1")
    api_port = int(_env_with_legacy("WYTHE_PORT", "TRUTH_ATLAS_PORT", "8780"))
    raw_origins = _env_with_legacy(
        "WYTHE_CORS_ORIGINS",
        "TRUTH_ATLAS_CORS_ORIGINS",
        "http://127.0.0.1:3780,http://localhost:3780",
    )
    origins = tuple(origin.strip() for origin in raw_origins.split(",") if origin.strip())
    return Settings(
        database_url=database_url,
        api_host=api_host,
        api_port=api_port,
        cors_origins=origins,
    )
