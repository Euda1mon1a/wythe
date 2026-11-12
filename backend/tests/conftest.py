"""Isolated database and synthetic repository fixtures for Wythe tests."""

from __future__ import annotations

from collections.abc import Generator
from pathlib import Path

import pytest
from sqlalchemy.orm import Session

from app.db.session import get_session_factory
from app.main import initialize_database


@pytest.fixture
def isolated_db_url(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> Generator[str, None, None]:
    """Point Wythe at a per-test SQLite database so live local state is untouched."""
    db_file = tmp_path / "test_wythe.db"
    db_url = f"sqlite:///{db_file}"
    monkeypatch.setenv("WYTHE_DATABASE_URL", db_url)
    monkeypatch.delenv("TRUTH_ATLAS_DATABASE_URL", raising=False)
    get_session_factory.cache_clear()
    initialize_database(db_url)
    try:
        yield db_url
    finally:
        get_session_factory.cache_clear()


@pytest.fixture
def db_session(isolated_db_url: str) -> Generator[Session, None, None]:
    """Yield a seeded SQLAlchemy session against the isolated test database."""
    factory = get_session_factory(isolated_db_url)
    session = factory()
    try:
        yield session
    finally:
        session.close()
