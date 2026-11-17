"""Isolated database and synthetic repository fixtures for Wythe tests."""

from __future__ import annotations

import sys
from collections.abc import Generator
from pathlib import Path

import pytest

_REPO_ROOT = Path(__file__).resolve().parents[2]
for _plugin_src in sorted((_REPO_ROOT / "plugins").glob("*/src")):
    if str(_plugin_src) not in sys.path:
        sys.path.insert(0, str(_plugin_src))
from sqlalchemy.orm import Session

from app.db.session import get_session_factory
from app.main import initialize_database
from app.services.investigation_service import clear_scan_reuse_cache


@pytest.fixture
def isolated_db_url(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> Generator[str, None, None]:
    """Point Wythe at a per-test SQLite database so live local state is untouched."""
    db_file = tmp_path / "test_wythe.db"
    db_url = f"sqlite:///{db_file}"
    monkeypatch.setenv("WYTHE_DATABASE_URL", db_url)
    monkeypatch.delenv("TRUTH_ATLAS_DATABASE_URL", raising=False)
    monkeypatch.delenv("WYTHE_STATE_DIR", raising=False)
    monkeypatch.delenv("TRUTH_ATLAS_STATE_DIR", raising=False)
    clear_scan_reuse_cache()
    get_session_factory.cache_clear()
    initialize_database(db_url)
    try:
        yield db_url
    finally:
        clear_scan_reuse_cache()
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
