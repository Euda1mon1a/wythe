"""Database engine and session management."""

from __future__ import annotations

from collections.abc import Generator
from functools import lru_cache

from sqlalchemy import create_engine, event
from sqlalchemy.engine import Engine
from sqlalchemy.orm import Session, sessionmaker

from app.core.config import load_settings


def build_engine(database_url: str) -> Engine:
    """Create a SQLAlchemy engine supporting PostgreSQL and local SQLite."""
    connect_args = {"check_same_thread": False} if database_url.startswith("sqlite:") else {}
    engine = create_engine(database_url, future=True, connect_args=connect_args)
    if database_url.startswith("sqlite:"):

        @event.listens_for(engine, "connect")
        def _enable_sqlite_fk(dbapi_connection, _connection_record) -> None:
            cursor = dbapi_connection.cursor()
            cursor.execute("PRAGMA foreign_keys=ON")
            cursor.close()

    return engine


@lru_cache(maxsize=4)
def get_session_factory(database_url: str | None = None) -> sessionmaker[Session]:
    """Return a cached sessionmaker for the configured or supplied database URL."""
    resolved_url = database_url or load_settings().database_url
    engine = build_engine(resolved_url)
    return sessionmaker(bind=engine, autoflush=False, autocommit=False, expire_on_commit=False)


def get_db() -> Generator[Session, None, None]:
    """FastAPI dependency yielding one transactional session per request."""
    factory = get_session_factory()
    db = factory()
    try:
        yield db
    finally:
        db.close()
