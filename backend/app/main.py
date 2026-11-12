"""FastAPI application entry point for Wythe."""

from __future__ import annotations

from collections.abc import AsyncIterator
from contextlib import asynccontextmanager
from pathlib import Path

from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from fastapi.staticfiles import StaticFiles

import app.models
from app import __version__
from app.api.routes import api_router
from app.core.config import load_settings
from app.db.base import Base
from app.db.seed import seed_catalog_if_needed
from app.db.session import build_engine, get_session_factory


def initialize_database(database_url: str | None = None) -> None:
    """Ensure tables exist and seed initial stack profiles, rules, and workspace targets."""
    settings = load_settings()
    resolved = database_url or settings.database_url
    engine = build_engine(resolved)
    Base.metadata.create_all(bind=engine)
    factory = get_session_factory(resolved)
    with factory() as session:
        seed_catalog_if_needed(session)


@asynccontextmanager
async def lifespan(_app: FastAPI) -> AsyncIterator[None]:
    initialize_database()
    yield


def create_app() -> FastAPI:
    settings = load_settings()
    application = FastAPI(
        title="Wythe API",
        version=__version__,
        description=(
            "Why -> Therefore: 3-tier architecture & lineage verifier. "
            "PostgreSQL holds truth, Backend manipulates truth, UI displays truth."
        ),
        lifespan=lifespan,
    )
    application.add_middleware(
        CORSMiddleware,
        allow_origins=list(settings.cors_origins),
        allow_credentials=False,
        allow_methods=["GET", "POST", "PATCH", "OPTIONS"],
        allow_headers=["*"],
    )
    application.include_router(api_router, prefix="/api/v1")

    @application.get("/healthz")
    def healthcheck() -> dict[str, str]:
        return {"status": "ok"}

    ui_dist_dir = Path(__file__).resolve().parent / "ui_dist"
    if (ui_dist_dir / "index.html").is_file():
        application.mount(
            "/",
            StaticFiles(directory=str(ui_dist_dir), html=True),
            name="wythe-ui",
        )

    return application


app = create_app()
