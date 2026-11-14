"""Regressions for independent 3-tier autodetect, partial-coverage adapters, and INCOMPLETE gates (#31)."""

from __future__ import annotations

from pathlib import Path

from sqlalchemy import select
from sqlalchemy.orm import Session

from app.adapters.autodetect import detect_repository_stack
from app.cli import main as cli_main
from app.models import StackProfile, TargetProject
from app.services.diff_and_sarif_service import build_sarif_log
from app.services.scanner_service import run_target_scan


def test_nestjs_kysely_autodetect_extracts_routes_with_no_truth_partial_coverage(
    isolated_db_url: str, db_session: Session, tmp_path: Path
) -> None:
    """Docmost-shaped NestJS + Kysely + React repo must not be misdetected as FastAPI/SQLAlchemy."""
    assert isolated_db_url.startswith("sqlite:")
    repo = tmp_path / "docmost_shape"
    (repo / "apps" / "server" / "src" / "core" / "page").mkdir(parents=True)
    (repo / "apps" / "client" / "src" / "pages").mkdir(parents=True)

    (repo / "apps" / "server" / "package.json").write_text(
        '{"dependencies": {"@nestjs/core": "10.0.0", "@nestjs/common": "10.0.0", "kysely": "0.27.0"}}',
        encoding="utf-8",
    )
    (repo / "apps" / "client" / "package.json").write_text(
        '{"dependencies": {"react": "18.3.0", "react-router-dom": "6.22.0"}}',
        encoding="utf-8",
    )
    (repo / "apps" / "client" / "vite.config.ts").write_text("export default {};\n", encoding="utf-8")
    (repo / "apps" / "server" / "src" / "core" / "page" / "page.controller.ts").write_text(
        "import { Controller, Post } from '@nestjs/common';\n"
        "@Controller('/api/pages')\n"
        "export class PageController {\n"
        "  @Post('info')\n"
        "  getInfo() { return { ok: true }; }\n"
        "}\n",
        encoding="utf-8",
    )
    (repo / "apps" / "client" / "src" / "pages" / "PageView.tsx").write_text(
        "export function PageView() { void fetch('/api/pages/info', { method: 'POST' }); return null; }\n",
        encoding="utf-8",
    )

    det = detect_repository_stack(db_session, str(repo))
    assert det.manipulator_adapter == "typescript-node"
    assert det.display_adapter == "typescript-react"
    assert det.backend_subdir == "apps/server"
    assert det.frontend_subdir == "apps/client"
    assert det.truth_adapter == "no-truth"
    assert det.recommended_profile_slug == "node-partial-react"
    assert det.confidence == "medium"
    assert det.coverage_complete is False

    target = TargetProject(
        id=0,
        slug="docmost-shape",
        name="Docmost Shape",
        repo_path=str(repo),
        stack_profile_slug=det.recommended_profile_slug,
        backend_subdir=det.backend_subdir,
        frontend_subdir=det.frontend_subdir,
        description="NestJS + Kysely partial",
        is_active=True,
    )
    report = run_target_scan(db_session, target, strict_gate=True, persist_snapshot=False)
    assert report.summary.manipulator_routes >= 1
    assert report.coverage_complete is False
    assert report.gate.verdict == "INCOMPLETE"
    assert "DISP-004" not in {f.rule_code for f in report.findings}
    assert cli_main(["gate", "--strict", str(repo)]) == 2


def test_immich_shaped_nestjs_sveltekit_ignores_auxiliary_ml_python(
    db_session: Session, tmp_path: Path
) -> None:
    """Immich-shaped NestJS + sql-tools + SvelteKit repo with machine-learning/pyproject.toml."""
    repo = tmp_path / "immich_shape"
    (repo / "server" / "src" / "controllers").mkdir(parents=True)
    (repo / "web" / "src" / "routes").mkdir(parents=True)
    (repo / "machine-learning").mkdir(parents=True)

    (repo / "machine-learning" / "pyproject.toml").write_text(
        '[project]\nname = "immich-ml"\ndependencies = ["fastapi>=0.115.0"]\n',
        encoding="utf-8",
    )
    (repo / "server" / "package.json").write_text(
        '{"dependencies": {"@nestjs/core": "10.0.0", "@immich/sql-tools": "0.1.0", "kysely": "0.27.0"}}',
        encoding="utf-8",
    )
    (repo / "web" / "package.json").write_text(
        '{"devDependencies": {"@sveltejs/kit": "2.0.0"}}',
        encoding="utf-8",
    )
    (repo / "web" / "svelte.config.js").write_text("export default {};\n", encoding="utf-8")
    (repo / "server" / "src" / "controllers" / "album.controller.ts").write_text(
        "import { Controller, Get } from '@nestjs/common';\n"
        "@Controller('/api/albums')\n"
        "export class AlbumController {\n"
        "  @Get()\n"
        "  listAlbums() { return []; }\n"
        "}\n",
        encoding="utf-8",
    )
    (repo / "web" / "src" / "routes" / "+page.svelte").write_text(
        "<script lang='ts'>void fetch('/api/albums');</script>\n",
        encoding="utf-8",
    )

    det = detect_repository_stack(db_session, str(repo))
    assert det.backend_subdir == "server"
    assert det.frontend_subdir == "web"
    assert det.manipulator_adapter == "typescript-node"
    assert det.display_adapter == "sveltekit"
    assert det.truth_adapter == "no-truth"
    assert det.recommended_profile_slug == "node-partial-sveltekit"
    assert det.confidence == "medium"
    assert det.coverage_complete is False


def test_typeorm_unsupported_orm_stays_partial_incomplete(
    isolated_db_url: str, db_session: Session, tmp_path: Path
) -> None:
    """Permanent negative control: unsupported TypeORM uses no-truth and exits 2 on gate."""
    assert isolated_db_url.startswith("sqlite:")
    repo = tmp_path / "typeorm_app"
    (repo / "server" / "src").mkdir(parents=True)
    (repo / "web" / "src").mkdir(parents=True)

    (repo / "server" / "package.json").write_text(
        '{"dependencies": {"@nestjs/core": "10.0.0", "typeorm": "0.3.20"}}',
        encoding="utf-8",
    )
    (repo / "web" / "package.json").write_text('{"dependencies": {"react": "18.3.0"}}', encoding="utf-8")
    (repo / "server" / "src" / "items.controller.ts").write_text(
        "@Controller('/api/items')\nexport class ItemsController {\n  @Get()\n  list() { return []; }\n}\n",
        encoding="utf-8",
    )

    det = detect_repository_stack(db_session, str(repo))
    assert det.truth_adapter == "no-truth"
    assert det.manipulator_adapter == "typescript-node"
    assert det.recommended_profile_slug == "node-partial-react"
    assert det.confidence == "medium"
    assert det.coverage_complete is False
    assert cli_main(["gate", "--strict", str(repo)]) == 2


def test_supported_fastapi_sqlalchemy_stack_reports_high_confidence_and_pass(
    isolated_db_url: str, db_session: Session, tmp_path: Path
) -> None:
    """Explicit FastAPI + SQLAlchemy + Next.js repo achieves high confidence and PASS."""
    assert isolated_db_url.startswith("sqlite:")
    repo = tmp_path / "supported_fastapi"
    (repo / "backend" / "app" / "models").mkdir(parents=True)
    (repo / "backend" / "app" / "services").mkdir(parents=True)
    (repo / "backend" / "app" / "api").mkdir(parents=True)
    (repo / "frontend" / "src" / "app").mkdir(parents=True)

    (repo / "backend" / "pyproject.toml").write_text(
        '[project]\nname = "api"\ndependencies = ["fastapi", "sqlalchemy"]\n',
        encoding="utf-8",
    )
    (repo / "frontend" / "package.json").write_text('{"dependencies": {"next": "15.0.0"}}', encoding="utf-8")
    (repo / "backend" / "schema.sql").write_text(
        "CREATE TABLE items (id INTEGER PRIMARY KEY, name TEXT NOT NULL);\n",
        encoding="utf-8",
    )
    (repo / "backend" / "app" / "models" / "item.py").write_text(
        "from sqlalchemy.orm import DeclarativeBase, Mapped, mapped_column\n"
        "class Base(DeclarativeBase): pass\n"
        "class Item(Base):\n"
        "    __tablename__ = 'items'\n"
        "    id: Mapped[int] = mapped_column(primary_key=True)\n",
        encoding="utf-8",
    )
    (repo / "backend" / "app" / "services" / "item_service.py").write_text(
        "from sqlalchemy import select\n"
        "from app.models.item import Item\n"
        "def list_items(db):\n"
        "    return db.scalars(select(Item)).all()\n",
        encoding="utf-8",
    )
    (repo / "backend" / "app" / "api" / "routes.py").write_text(
        "from fastapi import APIRouter\n"
        "from app.services.item_service import list_items\n"
        "router = APIRouter()\n"
        "@router.get('/items')\n"
        "def get_items():\n"
        "    return list_items(None)\n",
        encoding="utf-8",
    )
    (repo / "backend" / "app" / "main.py").write_text(
        "from fastapi import FastAPI\n"
        "from app.api.routes import router\n"
        "app = FastAPI()\n"
        "app.include_router(router, prefix='/api/v1')\n",
        encoding="utf-8",
    )
    (repo / "frontend" / "src" / "app" / "api-generated.ts").write_text("export interface paths {}\n", encoding="utf-8")
    (repo / "frontend" / "src" / "app" / "page.tsx").write_text(
        "import type { paths } from './api-generated';\n"
        "export default function Page() { void fetch('/api/v1/items'); return <main><h1>Items</h1></main>; }\n",
        encoding="utf-8",
    )

    det = detect_repository_stack(db_session, str(repo))
    assert det.recommended_profile_slug == "fastapi-sqlalchemy-nextjs"
    assert det.confidence == "high"
    assert det.coverage_complete is True
    assert cli_main(["gate", "--strict", str(repo)]) == 0


def test_frontend_only_repo_reports_incomplete_and_disp_008_instead_of_disp_004(
    isolated_db_url: str, db_session: Session, tmp_path: Path
) -> None:
    """Frontend-only repo cannot pretend backend coverage succeeded or mark calls DISP-004."""
    assert isolated_db_url.startswith("sqlite:")
    repo = tmp_path / "spa_only"
    (repo / "src" / "pages").mkdir(parents=True)
    (repo / "package.json").write_text('{"dependencies": {"react": "18.3.0"}}', encoding="utf-8")
    (repo / "vite.config.ts").write_text("export default {};\n", encoding="utf-8")
    (repo / "src" / "pages" / "HomePage.tsx").write_text(
        "export function HomePage() { void fetch('/api/items'); return <main><h1>Home</h1></main>; }\n",
        encoding="utf-8",
    )

    det = detect_repository_stack(db_session, str(repo))
    assert det.recommended_profile_slug == "frontend-only-react"
    assert det.manipulator_adapter == "no-manipulator"
    assert det.truth_adapter == "no-truth"
    assert det.display_adapter == "typescript-react"
    assert det.confidence == "fallback"
    assert det.coverage_complete is False

    target = TargetProject(
        id=0,
        slug="spa-only",
        name="SPA Only",
        repo_path=str(repo),
        stack_profile_slug=det.recommended_profile_slug,
        backend_subdir=det.backend_subdir,
        frontend_subdir=det.frontend_subdir,
        description="Frontend only",
        is_active=True,
    )
    report = run_target_scan(db_session, target, strict_gate=True, persist_snapshot=False)
    codes = {f.rule_code for f in report.findings}
    assert "DISP-008" in codes
    assert "DISP-004" not in codes
    assert "DISP-007" not in codes
    assert report.coverage_complete is False
    assert report.gate.verdict == "INCOMPLETE"

    sarif = build_sarif_log(report)
    assert sarif["runs"][0]["invocations"][0]["executionSuccessful"] is False
    assert cli_main(["gate", "--strict", str(repo)]) == 2


def test_preserves_detected_display_framework_even_on_profile_fallback(
    db_session: Session, tmp_path: Path
) -> None:
    """Plane-shaped Django + Next.js App Router must select django-nextjs and preserve display_adapter on fallback."""
    repo = tmp_path / "plane_shape"
    (repo / "apps" / "api" / "plane").mkdir(parents=True)
    (repo / "apps" / "web" / "app").mkdir(parents=True)
    (repo / "apps" / "api" / "manage.py").write_text("#!/usr/bin/env python\n", encoding="utf-8")
    (repo / "apps" / "web" / "package.json").write_text('{"dependencies": {"react": "18.3.0"}}', encoding="utf-8")
    (repo / "apps" / "web" / "app" / "page.tsx").write_text("export default function P() { return null; }\n", encoding="utf-8")

    det = detect_repository_stack(db_session, str(repo))
    assert det.display_adapter == "typescript-nextjs"
    assert det.recommended_profile_slug == "django-nextjs"
    assert det.confidence == "high"

    # Disable django-nextjs to prove fallback never overwrites detected display_adapter.
    prof = db_session.scalar(select(StackProfile).where(StackProfile.slug == "django-nextjs"))
    assert prof is not None
    prof.is_enabled = False
    db_session.commit()

    det_fallback = detect_repository_stack(db_session, str(repo))
    assert det_fallback.recommended_profile_slug == "django-react"
    assert det_fallback.display_adapter == "typescript-nextjs"
    assert det_fallback.confidence == "fallback"
    assert any("preserving detected display adapter" in s for s in det_fallback.detected_signals)
