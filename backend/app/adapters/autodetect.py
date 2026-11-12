"""Repository manifest and directory marker detector paired with DB StackProfile truth."""

from __future__ import annotations

from pathlib import Path

from sqlalchemy import select
from sqlalchemy.orm import Session

from app.models import StackProfile
from app.schemas.atlas import StackDetectionResult


def _find_subdir(repo_root: Path, candidates: tuple[str, ...]) -> str:
    for name in candidates:
        if (repo_root / name).is_dir():
            return name
    return "."


def _read_lower(path: Path) -> str:
    if not path.is_file():
        return ""
    return path.read_text(encoding="utf-8", errors="replace").lower()


def detect_repository_stack(session: Session, raw_repo_path: str) -> StackDetectionResult:
    """Inspect repository markers and resolve the best enabled StackProfile in database truth."""
    repo_root = Path(raw_repo_path).expanduser().resolve()
    if not repo_root.is_dir():
        raise ValueError(f"Repository directory does not exist: {repo_root}")

    signals: list[str] = []
    backend_sub = _find_subdir(
        repo_root,
        ("backend", "server", "api", "src-tauri", "apps/desktop/src-tauri", "apps/api", "apps/server", "apps/backend"),
    )
    frontend_sub = _find_subdir(
        repo_root,
        ("frontend", "web", "client", "ui", "apps/web", "apps/frontend", "apps/client", "apps/desktop"),
    )

    # Django project with root `manage.py` spans sibling app folders (`api/`, `backend/`, `core/`)
    if (repo_root / "manage.py").is_file():
        backend_sub = "."

    # Cargo workspace scan (`crates/*/Cargo.toml`) for Rust backend + WASM UI split
    workspace_cargos: list[tuple[str, str]] = []
    if (repo_root / "crates").is_dir():
        for ctoml in sorted((repo_root / "crates").glob("*/Cargo.toml")):
            rel_c = ctoml.parent.relative_to(repo_root).as_posix()
            workspace_cargos.append((rel_c, _read_lower(ctoml)))
    for rel_c, ctxt in workspace_cargos:
        if any(w in ctxt for w in ("leptos", "dioxus", "yew", "gloo-net", "gloo")):
            frontend_sub = rel_c
            break

    be_dir = repo_root if backend_sub == "." else repo_root / backend_sub
    fe_dir = repo_root if frontend_sub == "." else repo_root / frontend_sub

    root_pkg = _read_lower(repo_root / "package.json")
    fe_pkg = _read_lower(fe_dir / "package.json")
    be_pkg = _read_lower(be_dir / "package.json")
    pyproj = _read_lower(be_dir / "pyproject.toml") + "\n" + _read_lower(repo_root / "pyproject.toml")
    reqs = _read_lower(be_dir / "requirements.txt") + "\n" + _read_lower(repo_root / "requirements.txt")
    be_cargo = (
        _read_lower(be_dir / "Cargo.toml")
        + "\n"
        + _read_lower(repo_root / "Cargo.toml")
        + "\n"
        + "\n".join(ctxt for _, ctxt in workspace_cargos)
    )
    fe_cargo = _read_lower(fe_dir / "Cargo.toml")
    py_deps = pyproj + "\n" + reqs
    js_deps = root_pkg + "\n" + fe_pkg + "\n" + be_pkg

    # 1. Detect Tier 3 (Display)
    if any(w in fe_cargo for w in ("leptos", "dioxus", "yew", "gloo-net", "gloo")) or (repo_root / "Trunk.toml").is_file():
        disp_adapter = "rust-wasm"
        signals.append("Rust WASM UI (Leptos/Dioxus/Yew)")
    elif any((fe_dir / f).exists() or (repo_root / f).exists() for f in ("svelte.config.js", "svelte.config.ts")) or "@sveltejs/kit" in js_deps:
        disp_adapter = "sveltekit"
        signals.append("SvelteKit config / @sveltejs/kit")
    elif any((fe_dir / f).exists() or (repo_root / f).exists() for f in ("nuxt.config.ts", "nuxt.config.js")) or '"vue"' in js_deps or any(fe_dir.glob("src/**/*.vue")):
        disp_adapter = "vue-sfc"
        signals.append("Vue / Nuxt SFC markers")
    elif (
        any((fe_dir / f).exists() or (repo_root / f).exists() for f in ("next.config.js", "next.config.mjs", "next.config.ts"))
        or '"next"' in js_deps
        or (fe_dir / "src" / "app").is_dir()
        or (fe_dir / "pages").is_dir()
        or (frontend_sub != "." and (fe_dir / "app").is_dir())
    ):
        disp_adapter = "typescript-nextjs"
        signals.append("Next.js config / App or Pages Router")
    else:
        disp_adapter = "typescript-react"
        if '"react"' in js_deps or (fe_dir / "vite.config.ts").exists():
            signals.append("React SPA / Vite markers")

    # 2. Detect Tier 2 (Manipulate) & Tier 1 (Truth)
    has_tauri = "tauri" in be_cargo or backend_sub.endswith("src-tauri")
    has_rust = has_tauri or (be_dir / "Cargo.toml").is_file() or (
        (repo_root / "Cargo.toml").is_file()
        and any(w in be_cargo for w in ("axum", "actix-web", "rocket", "tauri", "sqlx", "diesel", "sea-orm"))
    )
    has_go = (be_dir / "go.mod").is_file() or (repo_root / "go.mod").is_file()
    has_django = (
        (be_dir / "manage.py").is_file()
        or (repo_root / "manage.py").is_file()
        or '"django' in py_deps
        or "'django" in py_deps
        or "\ndjango" in reqs
        or reqs.startswith("django")
    )
    has_fastapi = "fastapi" in py_deps or (be_dir / "app" / "main.py").is_file()
    has_prisma = (
        (be_dir / "prisma" / "schema.prisma").is_file()
        or (repo_root / "prisma" / "schema.prisma").is_file()
        or '"prisma"' in js_deps
        or '"@prisma/client"' in js_deps
    )
    has_drizzle = (
        any((d / f).is_file() for d in (be_dir, repo_root) for f in ("drizzle.config.ts", "drizzle.config.js"))
        or "drizzle-orm" in js_deps
    )

    if has_rust:
        manip_adapter = "rust-http"
        truth_adapter = "rust-sql"
        signals.append("Rust Cargo.toml (Tauri/axum/actix + sqlx/Diesel/SeaORM)")
    elif has_go:
        manip_adapter = "go-http"
        truth_adapter = "sql-ddl"
        signals.append("Go go.mod + SQL/sqlc")
    elif has_django:
        manip_adapter = "python-django"
        truth_adapter = "django-orm"
        signals.append("Django manage.py / ORM")
    elif has_fastapi:
        manip_adapter = "python-fastapi"
        truth_adapter = "postgres-sqlalchemy"
        signals.append("FastAPI + SQLAlchemy")
    elif has_prisma:
        manip_adapter = "typescript-node"
        truth_adapter = "prisma-schema"
        signals.append("Prisma schema + TypeScript/Node")
    elif has_drizzle:
        manip_adapter = "typescript-node"
        truth_adapter = "drizzle-orm"
        signals.append("Drizzle ORM + TypeScript/Node")
    else:
        manip_adapter = "python-fastapi"
        truth_adapter = "postgres-sqlalchemy"

    enabled_profiles = session.scalars(
        select(StackProfile).where(StackProfile.is_enabled.is_(True)).order_by(StackProfile.id)
    ).all()

    matched_slug = "fastapi-sqlalchemy-nextjs"
    confidence: str = "fallback"
    candidates = [
        prof
        for prof in enabled_profiles
        if prof.truth_adapter == truth_adapter
        and prof.manipulator_adapter == manip_adapter
        and prof.display_adapter == disp_adapter
    ]
    if candidates:
        if has_tauri:
            tauri_cands = [p for p in candidates if "tauri" in p.slug]
            matched_slug = tauri_cands[0].slug if tauri_cands else candidates[0].slug
        else:
            non_tauri = [p for p in candidates if "tauri" not in p.slug]
            matched_slug = non_tauri[0].slug if non_tauri else candidates[0].slug
        confidence = "high" if signals else "medium"
    else:
        for prof in enabled_profiles:
            if prof.truth_adapter == truth_adapter and prof.manipulator_adapter == manip_adapter:
                matched_slug = prof.slug
                disp_adapter = prof.display_adapter
                confidence = "medium"
                break

    return StackDetectionResult(
        repo_path=str(repo_root),
        recommended_profile_slug=matched_slug,
        truth_adapter=truth_adapter,
        manipulator_adapter=manip_adapter,
        display_adapter=disp_adapter,
        backend_subdir=backend_sub,
        frontend_subdir=frontend_sub,
        confidence=confidence,  # type: ignore[arg-type]
        detected_signals=signals,
    )
