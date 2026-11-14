"""Independent 3-tier repository stack detector paired with DB StackProfile truth."""

from __future__ import annotations

import json
from pathlib import Path

from sqlalchemy import select
from sqlalchemy.orm import Session

from app.models import StackProfile
from app.schemas.atlas import StackDetectionResult

_NODE_BACKEND_DEPS = frozenset(
    {
        "@nestjs/core",
        "@nestjs/common",
        "@nestjs/platform-express",
        "@nestjs/platform-fastify",
        "nest-commander",
        "express",
        "fastify",
        "hono",
        "@hono/node-server",
        "koa",
        "@trpc/server",
    }
)
_JS_FRONTEND_DEPS = frozenset(
    {
        "react",
        "react-dom",
        "vite",
        "@vitejs/plugin-react",
        "@vitejs/plugin-react-swc",
        "react-router",
        "@react-router/dev",
        "@tanstack/react-router",
        "preact",
        "solid-js",
    }
)
_UNSUPPORTED_DB_DEPS: tuple[tuple[str, str], ...] = (
    ("@immich/sql-tools", "@immich/sql-tools"),
    ("kysely", "Kysely"),
    ("kysely-postgres-js", "Kysely"),
    ("nestjs-kysely", "Kysely"),
    ("typeorm", "TypeORM"),
    ("@nestjs/typeorm", "TypeORM"),
    ("sequelize", "Sequelize"),
    ("@mikro-orm/core", "MikroORM"),
    ("mongoose", "Mongoose"),
)


def _find_subdir(repo_root: Path, candidates: tuple[str, ...]) -> str:
    for name in candidates:
        if (repo_root / name).is_dir():
            return name
    return "."


def _read_lower(path: Path) -> str:
    if not path.is_file():
        return ""
    return path.read_text(encoding="utf-8", errors="replace").lower()


def _pkg_deps(pkg_path: Path) -> set[str]:
    if not pkg_path.is_file():
        return set()
    try:
        data = json.loads(pkg_path.read_text(encoding="utf-8"))
    except (OSError, UnicodeDecodeError, ValueError):
        return set()
    if not isinstance(data, dict):
        return set()
    deps: set[str] = set()
    for section in ("dependencies", "devDependencies", "peerDependencies"):
        block = data.get(section)
        if isinstance(block, dict):
            deps.update(str(k).lower() for k in block)
    return deps


def _has_next_api_handlers(base_dir: Path) -> bool:
    for sub in ("pages/api", "src/pages/api", "app/api", "src/app/api"):
        cand = base_dir / sub
        if cand.is_dir() and any(
            p.suffix in (".ts", ".tsx", ".js", ".mjs") for p in cand.rglob("*") if p.is_file()
        ):
            return True
    return False


def _has_sveltekit_server_routes(base_dir: Path) -> bool:
    routes_dir = base_dir / "src" / "routes"
    if not routes_dir.is_dir():
        return False
    return any(
        p.name.startswith("+server.") or p.name.startswith("+page.server.") or p.name.startswith("+layout.server.")
        for p in routes_dir.rglob("+*server*")
        if p.is_file()
    )


def _has_dir_sources(base_dir: Path, exts: tuple[str, ...]) -> bool:
    if not base_dir.is_dir():
        return False
    for p in base_dir.rglob("*"):
        if "node_modules" in p.parts or ".git" in p.parts:
            continue
        if p.is_file() and p.suffix in exts:
            return True
    return False


def detect_repository_stack(session: Session, raw_repo_path: str) -> StackDetectionResult:
    """Inspect repository tiers independently and resolve the best enabled StackProfile."""
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

    if (repo_root / "manage.py").is_file():
        backend_sub = "."

    workspace_cargos: list[tuple[str, str]] = []
    for ctoml in sorted(repo_root.glob("*/Cargo.toml")):
        workspace_cargos.append((ctoml.parent.relative_to(repo_root).as_posix(), _read_lower(ctoml)))
    if (repo_root / "crates").is_dir():
        for ctoml in sorted((repo_root / "crates").glob("*/Cargo.toml")):
            workspace_cargos.append((ctoml.parent.relative_to(repo_root).as_posix(), _read_lower(ctoml)))
    for rel_c, ctxt in workspace_cargos:
        if any(w in ctxt for w in ("leptos", "dioxus", "yew", "gloo-net", "gloo")):
            frontend_sub = rel_c
            break

    be_dir = repo_root if backend_sub == "." else repo_root / backend_sub
    fe_dir = repo_root if frontend_sub == "." else repo_root / frontend_sub

    root_deps = _pkg_deps(repo_root / "package.json")
    be_deps = _pkg_deps(be_dir / "package.json")
    fe_deps = _pkg_deps(fe_dir / "package.json")

    ws_pkgs_deps: set[str] = set()
    for pat in ("packages/*/package.json", "apps/*/package.json"):
        for pjson in sorted(repo_root.glob(pat)):
            ws_pkgs_deps.update(_pkg_deps(pjson))

    # Avoid cross-contaminating a Node backend dir with an unrelated root/auxiliary Python manifest.
    node_owned_backend = (be_dir / "package.json").is_file() and not (
        (be_dir / "pyproject.toml").is_file() or (be_dir / "requirements.txt").is_file() or (be_dir / "manage.py").is_file()
    )
    be_pyproj = _read_lower(be_dir / "pyproject.toml")
    be_reqs = _read_lower(be_dir / "requirements.txt")
    root_pyproj = "" if node_owned_backend else _read_lower(repo_root / "pyproject.toml")
    root_reqs = "" if node_owned_backend else _read_lower(repo_root / "requirements.txt")
    pyproj = be_pyproj + "\n" + root_pyproj
    reqs = be_reqs + "\n" + root_reqs
    py_deps = pyproj + "\n" + reqs

    be_cargo = (
        _read_lower(be_dir / "Cargo.toml")
        + "\n"
        + _read_lower(repo_root / "Cargo.toml")
        + "\n"
        + "\n".join(ctxt for _, ctxt in workspace_cargos)
    )
    fe_cargo = _read_lower(fe_dir / "Cargo.toml")
    all_fe_deps = fe_deps | root_deps
    all_be_js_deps = be_deps | root_deps

    # 1. Tier 3 (Display) independent detection
    disp_ev = True
    if any(w in fe_cargo for w in ("leptos", "dioxus", "yew", "gloo-net", "gloo")) or (repo_root / "Trunk.toml").is_file():
        disp_adapter = "rust-wasm"
        signals.append("Display: Rust WASM UI (Leptos/Dioxus/Yew)")
    elif any((fe_dir / f).exists() or (repo_root / f).exists() for f in ("svelte.config.js", "svelte.config.ts")) or "@sveltejs/kit" in all_fe_deps:
        disp_adapter = "sveltekit"
        signals.append("Display: SvelteKit config / @sveltejs/kit")
    elif any((fe_dir / f).exists() or (repo_root / f).exists() for f in ("nuxt.config.ts", "nuxt.config.js")) or "vue" in all_fe_deps or "nuxt" in all_fe_deps or any(fe_dir.glob("src/**/*.vue")):
        disp_adapter = "vue-sfc"
        signals.append("Display: Vue / Nuxt SFC markers")
    elif (
        any((fe_dir / f).exists() or (repo_root / f).exists() for f in ("next.config.js", "next.config.mjs", "next.config.ts"))
        or "next" in all_fe_deps
        or (fe_dir / "src" / "app").is_dir()
        or (fe_dir / "pages").is_dir()
        or (frontend_sub != "." and (fe_dir / "app").is_dir())
    ):
        disp_adapter = "typescript-nextjs"
        signals.append("Display: Next.js config / App or Pages Router")
    elif bool(all_fe_deps & _JS_FRONTEND_DEPS) or (fe_dir / "vite.config.ts").is_file() or (fe_dir / "vite.config.js").is_file() or (frontend_sub != "." and _has_dir_sources(fe_dir, (".ts", ".tsx", ".js", ".jsx"))):
        disp_adapter = "typescript-react"
        signals.append("Display: React SPA / Vite markers")
    elif _has_dir_sources(fe_dir, (".tsx", ".jsx")):
        disp_adapter = "typescript-react"
        signals.append("Display: React TSX/JSX source markers")
    else:
        disp_adapter = "no-display"
        disp_ev = False

    # 2. Tier 2 (Manipulate) independent detection
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
    has_sqla_evidence = not node_owned_backend and (
        any(tok in py_deps for tok in ("sqlalchemy", "sqlmodel", "alembic", "psycopg", "asyncpg"))
        or (be_dir / "schema.sql").is_file()
        or (repo_root / "schema.sql").is_file()
        or (be_dir / "alembic.ini").is_file()
        or (be_dir / "alembic").is_dir()
        or (be_dir / "app" / "alembic").is_dir()
        or (be_dir / "app" / "models.py").is_file()
        or (be_dir / "app" / "models").is_dir()
    )
    has_fastapi = not node_owned_backend and ("fastapi" in py_deps or (be_dir / "app" / "main.py").is_file())
    has_python_app_layout = (
        not node_owned_backend
        and not has_django
        and not has_rust
        and not has_go
        and (has_fastapi or ((be_dir / "app").is_dir() and _has_dir_sources(be_dir / "app", (".py",))))
    )
    has_node_backend = (
        bool(all_be_js_deps & _NODE_BACKEND_DEPS)
        or "@trpc/server" in ws_pkgs_deps
        or _has_next_api_handlers(fe_dir)
        or (fe_dir != repo_root and _has_next_api_handlers(repo_root))
        or _has_sveltekit_server_routes(fe_dir)
        or (backend_sub != "." and not has_django and not has_python_app_layout and ((be_dir / "package.json").is_file() or _has_dir_sources(be_dir, (".ts", ".js"))))
    )
    has_python_services = (
        not node_owned_backend
        and not has_python_app_layout
        and disp_adapter == "no-display"
        and (
            bool(pyproj.strip() or reqs.strip())
            or any(repo_root.glob("*.py"))
            or ((repo_root / "scripts").is_dir() and next((repo_root / "scripts").rglob("*.py"), None) is not None)
        )
    )

    manip_ev = True
    if has_rust:
        manip_adapter = "rust-http"
        signals.append("Manipulate: Rust backend (axum/actix/rocket/Tauri)")
    elif has_go:
        manip_adapter = "go-http"
        signals.append("Manipulate: Go HTTP backend (go.mod)")
    elif has_django:
        manip_adapter = "python-django"
        signals.append("Manipulate: Django / DRF / Ninja backend")
    elif has_python_app_layout:
        manip_adapter = "python-fastapi"
        manip_ev = has_fastapi
        signals.append("Manipulate: FastAPI Python backend" if has_fastapi else "Manipulate: Python app/ package layout")
    elif has_node_backend:
        manip_adapter = "typescript-node"
        signals.append("Manipulate: TypeScript / Node.js HTTP backend")
    elif has_python_services:
        manip_adapter = "python-services"
        backend_sub = "."
        signals.append("Manipulate: Python services / scripts without web UI")
    else:
        manip_adapter = "no-manipulator"
        manip_ev = False
        signals.append("Manipulate: No supported backend framework detected (no-manipulator)")

    # 3. Tier 1 (Truth) independent detection
    has_prisma = (
        (be_dir / "prisma" / "schema.prisma").is_file()
        or (repo_root / "prisma" / "schema.prisma").is_file()
        or any((repo_root / "packages").glob("*/schema.prisma"))
        or "prisma" in (be_deps | root_deps | ws_pkgs_deps)
        or "@prisma/client" in (be_deps | root_deps | ws_pkgs_deps)
    )
    has_drizzle = (
        any((d / f).is_file() for d in (be_dir, repo_root) for f in ("drizzle.config.ts", "drizzle.config.js"))
        or "drizzle-orm" in (be_deps | root_deps | ws_pkgs_deps)
    )

    if disp_adapter == "no-display" and manip_adapter not in ("python-services",):
        # Backend-only Rust/Go/Django without UI still picks standard non-display fallback only if Python services
        disp_adapter = "typescript-react"

    truth_ev = True
    if has_rust:
        truth_adapter = "rust-sql"
        signals.append("Truth: Rust SQL (sqlx/Diesel/SeaORM)")
    elif has_go:
        truth_adapter = "sql-ddl"
        signals.append("Truth: SQL DDL / sqlc migrations")
    elif has_django:
        truth_adapter = "django-orm"
        signals.append("Truth: Django ORM / migrations")
    elif has_python_app_layout:
        truth_adapter = "postgres-sqlalchemy"
        truth_ev = has_sqla_evidence
        signals.append("Truth: SQLAlchemy / SQLModel / Alembic" if has_sqla_evidence else "Truth: FastAPI backend without explicit SQLAlchemy/SQLModel markers")
    elif has_prisma:
        truth_adapter = "prisma-schema"
        signals.append("Truth: Prisma schema / migrations")
    elif has_drizzle:
        truth_adapter = "drizzle-orm"
        signals.append("Truth: Drizzle ORM schema / migrations")
    elif has_python_services:
        truth_adapter = "sql-ddl"
        truth_ev = (be_dir / "schema.sql").is_file() or (repo_root / "schema.sql").is_file() or bool(list(repo_root.glob("*.sql")))
        signals.append("Truth: SQL DDL files")
    elif has_sqla_evidence and not node_owned_backend:
        truth_adapter = "postgres-sqlalchemy"
        signals.append("Truth: SQLAlchemy / SQLModel schema markers")
    else:
        truth_adapter = "no-truth"
        truth_ev = False
        unsupported_seen = [
            label
            for dep, label in _UNSUPPORTED_DB_DEPS
            if dep in (be_deps | root_deps)
        ]
        if unsupported_seen:
            unique_labels = ", ".join(dict.fromkeys(unsupported_seen))
            signals.append(
                f"Truth: Unsupported persistence technology ({unique_labels}); using no-truth partial coverage"
            )
        else:
            signals.append("Truth: No supported database schema or ORM markers detected (no-truth)")

    # 4. Resolve StackProfile while NEVER mutating detected tier adapters on partial/fallback matches
    enabled_profiles = session.scalars(
        select(StackProfile).where(StackProfile.is_enabled.is_(True)).order_by(StackProfile.id)
    ).all()

    candidates = [
        prof
        for prof in enabled_profiles
        if prof.truth_adapter == truth_adapter
        and prof.manipulator_adapter == manip_adapter
        and prof.display_adapter == disp_adapter
    ]
    exact_match = bool(candidates)
    matched_slug = "fastapi-sqlalchemy-nextjs"

    if candidates:
        if has_tauri:
            tauri_cands = [p for p in candidates if "tauri" in p.slug]
            matched_slug = tauri_cands[0].slug if tauri_cands else candidates[0].slug
        else:
            non_tauri = [p for p in candidates if "tauri" not in p.slug]
            matched_slug = non_tauri[0].slug if non_tauri else candidates[0].slug
    else:
        for prof in enabled_profiles:
            if prof.truth_adapter == truth_adapter and prof.manipulator_adapter == manip_adapter:
                matched_slug = prof.slug
                break
        else:
            for prof in enabled_profiles:
                if prof.display_adapter == disp_adapter and prof.manipulator_adapter == manip_adapter:
                    matched_slug = prof.slug
                    break
            else:
                for prof in enabled_profiles:
                    if prof.display_adapter == disp_adapter:
                        matched_slug = prof.slug
                        break
        signals.append(
            f"Profile fallback: no enabled profile matches ({truth_adapter}, {manip_adapter}, {disp_adapter}); "
            f"preserving detected display adapter `{disp_adapter}`"
        )

    coverage_complete = truth_adapter != "no-truth" and manip_adapter != "no-manipulator"
    if not exact_match or not manip_ev:
        confidence = "fallback"
    elif disp_adapter == "no-display":
        confidence = "high" if (manip_ev and truth_ev) else "medium"
    elif coverage_complete and truth_ev and manip_ev and disp_ev:
        confidence = "high"
    else:
        confidence = "medium"

    return StackDetectionResult(
        repo_path=str(repo_root),
        recommended_profile_slug=matched_slug,
        truth_adapter=truth_adapter,
        manipulator_adapter=manip_adapter,
        display_adapter=disp_adapter,
        backend_subdir=backend_sub,
        frontend_subdir=frontend_sub,
        confidence=confidence,  # type: ignore[arg-type]
        coverage_complete=coverage_complete,
        detected_signals=signals,
    )
