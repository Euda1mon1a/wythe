"""Independent 3-tier repository stack detector paired with DB StackProfile truth."""

from __future__ import annotations

import json
from collections.abc import Sequence
from pathlib import Path

from sqlalchemy import select
from sqlalchemy.orm import Session

from app.adapters.plugin_registry import collect_enabled_plugin_stack_profiles
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
    real_root = repo_root.resolve()
    for name in candidates:
        cand = real_root / name
        if not cand.is_dir():
            continue
        resolved = cand.resolve()
        if resolved.is_relative_to(real_root) and resolved != real_root:
            return resolved.relative_to(real_root).as_posix()
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


_UI_FRAMEWORK_DEPS = _JS_FRONTEND_DEPS | frozenset({"next", "vue", "nuxt", "@sveltejs/kit"})
_UI_CONFIG_FILES = (
    "vite.config.ts",
    "vite.config.js",
    "vite.config.mts",
    "next.config.js",
    "next.config.mjs",
    "next.config.ts",
    "svelte.config.js",
    "svelte.config.ts",
    "nuxt.config.ts",
    "nuxt.config.js",
)
_SKIP_SUBAPP_DIRS = frozenset(
    {
        "node_modules",
        "dist",
        "build",
        "out",
        "src",
        "app",
        "pages",
        "components",
        "public",
        "server",
        "api",
        "backend",
        "src-tauri",
    }
)


def _has_dir_sources(
    base_dir: Path,
    exts: tuple[str, ...],
    *,
    exclude_dirs: tuple[str, ...] = (),
) -> bool:
    if not base_dir.is_dir():
        return False
    skip = {"node_modules", ".git", ".venv", "venv", *exclude_dirs}
    for p in base_dir.rglob("*"):
        if any(part in skip for part in p.relative_to(base_dir).parts):
            continue
        if p.is_file() and p.suffix in exts:
            return True
    return False


def _is_frontend_subapp_dir(cand: Path) -> tuple[bool, set[str]]:
    if not cand.is_dir() or cand.is_symlink():
        return False, set()
    deps = _pkg_deps(cand / "package.json")
    has_ui_deps = bool(deps & _UI_FRAMEWORK_DEPS)
    has_ui_cfg = any((cand / cfg).is_file() for cfg in _UI_CONFIG_FILES)
    has_ui_src = _has_dir_sources(cand, (".tsx", ".jsx", ".vue", ".svelte"))
    if (deps & _NODE_BACKEND_DEPS) and not has_ui_deps and not has_ui_src:
        return False, set()
    return (has_ui_deps or has_ui_cfg or has_ui_src), deps


def _resolve_nested_frontend(
    repo_root: Path,
    frontend_sub: str,
    backend_sub: str,
    root_deps: set[str],
) -> tuple[str, set[str], list[Path], bool]:
    """Discover nested frontend sub-apps under `apps/web/*` or `apps/*` without picking `examples/*`
    or arbitrarily dropping sibling apps when multiple UI apps exist."""
    if frontend_sub != ".":
        fe_cand = repo_root / frontend_sub
        if (fe_cand / "package.json").is_file() or (fe_cand / "Cargo.toml").is_file():
            return frontend_sub, set(), [], False
        matched: list[tuple[Path, set[str]]] = []
        if fe_cand.is_dir() and not fe_cand.is_symlink():
            for child in sorted(fe_cand.iterdir()):
                if child.name.startswith(".") or child.name in _SKIP_SUBAPP_DIRS:
                    continue
                ok, c_deps = _is_frontend_subapp_dir(child)
                if ok:
                    matched.append((child, c_deps))
        if len(matched) == 1:
            sub_dir, sub_deps = matched[0]
            return sub_dir.relative_to(repo_root).as_posix(), sub_deps, [sub_dir], False
        if len(matched) >= 2:
            # Multiple sub-apps under `apps/web/*`: keep `frontend_sub` (`apps/web`) so all sub-apps
            # are scanned together, and avoid locking onto a single child directory.
            dirs = [sub_dir for sub_dir, _ in matched]
            react_only_deps = {
                d
                for _, sub_deps in matched
                for d in sub_deps
                if d in _JS_FRONTEND_DEPS
            }
            return frontend_sub, react_only_deps, dirs, True
        return frontend_sub, set(), [], False

    if root_deps & _UI_FRAMEWORK_DEPS:
        return frontend_sub, set(), [], False

    apps_dir = repo_root / "apps"
    if apps_dir.is_dir() and not apps_dir.is_symlink():
        matched_apps: list[tuple[Path, set[str]]] = []
        for child in sorted(apps_dir.iterdir()):
            if not child.is_dir() or child.is_symlink() or child.name.startswith("."):
                continue
            if child.name in _SKIP_SUBAPP_DIRS:
                continue
            rel_child = child.relative_to(repo_root).as_posix()
            if backend_sub != "." and (rel_child == backend_sub or rel_child.startswith(f"{backend_sub}/")):
                continue
            ok_c, c_deps = _is_frontend_subapp_dir(child)
            if ok_c:
                matched_apps.append((child, c_deps))
                continue
            for grand in sorted(child.iterdir()):
                if grand.is_dir() and not grand.is_symlink() and not grand.name.startswith(".") and grand.name not in _SKIP_SUBAPP_DIRS:
                    ok_g, g_deps = _is_frontend_subapp_dir(grand)
                    if ok_g:
                        matched_apps.append((grand, g_deps))
        if len(matched_apps) == 1:
            only_dir, only_deps = matched_apps[0]
            return only_dir.relative_to(repo_root).as_posix(), only_deps, [only_dir], False
        if len(matched_apps) >= 2:
            # Multiple sibling apps under `apps/*`: preserve root scan (`frontend_sub='.'`) with lowered confidence.
            return frontend_sub, set(), [], True
    return frontend_sub, set(), [], False


def _has_python_project_deps(pyproj: str, reqs: str) -> bool:
    """Return True when Python manifests declare actual project/runtime metadata rather than linter-only config."""
    if reqs.strip():
        return True
    if not pyproj.strip():
        return False
    return any(
        marker in pyproj
        for marker in (
            "[project]",
            "dependencies",
            "[tool.poetry]",
            "[project.scripts]",
        )
    )


def _has_python_backend_source_evidence(repo_root: Path, py_deps: str) -> bool:
    """Return True only on positive Python backend/daemon/store evidence (never standalone `.sql` files alone)."""
    if any(
        tok in py_deps
        for tok in (
            "sqlite3",
            "aiosqlite",
            "psycopg",
            "asyncpg",
            "sqlalchemy",
            "sqlmodel",
            "mcp",
            "fastmcp",
            "fastapi",
            "starlette",
            "uvicorn",
            "aiohttp",
            "flask",
        )
    ):
        return True
    checked = 0
    for scan_dir in dict.fromkeys([repo_root / "scripts", repo_root / "src", repo_root]):
        if not scan_dir.is_dir() or scan_dir.is_symlink():
            continue
        it = scan_dir.glob("*.py") if scan_dir == repo_root else scan_dir.rglob("*.py")
        for py_file in sorted(it):
            rel_parts = py_file.relative_to(repo_root).parts if py_file.is_relative_to(repo_root) else py_file.parts
            if any(p in rel_parts for p in (".git", ".venv", "venv", "node_modules", "tests", "test", "examples", "example")):
                continue
            if not py_file.is_file() or py_file.is_symlink():
                continue
            checked += 1
            low = _read_lower(py_file)
            if any(
                m in low
                for m in (
                    "sqlite3",
                    "aiosqlite",
                    "psycopg",
                    "asyncpg",
                    "create table",
                    ".jsonl",
                    "basehttprequesthandler",
                    "httpserver",
                    "threadinghttpserver",
                    "socketserver",
                    "asyncio.start_server",
                    "@mcp.tool",
                    "fastmcp",
                    "mcp.server",
                    "fastapi(",
                    "apirouter(",
                    "starlette(",
                    "uvicorn.run",
                )
            ):
                return True
            if checked >= 600:
                return False
    return False


def _count_python_service_sources(repo_root: Path) -> tuple[int, bool]:
    """Return `(py_count, has_service_units)` across non-test/non-example repository directories."""
    skip = {".git", ".venv", "venv", "env", "node_modules", "dist", "build", "tests", "test", "examples", "example", "docs"}
    py_count = 0
    has_units = False
    for p in repo_root.rglob("*"):
        if not p.is_file() or p.is_symlink():
            continue
        rel_parts = p.relative_to(repo_root).parts if p.is_relative_to(repo_root) else p.parts
        if any(part in skip or (part.startswith(".") and part != ".docker") for part in rel_parts[:-1]):
            continue
        if p.suffix == ".py":
            py_count += 1
        elif p.suffix in (".plist", ".service"):
            has_units = True
        if py_count >= 12 and has_units:
            break
    return py_count, has_units


def _has_standalone_sql_files(repo_root: Path, be_dir: Path) -> bool:
    return (
        (be_dir / "schema.sql").is_file()
        or (repo_root / "schema.sql").is_file()
        or _has_dir_sources(repo_root, (".sql",), exclude_dirs=("examples", "example"))
    )


def detect_repository_stack(
    session: Session,
    raw_repo_path: str,
    allow_local_plugins: bool = False,
    local_plugin_modules: Sequence[str] | None = None,
) -> StackDetectionResult:
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

    root_deps = _pkg_deps(repo_root / "package.json")
    frontend_sub, nested_fe_deps, nested_fe_dirs, multi_fe_apps = _resolve_nested_frontend(
        repo_root, frontend_sub, backend_sub, root_deps
    )
    if multi_fe_apps:
        signals.append("Display: Multiple nested frontend sub-apps detected; preserving shared scan root")
    be_dir = repo_root if backend_sub == "." else repo_root / backend_sub
    fe_dir = repo_root if frontend_sub == "." else repo_root / frontend_sub

    be_deps = _pkg_deps(be_dir / "package.json")
    fe_deps = _pkg_deps(fe_dir / "package.json") | nested_fe_deps

    ws_pkgs_deps: set[str] = set()
    for pat in ("packages/*/package.json", "apps/*/package.json"):
        for pjson in sorted(repo_root.glob(pat)):
            ws_pkgs_deps.update(_pkg_deps(pjson))

    # Avoid cross-contaminating a Node backend dir with an unrelated root/auxiliary Python manifest,
    # unless backend/package.json lacks Node backend/ORM deps or Python FastAPI source already exists.
    node_be_markers = _NODE_BACKEND_DEPS | {
        dep for dep, _ in _UNSUPPORTED_DB_DEPS
    } | {"prisma", "@prisma/client", "drizzle-orm", "kysely"}
    has_be_py_runtime_manifest = (
        (be_dir / "requirements.txt").is_file()
        or (be_dir / "manage.py").is_file()
        or (be_dir / "app" / "main.py").is_file()
        or (
            (be_dir / "pyproject.toml").is_file()
            and _has_python_project_deps(_read_lower(be_dir / "pyproject.toml"), "")
        )
    )
    node_owned_backend = (
        (be_dir / "package.json").is_file()
        and not has_be_py_runtime_manifest
        and (
            bool((be_deps | ws_pkgs_deps) & node_be_markers)
            or (
                be_dir != repo_root
                and not _has_python_project_deps(_read_lower(repo_root / "pyproject.toml"), _read_lower(repo_root / "requirements.txt"))
                and not (repo_root / "manage.py").is_file()
            )
        )
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
    fe_cfg_dirs = tuple(dict.fromkeys([fe_dir, *nested_fe_dirs, repo_root]))

    # 1. Tier 3 (Display) independent detection
    disp_ev = True
    if any(w in fe_cargo for w in ("leptos", "dioxus", "yew", "gloo-net", "gloo")) or (repo_root / "Trunk.toml").is_file():
        disp_adapter = "rust-wasm"
        signals.append("Display: Rust WASM UI (Leptos/Dioxus/Yew)")
    elif any((d / f).exists() for d in fe_cfg_dirs for f in ("svelte.config.js", "svelte.config.ts")) or "@sveltejs/kit" in all_fe_deps:
        disp_adapter = "sveltekit"
        signals.append("Display: SvelteKit config / @sveltejs/kit")
    elif any((d / f).exists() for d in fe_cfg_dirs for f in ("nuxt.config.ts", "nuxt.config.js")) or "vue" in all_fe_deps or "nuxt" in all_fe_deps or any(fe_dir.glob("src/**/*.vue")):
        disp_adapter = "vue-sfc"
        signals.append("Display: Vue / Nuxt SFC markers")
    elif (
        any((d / f).exists() for d in fe_cfg_dirs for f in ("next.config.js", "next.config.mjs", "next.config.ts"))
        or "next" in all_fe_deps
        or (fe_dir / "src" / "app").is_dir()
        or (fe_dir / "pages").is_dir()
        or (frontend_sub != "." and (fe_dir / "app").is_dir())
    ):
        disp_adapter = "typescript-nextjs"
        signals.append("Display: Next.js config / App or Pages Router")
    elif (
        bool(all_fe_deps & _JS_FRONTEND_DEPS)
        or any((d / f).is_file() for d in fe_cfg_dirs for f in ("vite.config.ts", "vite.config.js", "vite.config.mts"))
        or (frontend_sub != "." and _has_dir_sources(fe_dir, (".ts", ".tsx", ".js", ".jsx", ".mjs", ".html")))
    ):
        disp_adapter = "typescript-react"
        signals.append("Display: React SPA / Vite markers")
    elif _has_dir_sources(
        fe_dir,
        (".tsx", ".jsx"),
        exclude_dirs=("examples", "example") if fe_dir == repo_root else (),
    ):
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
        and (
            has_fastapi
            or ((has_sqla_evidence or disp_ev) and (be_dir / "app").is_dir() and _has_dir_sources(be_dir / "app", (".py",)))
        )
    )
    # Compute TypeScript / Node ORM markers ahead of Tier-2 Manipulate resolution so
    # Server-Action full-stack apps (Next.js/SvelteKit/Nuxt + Prisma/Drizzle/Kysely) and
    # Turborepo `packages/*` backends are never hijacked by auxiliary Python helper scripts.
    all_js_workspace_deps = be_deps | root_deps | ws_pkgs_deps
    has_prisma = (
        (be_dir / "prisma" / "schema.prisma").is_file()
        or (repo_root / "prisma" / "schema.prisma").is_file()
        or any((repo_root / "packages").glob("*/schema.prisma"))
        or any((repo_root / "packages").glob("*/prisma/schema.prisma"))
        or "prisma" in all_js_workspace_deps
        or "@prisma/client" in all_js_workspace_deps
    )
    has_drizzle = (
        any((d / f).is_file() for d in (be_dir, repo_root) for f in ("drizzle.config.ts", "drizzle.config.js"))
        or any((repo_root / "packages").glob("*/drizzle.config.*"))
        or "drizzle-orm" in all_js_workspace_deps
    )
    be_sub = be_dir.relative_to(repo_root).as_posix() if be_dir.is_dir() and be_dir != repo_root else "."
    if "@immich/sql-tools" in all_js_workspace_deps:
        from app.adapters.sql_tools_truth import discover_sql_tools_schema_files

        has_sql_tools = bool(discover_sql_tools_schema_files(repo_root, be_sub)[0])
    else:
        has_sql_tools = False
    kysely_deps = {"kysely", "kysely-postgres-js", "nestjs-kysely"}
    if all_js_workspace_deps & kysely_deps:
        from app.adapters.kysely_schema import discover_kysely_migrations

        has_kysely = bool(discover_kysely_migrations(repo_root, be_sub))
    else:
        has_kysely = False
    has_ts_orm = has_prisma or has_drizzle or has_sql_tools or has_kysely

    has_node_backend = (
        bool((all_be_js_deps | ws_pkgs_deps) & _NODE_BACKEND_DEPS)
        or _has_next_api_handlers(fe_dir)
        or (fe_dir != repo_root and _has_next_api_handlers(repo_root))
        or _has_sveltekit_server_routes(fe_dir)
        or (
            has_ts_orm
            and not has_rust
            and not has_go
            and not has_django
            and not has_python_app_layout
            and (
                disp_adapter in ("typescript-nextjs", "sveltekit", "vue-sfc")
                or bool(all_js_workspace_deps & (_NODE_BACKEND_DEPS | _UI_FRAMEWORK_DEPS))
            )
        )
        or (backend_sub != "." and not has_django and not has_python_app_layout and ((be_dir / "package.json").is_file() or _has_dir_sources(be_dir, (".ts", ".js"))))
    )
    has_py_backend_src_ev = _has_python_backend_source_evidence(repo_root, py_deps)
    has_py_project_deps = _has_python_project_deps(pyproj, reqs)
    pkg_swift_file = repo_root / "Package.swift"
    has_swift_package = pkg_swift_file.is_file() and not pkg_swift_file.is_symlink()
    is_swift_systems_repo = (
        has_swift_package
        and not disp_ev
        and not (
            has_rust
            or has_go
            or has_django
            or has_python_app_layout
            or has_node_backend
            or has_py_project_deps
            or has_py_backend_src_ev
        )
    )
    if is_swift_systems_repo:
        plugin_profiles = collect_enabled_plugin_stack_profiles(
            repo_root=repo_root,
            allow_local_plugins=allow_local_plugins,
            local_plugin_modules=local_plugin_modules,
        )
        swift_prof = next(
            (p for p in plugin_profiles if p.slug == "swift-systems-ipc"),
            None,
        )
        if swift_prof is not None:
            signals.append(
                "Swift Package.swift detected; activating optional plugin profile 'swift-systems-ipc'"
            )
            signals.append(
                f"Subtrees: backend='.' ({swift_prof.manipulator_adapter}), "
                f"frontend='.' ({swift_prof.display_adapter})"
            )
            return StackDetectionResult(
                repo_path=str(repo_root),
                recommended_profile_slug=swift_prof.slug,
                truth_adapter=swift_prof.truth_adapter,
                manipulator_adapter=swift_prof.manipulator_adapter,
                display_adapter=swift_prof.display_adapter,
                backend_subdir=".",
                frontend_subdir=".",
                confidence="high",
                coverage_complete=True,
                detected_signals=signals,
            )
        signals.append(
            "Swift Package.swift detected; optional plugin 'wythe-plugin-apple-ipc' is not installed "
            "(using partial no-coverage fallback)"
        )
        signals.append(
            "Subtrees: backend='.' (no-manipulator), frontend='.' (no-display)"
        )
        return StackDetectionResult(
            repo_path=str(repo_root),
            recommended_profile_slug="no-coverage-fallback",
            truth_adapter="no-truth",
            manipulator_adapter="no-manipulator",
            display_adapter="no-display",
            backend_subdir=".",
            frontend_subdir=".",
            confidence="fallback",
            coverage_complete=False,
            detected_signals=signals,
        )

    py_svc_count, has_svc_units = _count_python_service_sources(repo_root)
    has_standalone_sql = _has_standalone_sql_files(repo_root, be_dir)
    has_substantial_py_services = py_svc_count >= 2 or (
        py_svc_count >= 1 and (has_svc_units or has_standalone_sql)
    )
    has_python_services = (
        not node_owned_backend
        and not has_python_app_layout
        and (
            has_py_project_deps
            or has_py_backend_src_ev
            or has_substantial_py_services
            or (
                disp_adapter == "no-display"
                and (
                    any(repo_root.glob("*.py"))
                    or ((repo_root / "scripts").is_dir() and _has_dir_sources(repo_root / "scripts", (".py",)))
                    or ((repo_root / "src").is_dir() and _has_dir_sources(repo_root / "src", (".py",)))
                )
            )
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
        be_dir = repo_root
        signals.append(
            "Manipulate: Python services / daemons / scripts"
            if disp_adapter != "no-display"
            else "Manipulate: Python services / scripts without web UI"
        )
    else:
        manip_adapter = "no-manipulator"
        manip_ev = False
        signals.append("Manipulate: No supported backend framework detected (no-manipulator)")

    # 3. Tier 1 (Truth) independent detection
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
    elif has_sql_tools:
        truth_adapter = "sql-tools"
        signals.append("Truth: @immich/sql-tools decorator schema")
    elif has_kysely:
        truth_adapter = "kysely-migrations"
        signals.append("Truth: Kysely migration files")
    elif has_python_services:
        truth_adapter = "sql-ddl"
        truth_ev = has_py_backend_src_ev or _has_standalone_sql_files(repo_root, be_dir)
        signals.append(
            "Truth: SQL DDL / inline SQLite, PostgreSQL, or JSONL stores"
            if truth_ev
            else "Truth: SQL DDL files"
        )
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
    elif multi_fe_apps:
        confidence = "medium"
    elif disp_adapter == "no-display":
        confidence = "high" if (manip_ev and truth_ev) else "medium"
    elif coverage_complete and truth_ev and manip_ev and disp_ev:
        confidence = "high"
    else:
        confidence = "medium"

    signals.append(
        f"Subtrees: backend={backend_sub!r} ({manip_adapter}), frontend={frontend_sub!r} ({disp_adapter})"
    )

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
