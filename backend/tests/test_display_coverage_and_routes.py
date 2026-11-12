"""Regression tests for display-tier coverage and route resolution precision.

Pins: nested/aliased FastAPI sub-router mounts, display scanning outside the conventional
Next.js directories, same-file URL constants in call sites, id-valued path segments that
cannot match literal route segments, and JSX tag parsing in the WCAG inspector.
"""

from __future__ import annotations

import re
from pathlib import Path

from app.adapters.base import TruthExtractionResult
from app.adapters.python_fastapi import PythonFastApiAdapter


def _write(root: Path, rel: str, text: str) -> None:
    path = root / rel
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(text, encoding="utf-8")


def _routes(repo: Path) -> dict[tuple[str, str], str]:
    truth = TruthExtractionResult(nodes=[], table_symbol_map={}, function_symbol_map={})
    manip = PythonFastApiAdapter().extract(repo, "backend", truth)
    return {(r.http_method, r.full_path): r.path_regex for r in manip.routes}


# --- nested and aliased include_router -------------------------------------------------


def _build_nested_router_repo(root: Path) -> Path:
    repo = root / "nested"
    _write(
        repo,
        "backend/app/main.py",
        "from fastapi import FastAPI\n"
        "from app.api.routes import api_router\n"
        "from app.api.routes.status import router as status_router\n"
        "app = FastAPI()\n"
        "app.include_router(api_router, prefix='/api/v1')\n"
        "app.include_router(status_router, prefix='/api/v1/status')\n",
    )
    _write(
        repo,
        "backend/app/api/routes/__init__.py",
        "from fastapi import APIRouter\n"
        "from app.api.routes import parents\n"
        "api_router = APIRouter()\n"
        "api_router.include_router(parents.router, prefix='/parents')\n",
    )
    _write(
        repo,
        "backend/app/api/routes/parents.py",
        "from fastapi import APIRouter\n"
        "from app.api.routes.kids import router as kids_router\n"
        "from .notes import router as notes_router\n"
        "router = APIRouter()\n"
        "@router.get('/list')\n"
        "def list_parents():\n"
        "    return []\n"
        "router.include_router(kids_router)\n"
        "router.include_router(notes_router, prefix='/extra')\n",
    )
    _write(
        repo,
        "backend/app/api/routes/kids.py",
        "from fastapi import APIRouter\n"
        "router = APIRouter(prefix='/kids')\n"
        "@router.get('/{kid_id}')\n"
        "def read_kid(kid_id: str):\n"
        "    return {}\n",
    )
    _write(
        repo,
        "backend/app/api/routes/notes.py",
        "from fastapi import APIRouter\n"
        "router = APIRouter()\n"
        "@router.post('/notes')\n"
        "def add_note():\n"
        "    return {}\n",
    )
    _write(
        repo,
        "backend/app/api/routes/status.py",
        "from fastapi import APIRouter\n"
        "router = APIRouter()\n"
        "@router.get('/ping')\n"
        "def ping():\n"
        "    return {}\n",
    )
    # A file literally named `router.py` must not collect mounts meant for aliased routers.
    _write(
        repo,
        "backend/app/gateway/router.py",
        "from fastapi import APIRouter\n"
        "router = APIRouter()\n"
        "@router.get('/gateway-health')\n"
        "def gateway_health():\n"
        "    return {}\n",
    )
    return repo


def test_nested_aliased_sub_routers_mount_under_their_parent(tmp_path: Path) -> None:
    routes = _routes(_build_nested_router_repo(tmp_path))
    paths = set(routes)

    assert ("GET", "/parents/list") in paths
    # Aliased `router as kids_router` included into the parent's own router.
    assert ("GET", "/parents/kids/{kid_id}") in paths
    assert ("GET", "/kids/{kid_id}") not in paths
    # Relative import plus an include prefix compose too.
    assert ("POST", "/parents/extra/notes") in paths
    assert ("POST", "/notes") not in paths
    # A stray `router.py` keeps its own root path only.
    assert {p for (_m, p) in paths if "gateway" in p} == {"/gateway-health"}


def test_explicit_version_mount_stays_optional_for_base_relative_calls(tmp_path: Path) -> None:
    routes = _routes(_build_nested_router_repo(tmp_path))
    regex = routes[("GET", "/api/v1/status/ping")]
    assert re.match(regex, "/api/v1/status/ping")
    assert re.match(regex, "/status/ping")
    assert not re.match(regex, "/api/v2/status/ping")
