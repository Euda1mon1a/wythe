"""Regression tests for display-tier coverage and route resolution precision.

Pins: nested/aliased FastAPI sub-router mounts, display scanning outside the conventional
Next.js directories, same-file URL constants in call sites, id-valued path segments that
cannot match literal route segments, and JSX tag parsing in the WCAG inspector.
"""

from __future__ import annotations

import re
from pathlib import Path

from sqlalchemy.orm import Session

from app.adapters.base import TruthExtractionResult
from app.adapters.python_fastapi import PythonFastApiAdapter
from app.schemas.atlas import TargetProjectCreate
from app.services.governance_service import get_target_by_slug, register_target
from app.services.scanner_service import run_target_scan


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


# --- display coverage outside the conventional Next.js directories ---------------------


def _build_feature_folder_repo(root: Path) -> Path:
    repo = root / "featurefolders"
    _write(repo, "backend/schema.sql", "CREATE TABLE widgets (id INTEGER PRIMARY KEY);\n")
    _write(
        repo,
        "backend/app/api/routes.py",
        "from fastapi import APIRouter\n"
        "router = APIRouter()\n"
        "@router.get('/widgets/summary')\n"
        "def widget_summary():\n"
        "    return {}\n",
    )
    _write(
        repo,
        "backend/app/main.py",
        "from fastapi import FastAPI\n"
        "from app.api.routes import router\n"
        "app = FastAPI()\n"
        "app.include_router(router)\n",
    )
    _write(repo, "frontend/tsconfig.json", '{ "compilerOptions": { "paths": { "@/*": ["./src/*"] } } }\n')
    _write(
        repo,
        "frontend/src/lib/api.ts",
        "export async function get<T>(url: string): Promise<T> { return (await fetch(url)).json(); }\n",
    )
    _write(
        repo,
        "frontend/src/features/widgets/hooks.ts",
        "import { get } from '@/lib/api';\n"
        "export function useWidgetSummary() {\n"
        "  return get('/widgets/summary');\n"
        "}\n"
        "export function useWidgetHistory() {\n"
        "  return get('/widgets/history');\n"
        "}\n",
    )
    _write(
        repo,
        "frontend/src/features/widgets/WidgetPanel.tsx",
        "import { useWidgetSummary, useWidgetHistory } from './hooks';\n"
        "import { dayLabel } from '@/lib/dayLabel';\n"
        "export function WidgetPanel() {\n"
        "  void useWidgetSummary();\n"
        "  void useWidgetHistory();\n"
        "  return <div><input type=\"text\" />{dayLabel()}</div>;\n"
        "}\n",
    )
    _write(
        repo,
        "frontend/src/lib/dayLabel.ts",
        "export function dayLabel(): string {\n"
        "  const today = new Date();\n"
        "  return String(today.getDate());\n"
        "}\n"
        "export const stamp = () => new Date().toISOString();\n",
    )
    _write(
        repo,
        "frontend/src/app/widgets/page.tsx",
        "import { WidgetPanel } from '@/features/widgets/WidgetPanel';\n"
        "export default function WidgetsPage() {\n"
        "  return <WidgetPanel />;\n"
        "}\n",
    )
    # Test doubles and fixtures are not display code.
    _write(
        repo,
        "frontend/src/mocks/handlers.ts",
        "import { get } from '@/lib/api';\n"
        "export const mockLoad = () => get('/mock-only/endpoint');\n",
    )
    _write(
        repo,
        "frontend/src/test-utils/renderForm.tsx",
        "export const Form = () => <input type=\"text\" />;\n",
    )
    return repo


def test_feature_folders_and_lib_are_scanned_but_test_doubles_are_not(
    db_session: Session, tmp_path: Path
) -> None:
    repo = _build_feature_folder_repo(tmp_path)
    register_target(db_session, TargetProjectCreate(slug="featurefolders", name="Feature folders", repo_path=str(repo)))
    target = get_target_by_slug(db_session, "featurefolders")
    assert target is not None
    report = run_target_scan(db_session, target, strict_gate=True, persist_snapshot=False)
    by_rule: dict[str, list] = {}
    for f in report.findings:
        by_rule.setdefault(f.rule_code, []).append(f)

    disp004 = by_rule.get("DISP-004", [])
    assert [f.title for f in disp004] == ["Frontend `GET /widgets/history` has no matching backend route"]
    assert disp004[0].source_file == "frontend/src/features/widgets/hooks.ts"
    assert "app/widgets/page.tsx" in disp004[0].detail

    assert [(f.source_file, f.line) for f in by_rule.get("DISP-002", [])] == [
        ("frontend/src/lib/dayLabel.ts", 2)
    ], "device-clock 'today' is flagged; a serialized instant is not"
    assert [f.source_file for f in by_rule.get("DISP-005", [])] == [
        "frontend/src/features/widgets/WidgetPanel.tsx"
    ]
    assert not any("mock-only" in f.title or "test-utils" in f.source_file for f in report.findings)
    assert not any("/widgets/summary" in f.title for f in report.findings)


# --- same-file URL constants in call sites ---------------------------------------------

_CONST_PREFIX_SRC = (
    "import { get, post, del } from '@/lib/api';\n"
    "const BASE_URL = '/widgets';\n"
    "export const ARCHIVE = `${BASE_URL}/archive`;\n"
    "const AMBIGUOUS = '/one';\n"
    "export function loadWidget(id: string) {\n"
    "  return get<Widget>(`${BASE_URL}/${id}`);\n"
    "}\n"
    "export function createWidget(body: unknown) {\n"
    "  return post(BASE_URL, body);\n"
    "}\n"
    "export function purge(id: string) {\n"
    "  return del(`${ARCHIVE}/${id}`);\n"
    "}\n"
    "function other() {\n"
    "  const AMBIGUOUS = '/two';\n"
    "  return get(`${AMBIGUOUS}/x`);\n"
    "}\n"
)


def _const_prefix_calls() -> set[tuple[str, str, int]]:
    from app.adapters.typescript_nextjs import _extract_ts_http_calls

    return set(_extract_ts_http_calls(_CONST_PREFIX_SRC))


def test_same_file_url_constants_resolve_in_call_urls() -> None:
    calls = _const_prefix_calls()
    assert ("GET", "/widgets/${id}", 6) in calls
    assert ("POST", "/widgets", 9) in calls
    assert ("DELETE", "/widgets/archive/${id}", 12) in calls
    # A name bound to two different values is ambiguous: no guessed call.
    assert not any(url.startswith(("/one", "/two")) for _v, url, _l in calls)


def test_same_file_url_constants_resolve_without_treesitter(monkeypatch) -> None:
    import app.adapters.typescript_nextjs as tsnext

    monkeypatch.setattr(tsnext, "extract_ts_http_calls_cst", lambda *a, **k: None)
    calls = _const_prefix_calls()
    assert ("GET", "/widgets/${id}", 6) in calls
    assert ("POST", "/widgets", 9) in calls
    assert ("DELETE", "/widgets/archive/${id}", 12) in calls


def test_glued_trailing_query_suffix_is_dropped() -> None:
    from app.adapters.typescript_nextjs import _normalize_ts_url

    assert _normalize_ts_url("/items/${id}/preview${suffix}") == "/items/{param}/preview"
    assert _normalize_ts_url("/items/${id}${querySuffix}") == "/items/{param}"
    # A whole trailing segment is still a path parameter.
    assert _normalize_ts_url("/items/${suffix}") == "/items/{param}"
