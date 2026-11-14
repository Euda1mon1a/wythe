"""Tests for Django URLConf packages, list composition, CBV .as_view() methods, and Plane regression."""

from __future__ import annotations

from pathlib import Path

import pytest
from sqlalchemy.orm import Session

from app.adapters.autodetect import detect_repository_stack
from app.adapters.base import TruthExtractionResult
from app.adapters.python_django import PythonDjangoAdapter
from app.models import TargetProject
from app.services.scanner_service import run_target_scan

_PLANE_CORPUS_DIR = Path("/private/tmp/wythe-corpus-20261113/plane")


def test_django_url_packages_composition_cbv_and_controls(
    db_session: Session, tmp_path: Path
) -> None:
    """Resolve URL packages, starred/+/.extend lists, view re-exports, CBV verbs, and retain negative controls."""
    repo = tmp_path / "django_pkg_repo"
    (repo / "backend" / "config").mkdir(parents=True)
    (repo / "backend" / "myapp" / "urls").mkdir(parents=True)
    (repo / "backend" / "myapp" / "views").mkdir(parents=True)
    (repo / "backend" / "myapp" / "migrations").mkdir(parents=True)
    (repo / "frontend" / "src" / "services").mkdir(parents=True)
    (repo / "frontend" / "src" / "pages").mkdir(parents=True)

    (repo / "backend" / "manage.py").write_text("#!/usr/bin/env python3\n", encoding="utf-8")
    (repo / "backend" / "config" / "__init__.py").write_text("", encoding="utf-8")
    (repo / "backend" / "config" / "urls.py").write_text(
        """from django.urls import include, path

urlpatterns = [
    path("api/", include("myapp.urls")),
]
""",
        encoding="utf-8",
    )
    (repo / "backend" / "myapp" / "__init__.py").write_text("", encoding="utf-8")
    (repo / "backend" / "myapp" / "models.py").write_text(
        """from django.db import models

class Workspace(models.Model):
    slug = models.CharField(max_length=64)

    class Meta:
        db_table = "workspaces"
""",
        encoding="utf-8",
    )
    (repo / "backend" / "myapp" / "migrations" / "0001_initial.py").write_text(
        """from django.db import migrations

class Migration(migrations.Migration):
    operations = [
        migrations.CreateModel(
            name="Workspace",
            fields=[],
            options={"db_table": "workspaces"},
        ),
    ]
""",
        encoding="utf-8",
    )
    (repo / "backend" / "myapp" / "views" / "__init__.py").write_text(
        """from .external import ExternalAiView
from .extra import AliasHealthView, ItemViewSet, RestrictedView, fn_ping
""",
        encoding="utf-8",
    )
    (repo / "backend" / "myapp" / "views" / "external.py").write_text(
        """from myapp.models import Workspace

class BaseProtectedView:
    pass

class ExternalAiView(BaseProtectedView):
    def post(self, request, slug):
        return Workspace.objects.get(slug=slug)
""",
        encoding="utf-8",
    )
    (repo / "backend" / "myapp" / "views" / "extra.py").write_text(
        """from myapp.models import Workspace

def api_view(_methods):
    return lambda fn: fn

class AliasHealthView:
    def get(self, request):
        return {"ok": True}

class RestrictedView:
    def get(self, request):
        return Workspace.objects.all()

    def post(self, request):
        return Workspace.objects.create(slug="x")

class ItemViewSet:
    def list(self, request):
        return Workspace.objects.all()

@api_view(["GET"])
def fn_ping(request):
    return {"pong": True}
""",
        encoding="utf-8",
    )
    (repo / "backend" / "myapp" / "urls" / "external.py").write_text(
        """from django.urls import path
from myapp.views import ExternalAiView

urlpatterns = [
    path("workspaces/<str:slug>/ai-assistant/", ExternalAiView.as_view(), name="ai-assistant"),
]
""",
        encoding="utf-8",
    )
    (repo / "backend" / "myapp" / "urls" / "v2.py").write_text(
        """from django.urls import include, path
from myapp.views import AliasHealthView, ItemViewSet, RestrictedView, fn_ping

base_v2 = [
    path("health/", AliasHealthView.as_view()),
]
v2_patterns = base_v2 + [
    path("workspaces/<str:slug>/restricted/", RestrictedView.as_view(http_method_names=["get"])),
    path("items/", ItemViewSet.as_view({"get": "list"})),
    path("inline/", include(([path("ping/", fn_ping)], "inline"))),
]
v2_patterns.extend([])
""",
        encoding="utf-8",
    )
    (repo / "backend" / "myapp" / "urls" / "__init__.py").write_text(
        """from django.urls import include, path
from .external import urlpatterns as external_urls
from .v2 import v2_patterns

urlpatterns = [
    *external_urls,
    path("v2/", include(v2_patterns)),
]
""",
        encoding="utf-8",
    )

    (repo / "frontend" / "package.json").write_text(
        '{"dependencies": {"react": "18.3.0", "axios": "1.7.0"}}',
        encoding="utf-8",
    )
    (repo / "frontend" / "src" / "services" / "aiClient.ts").write_text(
        """import axios from "axios";

export function callValidAi(slug: string) {
  return axios.post(`/api/workspaces/${slug}/ai-assistant/`, { task: "summary" });
}

export function callWrongMethodAi(slug: string) {
  return axios.delete(`/api/workspaces/${slug}/ai-assistant/`);
}

export function callRestrictedPost(slug: string) {
  return axios.post(`/api/v2/workspaces/${slug}/restricted/`, {});
}

export function callAbsentEndpoint(slug: string) {
  return axios.post(`/api/workspaces/${slug}/missing-endpoint/`, {});
}

export function callHealth() {
  return axios.get("/api/v2/health/");
}

export function callInlinePing() {
  return axios.get("/api/v2/inline/ping/");
}
""",
        encoding="utf-8",
    )
    (repo / "frontend" / "src" / "pages" / "Home.tsx").write_text(
        """import {
  callAbsentEndpoint,
  callHealth,
  callInlinePing,
  callRestrictedPost,
  callValidAi,
  callWrongMethodAi,
} from "../services/aiClient";

export function HomePage({ slug }: { slug: string }) {
  void callValidAi(slug);
  void callWrongMethodAi(slug);
  void callRestrictedPost(slug);
  void callAbsentEndpoint(slug);
  void callHealth();
  void callInlinePing();
  return <main><h1>Workspace</h1></main>;
}
""",
        encoding="utf-8",
    )

    det = detect_repository_stack(db_session, str(repo))
    target = TargetProject(
        id=0,
        slug="django-pkg-demo",
        name="Django Package Demo",
        repo_path=str(repo),
        stack_profile_slug="django-react",
        backend_subdir=det.backend_subdir,
        frontend_subdir=det.frontend_subdir,
        description="Synthetic Django URL packages",
        is_active=True,
    )
    rep = run_target_scan(db_session, target, strict_gate=False, persist_snapshot=False)

    # Active verified chain through imported URL package -> CBV -> Workspace ORM table
    ai_chains = [c for c in rep.chains if c.http_method == "POST" and "ai-assistant" in c.http_path]
    assert ai_chains, f"Expected POST ai-assistant chain; got {rep.chains}"
    assert "t:workspaces" in ai_chains[0].truth_table_ids

    unbacked = [
        (f.rule_code, f.title)
        for f in rep.findings
        if f.rule_code in ("DISP-004", "DISP-007")
    ]
    unbacked_titles = "\n".join(title for _, title in unbacked)

    assert "POST /api/workspaces/{param}/ai-assistant" not in unbacked_titles
    assert "GET /api/v2/health" not in unbacked_titles
    assert "GET /api/v2/inline/ping" not in unbacked_titles
    # Negative controls: unsupported HTTP verb on existing endpoint & genuinely absent endpoint
    assert "DELETE /api/workspaces/{param}/ai-assistant" in unbacked_titles
    assert "POST /api/v2/workspaces/{param}/restricted" in unbacked_titles
    assert "POST /api/workspaces/{param}/missing-endpoint" in unbacked_titles


def test_django_dynamic_urlpatterns_and_cycle_guards(tmp_path: Path) -> None:
    """Keep unresolved dynamic URL construction explicit, guard cycles, and respect empty method sets."""
    dyn_repo = tmp_path / "dyn_django"
    (dyn_repo / "backend" / "app" / "urls").mkdir(parents=True)
    (dyn_repo / "backend" / "app" / "views.py").write_text(
        """class HeadOnlyView:
    def options(self, request):
        return None
""",
        encoding="utf-8",
    )
    (dyn_repo / "backend" / "app" / "urls" / "cycle_a.py").write_text(
        """from django.urls import include, path
from .cycle_b import urlpatterns as b_urls

def ok_view(request):
    return None

urlpatterns = [
    path("ok/", ok_view),
    path("self/", include("app.urls.cycle_a")),
    *b_urls,
]
""",
        encoding="utf-8",
    )
    (dyn_repo / "backend" / "app" / "urls" / "cycle_b.py").write_text(
        """from django.urls import path
from .cycle_a import urlpatterns as a_urls

def b_view(request):
    return None

urlpatterns = [
    path("b/", b_view),
    *a_urls,
]
""",
        encoding="utf-8",
    )
    (dyn_repo / "backend" / "app" / "urls" / "__init__.py").write_text(
        """from django.urls import include, path
from .cycle_a import urlpatterns as a_urls
from app.views import HeadOnlyView

def build_extra():
    return []

def get_dynamic():
    return "app.urls.cycle_b"

urlpatterns = [
    *a_urls,
    path("head-only/", HeadOnlyView.as_view(http_method_names=["head", "options"])),
    path("dyn-inc/", include(get_dynamic())),
    *[path(f"{p}/", lambda r: r) for p in ("x",)],
]
urlpatterns += build_extra()
""",
        encoding="utf-8",
    )

    manip = PythonDjangoAdapter().extract(
        dyn_repo,
        "backend",
        TruthExtractionResult(nodes=[], table_symbol_map={}, function_symbol_map={}),
    )
    assert manip.coverage_complete is False
    joined_notes = "\n".join(manip.notes).lower()
    assert "dynamic" in joined_notes or "unresolved" in joined_notes
    assert "cyclic" in joined_notes

    paths = {(r.http_method, r.full_path) for r in manip.routes}
    assert ("GET", "/ok") in paths
    assert ("GET", "/b") in paths
    # Inline lambda/view in `app/urls/cycle_a.py` has no fabricated `/head-only` GET/POST
    assert all(p != "/head-only" for _, p in paths)


@pytest.mark.skipif(
    not _PLANE_CORPUS_DIR.is_dir(),
    reason="Pinned makeplane/plane checkout is not present at /private/tmp/wythe-corpus-20261113/plane",
)
def test_plane_pinned_ai_assistant_route_and_rephrase_control(db_session: Session) -> None:
    """Verify Plane recovers POST /api/workspaces/{slug}/ai-assistant and keeps rephrase-grammar unbacked."""
    det = detect_repository_stack(db_session, str(_PLANE_CORPUS_DIR))
    target = TargetProject(
        id=0,
        slug="plane-pinned",
        name="Plane",
        repo_path=str(_PLANE_CORPUS_DIR),
        stack_profile_slug=det.recommended_profile_slug,
        backend_subdir=det.backend_subdir,
        frontend_subdir=det.frontend_subdir,
        description="Pinned Plane corpus check",
        is_active=True,
    )
    rep = run_target_scan(db_session, target, strict_gate=False, persist_snapshot=False)

    ai_chains = [
        c
        for c in rep.chains
        if c.http_method == "POST"
        and c.http_path == "/api/workspaces/{slug}/ai-assistant"
        and c.route_node_id == "m:route:plane.app.views.external.base"
    ]
    assert ai_chains, "Expected verified chain for Plane WorkspaceGPTIntegrationEndpoint POST /ai-assistant"

    ai_service_unbacked = [
        (f.rule_code, f.line, f.title)
        for f in rep.findings
        if f.source_file == "apps/web/services/ai.service.ts"
        and f.rule_code in ("DISP-004", "DISP-007")
    ]
    assert all("ai-assistant" not in title for _, _, title in ai_service_unbacked)
    assert any("rephrase-grammar" in title for _, _, title in ai_service_unbacked)

