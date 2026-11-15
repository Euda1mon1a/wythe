"""Unit tests for v0.2.2 Kubernetes static adapter, .docker/ & compose variants, and symbol_links."""

from __future__ import annotations

from pathlib import Path

import pytest

from app.adapters.base import ManipulatorExtractionResult, TruthExtractionResult
from app.adapters.compose_sources import augment_container_sources, discover_compose_files
from app.adapters.dockerfile_sources import discover_dockerfiles
from app.adapters.k8s_sources import augment_k8s_sources, discover_k8s_files
from app.adapters.python_fastapi import PythonFastApiAdapter
from app.adapters.python_services import PythonServicesAdapter
from app.services.llm_context_service import _bfs_cone_direction


def _put(root: Path, rel: str, content: str) -> Path:
    dest = root / rel
    dest.parent.mkdir(parents=True, exist_ok=True)
    dest.write_text(content, encoding="utf-8")
    return dest


def _fastapi_extract(root: Path, backend_subdir: str = "backend") -> ManipulatorExtractionResult:
    truth = TruthExtractionResult(nodes=[], table_symbol_map={}, function_symbol_map={})
    return PythonFastApiAdapter().extract(root, backend_subdir, truth)


def _services_extract(root: Path) -> ManipulatorExtractionResult:
    truth = TruthExtractionResult(nodes=[], table_symbol_map={}, function_symbol_map={})
    return PythonServicesAdapter().extract(root, ".", truth)


def test_dot_docker_dir_and_compose_filename_variants(tmp_path: Path) -> None:
    _put(tmp_path, "backend/app/main.py", "from fastapi import FastAPI\napp = FastAPI()\n")
    _put(tmp_path, "slack_bot/bot.py", "def run_bot():\n    return True\n")
    _put(
        tmp_path,
        ".docker/backend.Dockerfile",
        """\
FROM python:3.12-slim
WORKDIR /app
COPY backend/app /app/app
CMD ["uvicorn", "app.main:app", "--host", "0.0.0.0"]
""",
    )
    _put(
        tmp_path,
        ".docker/frontend.Dockerfile",
        """\
FROM node:20-alpine
WORKDIR /web
CMD ["npm", "run", "start"]
""",
    )
    # Other dot-directories must remain excluded
    _put(tmp_path, ".secret_cache/Dockerfile", "FROM alpine:3.20\nCMD [\"echo\", \"nope\"]\n")

    _put(
        tmp_path,
        ".docker/docker-compose.prod.yml",
        """\
services:
  backend:
    build:
      context: ..
      dockerfile: .docker/backend.Dockerfile
    image: registry.example/acme-backend:prod
  postgres:
    image: pgvector/pgvector:pg16
""",
    )
    _put(
        tmp_path,
        "docker-compose.local.yml",
        """\
services:
  api:
    build:
      context: .
      dockerfile: .docker/backend.Dockerfile
  redis:
    image: redis:7-alpine
""",
    )
    _put(
        tmp_path,
        "docker-compose.ollama.yml",
        """\
services:
  ollama:
    image: ollama/ollama:latest
""",
    )
    _put(
        tmp_path,
        "docker-compose.slack-bot.yml",
        """\
services:
  slack-bot:
    image: python:3.12-slim
    volumes:
      - ./slack_bot:/bot/slack_bot
    working_dir: /bot
    command: ["python", "slack_bot/bot.py"]
""",
    )
    _put(
        tmp_path,
        "compose.staging.yaml",
        """\
services:
  staging-api:
    build:
      context: .
      dockerfile: .docker/backend.Dockerfile
""",
    )

    dfs, _ = discover_dockerfiles(tmp_path)
    df_rels = [p.relative_to(tmp_path).as_posix() for p in dfs]
    assert df_rels == [".docker/backend.Dockerfile", ".docker/frontend.Dockerfile"]

    cfs = discover_compose_files(tmp_path)
    cf_rels = [p.relative_to(tmp_path).as_posix() for p in cfs]
    assert cf_rels == [
        ".docker/docker-compose.prod.yml",
        "compose.staging.yaml",
        "docker-compose.local.yml",
        "docker-compose.ollama.yml",
        "docker-compose.slack-bot.yml",
    ]

    res = _fastapi_extract(tmp_path)
    augment_container_sources(tmp_path, "backend", res)

    node_by_id = {n.id: n for n in res.nodes}
    assert "m:dockerfile:.docker/backend.Dockerfile" in node_by_id
    assert "m:dockerfile:.docker/frontend.Dockerfile" in node_by_id
    assert node_by_id["m:compose:.docker/docker-compose.prod.yml:backend"].label == ".docker/backend"
    assert node_by_id["m:compose:docker-compose.local.yml:api"].label == "api"
    assert node_by_id["m:compose:docker-compose.slack-bot.yml:slack-bot"].label == "slack-bot"

    assert any(
        e.source_id == "m:compose:.docker/docker-compose.prod.yml:backend"
        and e.target_id == "m:dockerfile:.docker/backend.Dockerfile"
        for e in res.edges
    )
    bot_node = next(n for n in res.nodes if n.source_file == "slack_bot/bot.py")
    assert any(
        e.source_id == "m:compose:docker-compose.slack-bot.yml:slack-bot"
        and e.target_id == bot_node.id
        and e.symbol_links == []
        for e in res.edges
    )
    assert [f for f in res.findings if f.rule_code == "MANIP-005"] == []


def test_symbol_links_across_dockerfile_compose_k8s_and_surgical_cone(tmp_path: Path) -> None:
    _put(
        tmp_path,
        "backend/app/main.py",
        """\
from app.services.live import build_api
from app.services.cold import run_cold_audit


def create_app():
    return build_api()


def unused_cli_maintenance():
    return run_cold_audit()
""",
    )
    _put(tmp_path, "backend/app/services/live.py", "def build_api():\n    return 'live'\n")
    _put(tmp_path, "backend/app/services/cold.py", "def run_cold_audit():\n    return 'cold'\n")
    _put(
        tmp_path,
        "backend/app/worker.py",
        """\
from app.services.live import build_api


class CeleryStub:
    def task(self, fn):
        return fn


celery_app = CeleryStub()


@celery_app.task
def run_job():
    return build_api()
""",
    )
    _put(
        tmp_path,
        "backend/app/actor_worker.py",
        """\
from app.services.live import build_api
from app.services.cold import run_cold_audit


def process_queue():
    return build_api()


def unused_repair():
    return run_cold_audit()
""",
    )
    _put(tmp_path, "backend/scripts/nightly.py", "def main():\n    return 0\n")
    _put(
        tmp_path,
        "Dockerfile",
        """\
FROM python:3.12-slim
WORKDIR /app
COPY backend/app /app/app
COPY backend/scripts /app/scripts
CMD ["uvicorn", "app.main:create_app", "--factory"]
""",
    )
    _put(
        tmp_path,
        "compose.yaml",
        """\
services:
  worker:
    build: .
    command: ["celery", "-A", "app.worker.celery_app", "worker", "-l", "info"]
  actor:
    build: .
    command: ["dramatiq", "app.actor_worker:process_queue"]
  wsgi:
    build: .
    command: gunicorn app.main:create_app
""",
    )
    _put(
        tmp_path,
        "k8s/workloads.yaml",
        """\
apiVersion: apps/v1
kind: Deployment
metadata:
  name: api-deploy
spec:
  template:
    spec:
      containers:
        - name: api
          image: ghcr.io/acme/my-service:1.0.0
          command: ["uvicorn", "app.main:create_app", "--factory"]
---
apiVersion: batch/v1
kind: CronJob
metadata:
  name: nightly-sweep
spec:
  schedule: "0 2 * * *"
  jobTemplate:
    spec:
      template:
        spec:
          containers:
            - name: sweep
              image: ghcr.io/acme/my-service:1.0.0
              command: ["python", "/app/scripts/nightly.py"]
""",
    )

    res = _fastapi_extract(tmp_path)
    augment_container_sources(tmp_path, "backend", res)

    main_node = next(n for n in res.nodes if n.source_file == "backend/app/main.py")
    live_node = next(n for n in res.nodes if n.source_file == "backend/app/services/live.py")
    cold_node = next(n for n in res.nodes if n.source_file == "backend/app/services/cold.py")
    worker_node = next(n for n in res.nodes if n.source_file == "backend/app/worker.py")
    actor_node = next(n for n in res.nodes if n.source_file == "backend/app/actor_worker.py")
    nightly_node = next(n for n in res.nodes if n.source_file == "backend/scripts/nightly.py")

    df_edge = next(
        e for e in res.edges if e.source_id == "m:dockerfile:Dockerfile" and e.target_id == main_node.id
    )
    assert df_edge.symbol_links == ["*->create_app"]

    # Non-callable variable `celery_app = CeleryStub()` falls back to `[]` so `@celery_app.task` flows
    celery_edge = next(
        e for e in res.edges if e.source_id == "m:compose:compose.yaml:worker" and e.target_id == worker_node.id
    )
    assert celery_edge.symbol_links == []

    # Callable function `process_queue` narrows surgically to `["*->process_queue"]`
    actor_edge = next(
        e for e in res.edges if e.source_id == "m:compose:compose.yaml:actor" and e.target_id == actor_node.id
    )
    assert actor_edge.symbol_links == ["*->process_queue"]

    wsgi_edge = next(
        e for e in res.edges if e.source_id == "m:compose:compose.yaml:wsgi" and e.target_id == main_node.id
    )
    assert wsgi_edge.symbol_links == ["*->create_app"]

    k8s_api_edge = next(
        e
        for e in res.edges
        if e.source_id == "m:k8s:k8s/workloads.yaml:deployment:api-deploy" and e.target_id == main_node.id
    )
    assert k8s_api_edge.symbol_links == ["*->create_app"]

    k8s_cron_edge = next(
        e
        for e in res.edges
        if e.source_id == "m:k8s:k8s/workloads.yaml:cronjob:nightly-sweep" and e.target_id == nightly_node.id
    )
    assert k8s_cron_edge.symbol_links == []

    # Verify surgical BFS cone narrows through `*->create_app` -> `create_app->build_api`
    valid_ids = {n.id for n in res.nodes}
    down_edges: dict[str, list[tuple[object, str]]] = {}
    for edge in res.edges:
        down_edges.setdefault(edge.source_id, []).append((edge, edge.target_id))

    ordered, _ = _bfs_cone_direction(
        ["m:dockerfile:Dockerfile"],
        down_edges,  # type: ignore[arg-type]
        valid_ids,
        reverse=False,
    )
    assert main_node.id in ordered
    assert live_node.id in ordered
    assert cold_node.id not in ordered

    # Celery worker reaches `@celery_app.task def run_job` -> `live_node` without severing
    celery_ordered, _ = _bfs_cone_direction(
        ["m:compose:compose.yaml:worker"],
        down_edges,  # type: ignore[arg-type]
        valid_ids,
        reverse=False,
    )
    assert worker_node.id in celery_ordered
    assert live_node.id in celery_ordered

    # Dramatiq callable worker reaches `process_queue` -> `live_node` while pruning `cold_node`
    actor_ordered, _ = _bfs_cone_direction(
        ["m:compose:compose.yaml:actor"],
        down_edges,  # type: ignore[arg-type]
        valid_ids,
        reverse=False,
    )
    assert actor_node.id in actor_ordered
    assert live_node.id in actor_ordered
    assert cold_node.id not in actor_ordered


def test_k8s_multi_workload_kinds_list_wrapper_configmap_and_symlinks(tmp_path: Path) -> None:
    outside = tmp_path.parent / f"{tmp_path.name}_outside_k8s.yaml"
    outside.write_text("apiVersion: v1\nkind: Pod\nmetadata:\n  name: escaped\n", encoding="utf-8")
    try:
        repo = tmp_path / "repo"
        _put(repo, "app/main.py", "def app():\n    return 'ok'\n")
        _put(repo, "mkdocs.yml", "site_name: Example Docs\nnav:\n  - Home: index.md\n")
        _put(
            repo,
            ".docker/app.Dockerfile",
            """\
FROM python:3.12-slim
WORKDIR /srv
COPY app /srv/app
CMD ["gunicorn", "app.main:app"]
""",
        )
        _put(
            repo,
            "k8s/cluster.yaml",
            """\
apiVersion: v1
kind: ConfigMap
metadata:
  name: app-settings
data:
  LOG_LEVEL: info
---
apiVersion: apps/v1
kind: Deployment
metadata:
  name: web-app
spec:
  template:
    spec:
      initContainers:
        - name: wait-db
          image: busybox:1.36
          command: ["sh", "-c", "echo waiting"]
      containers:
        - name: app
          image: ghcr.io/org/app:sha-abc
          envFrom:
            - configMapRef:
                name: app-settings
---
apiVersion: apps/v1
kind: StatefulSet
metadata:
  name: primary-db
spec:
  template:
    spec:
      containers:
        - name: postgres
          image: postgres:16-alpine
---
apiVersion: apps/v1
kind: DaemonSet
metadata:
  name: node-agent
spec:
  template:
    spec:
      containers:
        - name: agent
          image: fluent/fluent-bit:3.1
""",
        )
        _put(
            repo,
            ".k8s/jobs-list.yaml",
            """\
apiVersion: v1
kind: List
items:
  - apiVersion: batch/v1
    kind: Job
    metadata:
      name: db-migrate
    spec:
      template:
        spec:
          volumes:
            - name: cfg
              configMap:
                name: app-settings
          containers:
            - name: migrate
              image: ghcr.io/org/app:sha-abc
              command: ["python", "/srv/app/main.py"]
  - apiVersion: v1
    kind: Pod
    metadata:
      name: smoke-pod
    spec:
      containers:
        - name: curl
          image: curlimages/curl:8.9.1
          command: ["curl", "-fsS", "http://web-app:8000/health"]
""",
        )
        (repo / "k8s" / "escaped.yaml").symlink_to(outside)

        discovered = [p.relative_to(repo).as_posix() for p, _ in discover_k8s_files(repo)]
        assert "k8s/escaped.yaml" not in discovered

        res = _services_extract(repo)
        augment_container_sources(repo, ".", res)

        nids = {n.id for n in res.nodes}
        assert "m:k8s:k8s/cluster.yaml:configmap:app-settings" in nids
        assert "m:k8s:k8s/cluster.yaml:deployment:web-app" in nids
        assert "m:k8s:k8s/cluster.yaml:statefulset:primary-db" in nids
        assert "m:k8s:k8s/cluster.yaml:daemonset:node-agent" in nids
        assert "m:k8s:.k8s/jobs-list.yaml:job:db-migrate" in nids
        assert "m:k8s:.k8s/jobs-list.yaml:pod:smoke-pod" in nids
        assert not any("escaped" in nid for nid in nids)
        assert not any("mkdocs" in nid for nid in nids)

        # Deployment and Job match `.docker/app.Dockerfile`; busybox/postgres/fluent-bit/curl do not
        df_edges = [e for e in res.edges if e.target_id == "m:dockerfile:.docker/app.Dockerfile"]
        assert {e.source_id for e in df_edges} == {
            "m:k8s:k8s/cluster.yaml:deployment:web-app",
            "m:k8s:.k8s/jobs-list.yaml:job:db-migrate",
        }

        # Both Deployment (envFrom) and Job (volume) link to ConfigMap
        cm_edges = [e for e in res.edges if e.target_id == "m:k8s:k8s/cluster.yaml:configmap:app-settings"]
        assert {e.source_id for e in cm_edges} == {
            "m:k8s:k8s/cluster.yaml:deployment:web-app",
            "m:k8s:.k8s/jobs-list.yaml:job:db-migrate",
        }
        assert any("backing DB/Redis image(s): primary-db/postgres [postgres]" in n for n in res.notes)
    finally:
        outside.unlink(missing_ok=True)


@pytest.mark.parametrize(
    ("command_yaml", "args_yaml", "expect_manip_004"),
    [
        ('["python", "$(APP_HOME)/run.py", "--port=$(PORT)", "$$LITERAL"]', "[]", False),
        ('["sh", "-c"]', '["python $APP_HOME/run.py && ~/cleanup.sh"]', False),
        ('["/bin/bash", "-lc", "python ${APP_HOME}/run.py"]', "[]", False),
        ('["python", "$APP_HOME/run.py"]', "[]", True),
        ('["python", "${APP_HOME}/run.py"]', "[]", True),
        ('["~/run.sh"]', "[]", True),
        ('[""]', "[]", True),
        ("null", '["$UNEXPANDED_ARG"]', True),
        ("null", '["$(VALID_K8S_ARG)"]', False),
    ],
)
def test_k8s_exec_parens_var_allowed_vs_bare_shell_var_flagged(
    tmp_path: Path,
    command_yaml: str,
    args_yaml: str,
    expect_manip_004: bool,
) -> None:
    _put(tmp_path, "app/run.py", "def main():\n    return 1\n")
    cmd_line = f"          command: {command_yaml}\n" if command_yaml != "null" else ""
    args_line = f"          args: {args_yaml}\n" if args_yaml != "[]" else ""
    _put(
        tmp_path,
        "k8s/deploy.yaml",
        f"""\
apiVersion: apps/v1
kind: Deployment
metadata:
  name: runner
spec:
  template:
    spec:
      containers:
        - name: runner
          image: ghcr.io/acme/runner:latest
          env:
            - name: APP_HOME
              value: "/workspace/app"
            - name: PORT
              value: "8080"
          workingDir: /workspace
{cmd_line}{args_line}""",
    )
    res = _services_extract(tmp_path)
    augment_k8s_sources(tmp_path, ".", res)
    m4 = [f for f in res.findings if f.rule_code == "MANIP-004" and f.source_file == "k8s/deploy.yaml"]
    if expect_manip_004:
        assert len(m4) == 1
    else:
        assert m4 == []
        if "$(APP_HOME)/run.py" in command_yaml:
            run_node = next(n for n in res.nodes if n.source_file == "app/run.py")
            assert any(
                e.source_id == "m:k8s:k8s/deploy.yaml:deployment:runner" and e.target_id == run_node.id
                for e in res.edges
            )


def test_k8s_policy_in_env_and_configmap_vs_value_from_negative_controls(tmp_path: Path) -> None:
    _put(
        tmp_path,
        "manifests/policy.yaml",
        """\
apiVersion: v1
kind: ConfigMap
metadata:
  name: scheduling-config
data:
  MAX_HOURS_LIMIT: "80"
  FEATURE_THRESHOLD_ENABLED: "true"
  app.env: |
    LOG_FORMAT=json
    SUPERVISION_RATIO=4
---
apiVersion: v1
kind: ConfigMap
metadata:
  name: clean-config
data:
  LOG_LEVEL: "info"
  PASS_THROUGH_LIMIT: "$(RUNTIME_LIMIT)"
---
apiVersion: apps/v1
kind: Deployment
metadata:
  name: scheduler
spec:
  template:
    spec:
      containers:
        - name: scheduler
          image: ghcr.io/acme/scheduler:1.0
          env:
            - name: MAX_UTILIZATION_THRESHOLD
              value: "0.85"
            - name: SECRET_PENALTY_WEIGHT
              valueFrom:
                secretKeyRef:
                  name: solver-secrets
                  key: penalty_weight
            - name: CM_HOURS_LIMIT
              valueFrom:
                configMapKeyRef:
                  name: scheduling-config
                  key: MAX_HOURS_LIMIT
            - name: INTERP_CAPACITY
              value: "$(POD_CAPACITY)"
            - name: SHELL_INTERP_CAPACITY
              value: "${POD_CAPACITY}"
""",
    )

    res = ManipulatorExtractionResult(nodes=[], edges=[], findings=[], routes=[])
    augment_k8s_sources(tmp_path, ".", res)

    node_by_id = {n.id: n for n in res.nodes}
    assert node_by_id["m:k8s:manifests/policy.yaml:configmap:scheduling-config"].status == "policy_in_code"
    assert node_by_id["m:k8s:manifests/policy.yaml:configmap:clean-config"].status == "clean"
    assert node_by_id["m:k8s:manifests/policy.yaml:deployment:scheduler"].status == "policy_in_code"

    m1 = [f for f in res.findings if f.rule_code == "MANIP-001"]
    titles = " | ".join(f.title for f in m1)
    assert len(m1) == 3
    assert "MAX_HOURS_LIMIT" in titles
    assert "SUPERVISION_RATIO" in titles
    assert "MAX_UTILIZATION_THRESHOLD" in titles
    assert "SECRET_PENALTY_WEIGHT" not in titles
    assert "CM_HOURS_LIMIT" not in titles
    assert "INTERP_CAPACITY" not in titles
    assert "SHELL_INTERP_CAPACITY" not in titles


def test_helm_mustache_templates_safely_skipped_with_coverage_note(tmp_path: Path) -> None:
    _put(
        tmp_path,
        "k8s/templates/deployment.yaml",
        """\
{{- if .Values.enabled }}
apiVersion: apps/v1
kind: Deployment
metadata:
  name: {{ include "chart.fullname" . }}
spec:
  template:
    spec:
      containers:
        - name: app
          image: "{{ .Values.image.repository }}:{{ .Values.image.tag }}"
{{- end }}
""",
    )
    res = ManipulatorExtractionResult(nodes=[], edges=[], findings=[], routes=[])
    augment_container_sources(tmp_path, ".", res)

    assert res.nodes == []
    assert res.findings == []
    assert any(
        "skipped 1 unrendered Helm/Mustache `{{` template file(s)" in n
        and "k8s/templates/deployment.yaml" in n
        for n in res.notes
    )
