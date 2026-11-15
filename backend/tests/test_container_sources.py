"""Unit tests for static Dockerfile, .dockerignore, and Compose source lineage."""

from __future__ import annotations

from pathlib import Path

import pytest

from app.adapters.base import ManipulatorExtractionResult, TruthExtractionResult
from app.adapters.compose_sources import augment_compose_sources, augment_container_sources
from app.adapters.dockerfile_sources import augment_dockerfile_sources
from app.adapters.python_fastapi import PythonFastApiAdapter
from app.adapters.python_services import PythonServicesAdapter


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


def test_quiet_noop_when_no_container_files(tmp_path: Path) -> None:
    _put(tmp_path, "backend/app/main.py", "from fastapi import FastAPI\napp = FastAPI()\n")
    res = _fastapi_extract(tmp_path)
    before_nodes = len(res.nodes)
    before_notes = list(res.notes)
    augment_container_sources(tmp_path, "backend", res)
    assert len(res.nodes) == before_nodes
    assert res.notes == before_notes


def test_valid_multistage_dockerfile_copy_from_builder_and_uvicorn(tmp_path: Path) -> None:
    _put(
        tmp_path,
        "backend/app/main.py",
        "from fastapi import FastAPI\nfrom app.services.orders import list_orders\napp = FastAPI()\n",
    )
    _put(
        tmp_path,
        "backend/app/services/orders.py",
        "from app.services.pricing import compute_total\ndef list_orders():\n    return compute_total()\n",
    )
    _put(tmp_path, "backend/app/services/pricing.py", "def compute_total():\n    return 42\n")
    _put(
        tmp_path,
        "Dockerfile",
        """\
FROM python:3.12-slim AS builder
ARG APP_ROOT=/build
WORKDIR $APP_ROOT
COPY --chown=1000:1000 backend /build

FROM python:3.12-slim AS runtime
WORKDIR /app
COPY --link --from=builder /build/app /app/app
CMD ["uvicorn", "app.main:app", "--host", "0.0.0.0", "--port", "8000"]
""",
    )

    res = _fastapi_extract(tmp_path)
    augment_dockerfile_sources(tmp_path, "backend", res)

    df_nodes = [n for n in res.nodes if n.id == "m:dockerfile:Dockerfile"]
    assert len(df_nodes) == 1
    df_node = df_nodes[0]
    assert df_node.tier == "manipulate"
    assert df_node.subkind == "cli"
    assert df_node.cluster == "containers"
    assert "image build and runtime execution are not observed" in df_node.summary

    main_node = next(n for n in res.nodes if n.source_file == "backend/app/main.py")
    assert any(
        e.source_id == "m:dockerfile:Dockerfile"
        and e.target_id == main_node.id
        and e.kind == "calls_helper"
        and e.verification == "declared"
        for e in res.edges
    )
    container_findings = [f for f in res.findings if f.source_file == "Dockerfile"]
    assert container_findings == []


def test_missing_copy_source_and_symlink_containment(tmp_path: Path) -> None:
    outside = tmp_path.parent / f"{tmp_path.name}_outside_secret.txt"
    outside.write_text("secret", encoding="utf-8")
    try:
        repo = tmp_path / "repo"
        _put(repo, "app/main.py", "print('ok')\n")
        (repo / "app" / "escaped.py").symlink_to(outside)
        (repo / "Dockerfile.link").symlink_to(outside)
        _put(
            repo,
            "Dockerfile",
            """\
FROM python:3.12-slim
WORKDIR /app
COPY app/does_not_exist.py /app/does_not_exist.py
COPY app/escaped.py /app/escaped.py
CMD ["python", "app/main.py"]
""",
        )

        res = _services_extract(repo)
        augment_dockerfile_sources(repo, ".", res)

        assert not any(n.id == "m:dockerfile:Dockerfile.link" for n in res.nodes)
        manip5 = [f for f in res.findings if f.rule_code == "MANIP-005" and f.source_file == "Dockerfile"]
        assert any("does_not_exist.py" in f.title and f.line == 3 for f in manip5)
        assert any("escaped.py" in f.title and f.line == 4 for f in manip5)
    finally:
        outside.unlink(missing_ok=True)


def test_dockerignore_excluded_copy_and_negation_rules(tmp_path: Path) -> None:
    _put(tmp_path, "app/main.py", "print('hello')\n")
    _put(tmp_path, "app/secret.key", "super-secret\n")
    _put(tmp_path, "private_dir/creds.json", "{}\n")
    _put(
        tmp_path,
        ".dockerignore",
        """\
# Ignore everything by default, then re-include app/ except secret.key
*
!app/**
app/secret.key
private_dir/
""",
    )
    _put(
        tmp_path,
        "Dockerfile",
        """\
FROM python:3.12-slim
WORKDIR /srv
COPY app/main.py /srv/app/main.py
COPY app/secret.key /srv/app/secret.key
COPY private_dir /srv/private_dir
CMD ["python", "app/main.py"]
""",
    )

    res = _services_extract(tmp_path)
    augment_dockerfile_sources(tmp_path, ".", res)

    findings = [f for f in res.findings if f.rule_code == "MANIP-005" and f.source_file == "Dockerfile"]
    flagged_lines = {f.line: f.title for f in findings}
    assert 3 not in flagged_lines  # re-included via !app/**
    assert 4 in flagged_lines and ".dockerignore" in flagged_lines[4]
    assert 5 in flagged_lines and ".dockerignore" in flagged_lines[5]


def test_omitted_transitive_python_import_caught_by_graph_intersection(tmp_path: Path) -> None:
    _put(
        tmp_path,
        "backend/app/main.py",
        "from fastapi import FastAPI\nfrom app.services.mid import handle\napp = FastAPI()\n",
    )
    _put(
        tmp_path,
        "backend/app/services/mid.py",
        "from app.services.leaf import compute\ndef handle():\n    return compute()\n",
    )
    _put(tmp_path, "backend/app/services/leaf.py", "def compute():\n    return 1\n")
    _put(
        tmp_path,
        "Dockerfile",
        """\
FROM python:3.12-slim
WORKDIR /app
COPY backend/app/main.py /app/app/main.py
COPY backend/app/services/mid.py /app/app/services/mid.py
CMD ["uvicorn", "app.main:app"]
""",
    )

    res = _fastapi_extract(tmp_path)
    augment_dockerfile_sources(tmp_path, "backend", res)

    unpacked = [
        f
        for f in res.findings
        if f.rule_code == "MANIP-005"
        and f.node_id == "m:dockerfile:Dockerfile"
        and "backend/app/services/leaf.py" in f.title
    ]
    assert len(unpacked) == 1
    assert "backend/app/main.py -> backend/app/services/mid.py -> backend/app/services/leaf.py" in unpacked[0].detail


def test_dockerignore_excluded_transitive_dependency_caught(tmp_path: Path) -> None:
    _put(
        tmp_path,
        "backend/app/main.py",
        "from fastapi import FastAPI\nfrom app.services.secret_calc import calc\napp = FastAPI()\n",
    )
    _put(tmp_path, "backend/app/services/secret_calc.py", "def calc():\n    return 9\n")
    _put(tmp_path, ".dockerignore", "backend/app/services/secret_calc.py\n")
    _put(
        tmp_path,
        "Dockerfile",
        """\
FROM python:3.12-slim
WORKDIR /srv/backend
COPY . /srv
CMD ["uvicorn", "app.main:app"]
""",
    )

    res = _fastapi_extract(tmp_path)
    augment_dockerfile_sources(tmp_path, "backend", res)

    findings = [f for f in res.findings if f.rule_code == "MANIP-005" and f.source_file == "Dockerfile"]
    assert len(findings) == 1
    assert "backend/app/services/secret_calc.py" in findings[0].title
    assert ".dockerignore" in findings[0].title


@pytest.mark.parametrize(
    ("instruction", "expect_manip_004"),
    [
        ('ENTRYPOINT ["python", "$APP_HOME/run.py"]', True),
        ('CMD ["~/run.sh"]', True),
        ("CMD []", True),
        ('ENTRYPOINT ["sh", "-c", "python $APP_HOME/run.py"]', False),
        ('CMD ["/bin/bash", "-lc", "~/run.sh"]', False),
        ("CMD python $APP_HOME/run.py", False),
        ('ENTRYPOINT ["python", "run.py"]\nCMD []', False),
    ],
)
def test_exec_form_var_bug_vs_valid_shell_controls(
    tmp_path: Path, instruction: str, expect_manip_004: bool
) -> None:
    _put(tmp_path, "run.py", "print('ok')\n")
    _put(tmp_path, "run.sh", "#!/bin/sh\npython run.py\n")
    _put(
        tmp_path,
        "Dockerfile",
        f"FROM python:3.12-slim\nENV APP_HOME=/app\nWORKDIR /app\nCOPY . /app\n{instruction}\n",
    )

    res = ManipulatorExtractionResult(nodes=[], edges=[], routes=[])
    augment_dockerfile_sources(tmp_path, ".", res)
    manip4 = [f for f in res.findings if f.rule_code == "MANIP-004"]
    assert bool(manip4) is expect_manip_004


def test_shell_entrypoint_and_runner_variants(tmp_path: Path) -> None:
    _put(tmp_path, "pkg/__init__.py", "")
    _put(tmp_path, "pkg/mod.py", "def run(): pass\n")
    _put(tmp_path, "scripts/start.sh", "#!/bin/sh\nexec python -m pkg.mod\n")
    _put(
        tmp_path,
        "Dockerfile.worker",
        """\
FROM python:3.12-slim
WORKDIR /app
COPY pkg /app/pkg
COPY scripts/start.sh /app/scripts/start.sh
ENTRYPOINT ["/app/scripts/start.sh"]
""",
    )

    res = _services_extract(tmp_path)
    augment_dockerfile_sources(tmp_path, ".", res)

    pairs = {(e.source_id, e.target_id) for e in res.edges}
    assert ("m:dockerfile:Dockerfile.worker", "m:script:scripts/start.sh") in pairs
    assert ("m:script:scripts/start.sh", "m:script:pkg/mod.py") in pairs


def test_compose_multiservice_linking_policy_env_and_negative_controls(tmp_path: Path) -> None:
    _put(tmp_path, "backend/app/main.py", "from fastapi import FastAPI\napp = FastAPI()\n")
    _put(tmp_path, "backend/app/worker.py", "def celery_app(): pass\n")
    _put(tmp_path, "frontend/server.js", "console.log('web');\n")
    _put(tmp_path, "workers/bull_worker.js", "console.log('bullmq');\n")
    _put(
        tmp_path,
        "Dockerfile",
        """\
FROM python:3.12-slim
WORKDIR /app
COPY backend/app /app/app
COPY workers /app/workers
CMD ["uvicorn", "app.main:app"]
""",
    )
    _put(
        tmp_path,
        "frontend/Dockerfile",
        """\
FROM node:22-alpine
WORKDIR /web
COPY server.js /web/server.js
CMD ["node", "server.js"]
""",
    )
    _put(
        tmp_path,
        "compose.yaml",
        """\
services:
  web:
    build: ./frontend
    command: ["node", "server.js"]
    depends_on:
      - api
    environment:
      PORT: 3000

  api:
    build:
      context: .
      dockerfile: Dockerfile
    command: uvicorn app.main:app --host 0.0.0.0 --port 8000
    depends_on:
      postgres:
        condition: service_healthy
      redis:
        condition: service_started
    environment:
      DUTY_HOUR_LIMIT: 80
      SUPERVISION_RATIO: "${SUPERVISION_RATIO}"
      ENABLE_DUTY_HOUR_AUDIT: true

  worker:
    build: .
    command: celery -A app.worker worker -l info
    depends_on:
      - postgres
      - redis
    environment:
      - SHIFT_CAP
      - WORKER_CONCURRENCY=4
      - CALL_CAP=6

  bull:
    build: .
    command: ["node", "workers/bull_worker.js"]
    depends_on:
      - redis

  postgres:
    image: postgres:16-alpine

  redis:
    image: valkey/valkey:8-alpine

  gateway:
    image: nginx:1.27-alpine
""",
    )

    res = _fastapi_extract(tmp_path)
    augment_container_sources(tmp_path, "backend", res)

    node_by_id = {n.id: n for n in res.nodes}
    for svc in ("web", "api", "worker", "bull", "postgres", "redis", "gateway"):
        cid = f"m:compose:compose.yaml:{svc}"
        assert cid in node_by_id
        assert node_by_id[cid].cluster == "containers"
        assert node_by_id[cid].subkind == "cli"

    main_node = next(n for n in res.nodes if n.source_file == "backend/app/main.py")
    worker_node = next(n for n in res.nodes if n.source_file == "backend/app/worker.py")
    edges = {(e.source_id, e.target_id) for e in res.edges if e.verification == "declared"}

    assert ("m:compose:compose.yaml:web", "m:dockerfile:frontend/Dockerfile") in edges
    assert ("m:compose:compose.yaml:web", "m:script:frontend/server.js") in edges
    assert ("m:compose:compose.yaml:web", "m:compose:compose.yaml:api") in edges
    assert ("m:compose:compose.yaml:api", "m:dockerfile:Dockerfile") in edges
    assert ("m:compose:compose.yaml:api", main_node.id) in edges
    assert ("m:compose:compose.yaml:api", "m:compose:compose.yaml:postgres") in edges
    assert ("m:compose:compose.yaml:api", "m:compose:compose.yaml:redis") in edges
    assert ("m:compose:compose.yaml:worker", "m:dockerfile:Dockerfile") in edges
    assert ("m:compose:compose.yaml:worker", worker_node.id) in edges
    assert ("m:compose:compose.yaml:bull", "m:script:workers/bull_worker.js") in edges

    # MANIP-001 checks + negative controls
    manip1 = [f for f in res.findings if f.rule_code == "MANIP-001" and f.source_file == "compose.yaml"]
    flagged_titles = " | ".join(f.title for f in manip1)
    assert "DUTY_HOUR_LIMIT" in flagged_titles
    assert "CALL_CAP" in flagged_titles
    assert "SUPERVISION_RATIO" not in flagged_titles  # pure ${VAR} pass-through
    assert "ENABLE_DUTY_HOUR_AUDIT" not in flagged_titles  # boolean toggle
    assert "SHIFT_CAP" not in flagged_titles  # bare pass-through list item
    assert "WORKER_CONCURRENCY" not in flagged_titles  # non-policy operational knob
    assert "PORT" not in flagged_titles
    assert node_by_id["m:compose:compose.yaml:api"].status == "policy_in_code"
    assert node_by_id["m:compose:compose.yaml:worker"].status == "policy_in_code"
    assert node_by_id["m:compose:compose.yaml:web"].status == "clean"

    # Coverage note checks
    compose_notes = [n for n in res.notes if n.startswith("Compose source coverage:")]
    assert len(compose_notes) == 1
    assert "postgres [postgres]" in compose_notes[0]
    assert "redis [valkey]" in compose_notes[0]
    assert "gateway [nginx:1.27-alpine]" in compose_notes[0]

    # Standalone augment_compose_sources without pre-supplied dockerfiles dict remains valid
    standalone = _fastapi_extract(tmp_path)
    augment_compose_sources(tmp_path, "backend", standalone)
    s_nodes = {n.id for n in standalone.nodes}
    assert all(e.source_id in s_nodes and e.target_id in s_nodes for e in standalone.edges)


def test_containerfile_numeric_stage_json_copy_url_add_and_excluded_dirs(tmp_path: Path) -> None:
    _put(tmp_path, "backend/app/wsgi.py", "def application(env, start): pass\n")
    _put(tmp_path, "backend/app/ignored_mod.py", "X = 1\n")
    _put(tmp_path, "backend/.dockerignore", "app/ignored_mod.py\n")
    # Excluded directories (`tests/`, `.hidden/`) must never be scanned as live containers
    _put(tmp_path, "tests/Dockerfile", "FROM scratch\nCOPY nope /nope\n")
    _put(tmp_path, ".hidden/Dockerfile", "FROM scratch\nCOPY nope /nope\n")
    _put(
        tmp_path,
        "backend/Containerfile",
        """\
FROM python:3.12-slim
WORKDIR /stage0
COPY ["app/wsgi.py", "/stage0/app/wsgi.py"]

FROM python:3.12-slim
WORKDIR /srv
ADD https://example.com/healthcheck.tar.gz /tmp/
COPY --from=0 ["app/wsgi.py", "/srv/app/wsgi.py"]
CMD ["gunicorn", "-w", "4", "app.wsgi:application"]
""",
    )

    res = _fastapi_extract(tmp_path)
    augment_dockerfile_sources(tmp_path, "backend", res)

    node_ids = {n.id for n in res.nodes}
    assert "m:dockerfile:backend/Containerfile" in node_ids
    assert "m:dockerfile:tests/Dockerfile" not in node_ids
    assert "m:dockerfile:.hidden/Dockerfile" not in node_ids

    wsgi_node = next(n for n in res.nodes if n.source_file == "backend/app/wsgi.py")
    assert any(
        e.source_id == "m:dockerfile:backend/Containerfile" and e.target_id == wsgi_node.id
        for e in res.edges
    )
    assert [f for f in res.findings if f.source_file == "backend/Containerfile"] == []


def test_subdir_compose_manage_py_and_env_default_fallback_policy(tmp_path: Path) -> None:
    _put(tmp_path, "manage.py", "import sys\n")
    _put(
        tmp_path,
        "Dockerfile",
        """\
FROM python:3.12-slim
WORKDIR /code
COPY manage.py /code/manage.py
CMD ["python", "manage.py", "runserver"]
""",
    )
    _put(tmp_path, "tests/docker-compose.yml", "services:\n  bad:\n    build: ./missing\n")
    _put(
        tmp_path,
        "deploy/docker-compose.yml",
        """\
services:
  django:
    build:
      context: ..
      dockerfile: Dockerfile
    command: ["python", "manage.py", "migrate"]
    environment:
      WEEKLY_MAX: "${WEEKLY_MAX:-60}"
""",
    )

    res = _services_extract(tmp_path)
    augment_container_sources(tmp_path, ".", res)

    node_ids = {n.id for n in res.nodes}
    assert "m:compose:deploy/docker-compose.yml:django" in node_ids
    assert "m:compose:tests/docker-compose.yml:bad" not in node_ids

    edges = {(e.source_id, e.target_id) for e in res.edges}
    assert ("m:compose:deploy/docker-compose.yml:django", "m:dockerfile:Dockerfile") in edges
    assert ("m:compose:deploy/docker-compose.yml:django", "m:script:manage.py") in edges

    manip1 = [
        f
        for f in res.findings
        if f.rule_code == "MANIP-001" and f.source_file == "deploy/docker-compose.yml"
    ]
    assert len(manip1) == 1
    assert "WEEKLY_MAX" in manip1[0].title
