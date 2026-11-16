"""Regression tests for Wave 1 Issue #75: static container CLI launchers & micro-VM docs."""

from __future__ import annotations

import plistlib
from pathlib import Path

import pytest

from app.adapters.base import ManipulatorExtractionResult, TruthExtractionResult
from app.adapters.compose_sources import augment_container_sources
from app.adapters.container_launchers import (
    augment_container_launchers,
    parse_container_run_argv,
)
from app.adapters.plugin_registry import run_manipulator_plugins
from app.adapters.python_fastapi import PythonFastApiAdapter
from app.adapters.python_services import PythonServicesAdapter
from app.services.llm_context_service import _bfs_cone_direction

REPO_ROOT = Path(__file__).resolve().parents[2]


def _put(root: Path, rel: str, content: str) -> Path:
    dest = root / rel
    dest.parent.mkdir(parents=True, exist_ok=True)
    dest.write_text(content, encoding="utf-8")
    return dest


def _put_plist(root: Path, rel: str, payload: dict[str, object]) -> Path:
    dest = root / rel
    dest.parent.mkdir(parents=True, exist_ok=True)
    dest.write_bytes(plistlib.dumps(payload))
    return dest


def _fastapi_extract(root: Path, backend_subdir: str = "backend") -> ManipulatorExtractionResult:
    truth = TruthExtractionResult(nodes=[], table_symbol_map={}, function_symbol_map={})
    return PythonFastApiAdapter().extract(root, backend_subdir, truth)


def _services_extract(root: Path) -> ManipulatorExtractionResult:
    truth = TruthExtractionResult(nodes=[], table_symbol_map={}, function_symbol_map={})
    return PythonServicesAdapter().extract(root, ".", truth)


def test_apple_container_run_cli_grammar_and_launchd_bridge(tmp_path: Path) -> None:
    inv = parse_container_run_argv(
        [
            "/usr/local/bin/container",
            "run",
            "--rm",
            "--virtualization",
            "--rosetta",
            "-c",
            "4",
            "-m",
            "4G",
            "--uid",
            "1000",
            "--gid",
            "1000",
            "--network",
            "none",
            "--mount",
            "type=bind,source=./backend,target=/app,readonly",
            "-v",
            "./scratch:/tmp/out:rw",
            "-e",
            "LOG_LEVEL=info",
            "-e",
            "PASSTHROUGH_TOKEN",
            "--env-file",
            "config/runtime.env",
            "-w",
            "/app",
            "--entrypoint",
            "uvicorn",
            "acme-api:0.2.2",
            "app.main:create_app",
            "--factory",
        ],
        line=12,
    )
    assert inv is not None
    assert inv.cli == "container"
    assert inv.rm is True
    assert inv.network == "none"
    assert inv.workdir == "/app"
    assert inv.entrypoint == "uvicorn"
    assert inv.image == "acme-api:0.2.2"
    assert inv.command_argv == ("app.main:create_app", "--factory")
    assert [(e.key, e.value) for e in inv.env] == [
        ("LOG_LEVEL", "info"),
        ("PASSTHROUGH_TOKEN", None),
    ]
    assert inv.env_files == (("config/runtime.env", 12),)
    assert [(m.kind, m.source, m.target, m.readonly) for m in inv.mounts] == [
        ("bind", "./backend", "/app", True),
        ("bind", "./scratch", "/tmp/out", False),
    ]

    _put(
        tmp_path,
        "backend/app/main.py",
        "def create_app():\n    return 'ok'\n",
    )
    _put(
        tmp_path,
        "Dockerfile",
        "FROM python:3.12-slim\nWORKDIR /app\nCOPY backend/app /app/app\nCMD [\"uvicorn\", \"app.main:create_app\", \"--factory\"]\n",
    )
    _put(
        tmp_path,
        "scripts/build_image.sh",
        "#!/bin/sh\ncontainer build -t acme-api:latest -f Dockerfile .\n",
    )
    _put_plist(
        tmp_path,
        "launchagents/com.acme.api.plist",
        {
            "Label": "com.acme.api",
            "ProgramArguments": [
                "/usr/local/bin/container",
                "run",
                "--rm",
                "--mount",
                "type=bind,source=backend,target=/app,readonly",
                "-w",
                "/app",
                "acme-api:latest",
                "uvicorn",
                "app.main:create_app",
                "--factory",
            ],
        },
    )

    # FastAPI profile: m:launchd:* does not pre-exist and must be created & wired
    res_fapi = _fastapi_extract(tmp_path)
    augment_container_sources(tmp_path, "backend", res_fapi)
    launchd_nodes = [n for n in res_fapi.nodes if n.id == "m:launchd:launchagents/com.acme.api.plist"]
    assert len(launchd_nodes) == 1
    assert launchd_nodes[0].cluster == "launchd"
    main_node = next(n for n in res_fapi.nodes if n.source_file == "backend/app/main.py")
    assert any(
        e.source_id == "m:launchd:launchagents/com.acme.api.plist"
        and e.target_id == "m:dockerfile:Dockerfile"
        and e.verification == "declared"
        for e in res_fapi.edges
    )
    ep_edge = next(
        e
        for e in res_fapi.edges
        if e.source_id == "m:launchd:launchagents/com.acme.api.plist"
        and e.target_id == main_node.id
    )
    assert ep_edge.symbol_links == ["*->create_app"]
    assert any("bind mount(s): 1 read-only / 0 writable" in n for n in res_fapi.notes)

    # python-services profile: m:launchd:* pre-exists from launchd_sources.py and must be reused
    res_svc = _services_extract(tmp_path)
    augment_container_sources(tmp_path, ".", res_svc)
    assert len([n for n in res_svc.nodes if n.id == "m:launchd:launchagents/com.acme.api.plist"]) == 1


def test_systemd_podman_run_and_direct_execstart_script_targets(tmp_path: Path) -> None:
    _put(
        tmp_path,
        "backend/app/actor.py",
        "from app.services.jobs import run_batch\n\ndef process_queue():\n    return run_batch()\n",
    )
    _put(tmp_path, "backend/app/services/jobs.py", "def run_batch():\n    return 1\n")
    _put(tmp_path, "backend/scripts/housekeeping.py", "def main():\n    return 0\n")
    _put(
        tmp_path,
        ".docker/worker.Containerfile",
        "FROM python:3.12-slim\nWORKDIR /srv\nCOPY backend/app /srv/app\nCMD [\"dramatiq\", \"app.actor:process_queue\"]\n",
    )
    _put(
        tmp_path,
        "scripts/build_worker.sh",
        "#!/bin/sh\npodman build -t ghcr.io/acme/worker:1.0.0 -f .docker/worker.Containerfile .\n",
    )
    _put(
        tmp_path,
        "deploy/acme-worker.service",
        """\
[Unit]
Description=Acme Queue Worker

[Service]
WorkingDirectory=backend
ExecStartPre=-/usr/bin/podman pull ghcr.io/acme/worker:1.0.0
ExecStart=/usr/bin/podman run --rm --read-only --network=none \\
  -v ./app:/srv/app:ro \\
  -w /srv \\
  ghcr.io/acme/worker:1.0.0 \\
  dramatiq app.actor:process_queue
""",
    )
    _put(
        tmp_path,
        "deploy/housekeeping.service",
        """\
[Unit]
Description=Nightly Housekeeping

[Service]
WorkingDirectory=backend
ExecStart=-+/usr/bin/python3 scripts/housekeeping.py
""",
    )

    res = _fastapi_extract(tmp_path)
    run_manipulator_plugins(tmp_path, "backend", res)

    node_by_id = {n.id: n for n in res.nodes}
    w_unit = node_by_id["m:systemd:deploy/acme-worker.service"]
    h_unit = node_by_id["m:systemd:deploy/housekeeping.service"]
    assert w_unit.tier == "manipulate" and w_unit.subkind == "cli" and w_unit.cluster == "systemd"
    assert h_unit.tier == "manipulate" and h_unit.subkind == "cli" and h_unit.cluster == "systemd"

    actor_node = next(n for n in res.nodes if n.source_file == "backend/app/actor.py")
    hk_node = next(n for n in res.nodes if n.source_file == "backend/scripts/housekeeping.py")

    assert any(
        e.source_id == w_unit.id and e.target_id == "m:dockerfile:.docker/worker.Containerfile"
        for e in res.edges
    )
    actor_edge = next(e for e in res.edges if e.source_id == w_unit.id and e.target_id == actor_node.id)
    assert actor_edge.symbol_links == ["*->process_queue"]
    assert any(e.source_id == h_unit.id and e.target_id == hk_node.id for e in res.edges)

    # Systemd linkage clears false MANIP-003 inert-module findings on worker & script nodes
    m3_ids = {f.node_id for f in res.findings if f.rule_code == "MANIP-003"}
    assert actor_node.id not in m3_ids
    assert hk_node.id not in m3_ids
    assert actor_node.status == "clean"


def test_shell_wrappers_non_run_negative_controls_and_surgical_symbol_cone(tmp_path: Path) -> None:
    for subcmd in (
        "docker build -t acme/ci:1.0 .",
        "docker pull ghcr.io/acme/ci:1.0",
        "docker inspect acme/ci:1.0",
        "podman ps --all",
        "container login ghcr.io",
    ):
        assert parse_container_run_argv(subcmd.split()) is None

    _put(
        tmp_path,
        "backend/app/factory_entry.py",
        """\
from app.services.hot import serve_hot
from app.services.cold import run_cold


def build_app():
    return serve_hot()


def unused_cli():
    return run_cold()
""",
    )
    _put(tmp_path, "backend/app/services/hot.py", "def serve_hot():\n    return 'hot'\n")
    _put(tmp_path, "backend/app/services/cold.py", "def run_cold():\n    return 'cold'\n")
    _put(
        tmp_path,
        "backend/app/router_hub.py",
        """\
from fastapi import FastAPI
from app.api.items import router

app = FastAPI()
app.include_router(router, prefix="/api")
""",
    )
    _put(
        tmp_path,
        "backend/app/api/items.py",
        "from fastapi import APIRouter\nrouter = APIRouter()\n@router.get('/items')\ndef list_items():\n    return []\n",
    )
    _put(
        tmp_path,
        ".docker/api.Dockerfile",
        "FROM python:3.12-slim\nWORKDIR /app\nCOPY backend/app /app/app\nCMD [\"uvicorn\", \"app.factory_entry:build_app\", \"--factory\"]\n",
    )
    # Non-run CI script must NOT emit launcher nodes, edges, or notes
    _put(
        tmp_path,
        "scripts/ci_build_only.sh",
        """\
#!/usr/bin/env bash
docker login ghcr.io -u ci -p "$CI_TOKEN"
docker pull python:3.12-slim
docker build -t local-api:ci -f .docker/api.Dockerfile .
docker inspect local-api:ci
""",
    )
    # Shell wrapper with build + run + router-hub invocation
    _put(
        tmp_path,
        "scripts/run_stack.sh",
        """\
#!/usr/bin/env bash
docker build -t local-api:dev -f .docker/api.Dockerfile .
docker run --rm -w /app -v "$PWD/backend:/app" local-api:dev \\
  uvicorn app.factory_entry:build_app --factory
docker run --rm -w /app -v "$PWD/backend:/app" local-api:dev \\
  gunicorn app.router_hub:app
""",
    )

    res = _fastapi_extract(tmp_path)
    augment_container_sources(tmp_path, "backend", res)

    nids = {n.id for n in res.nodes}
    assert "m:script:scripts/ci_build_only.sh" not in nids
    assert "m:script:scripts/run_stack.sh" in nids

    fac_node = next(n for n in res.nodes if n.source_file == "backend/app/factory_entry.py")
    hot_node = next(n for n in res.nodes if n.source_file == "backend/app/services/hot.py")
    cold_node = next(n for n in res.nodes if n.source_file == "backend/app/services/cold.py")
    hub_node = next(n for n in res.nodes if n.source_file == "backend/app/router_hub.py")

    fac_edge = next(
        e for e in res.edges if e.source_id == "m:script:scripts/run_stack.sh" and e.target_id == fac_node.id
    )
    assert fac_edge.symbol_links == ["*->build_app"]

    # Router-mounting FastAPI `app = FastAPI()` falls back to `[]` so downstream routes stay reachable
    hub_edge = next(
        e for e in res.edges if e.source_id == "m:script:scripts/run_stack.sh" and e.target_id == hub_node.id
    )
    assert hub_edge.symbol_links == []

    down_edges: dict[str, list[tuple[object, str]]] = {}
    for edge in res.edges:
        down_edges.setdefault(edge.source_id, []).append((edge, edge.target_id))
    ordered, _ = _bfs_cone_direction(
        ["m:dockerfile:.docker/api.Dockerfile"],
        down_edges,  # type: ignore[arg-type]
        nids,
        reverse=False,
    )
    assert fac_node.id in ordered
    assert hot_node.id in ordered
    assert cold_node.id not in ordered


def test_manip_001_policy_env_containment_and_template_exclusions(tmp_path: Path) -> None:
    outside_env = tmp_path.parent / f"{tmp_path.name}_outside_policy.env"
    outside_env.write_text("DUTY_HOUR_LIMIT=99\n", encoding="utf-8")
    try:
        repo = tmp_path / "repo"
        _put(repo, "config/prod.env", "WEEKLY_MAX=60\nPORT=8080\nSHIFT_CAP\n")
        _put(repo, ".env.example", "DUTY_HOUR_LIMIT=80\nCALL_CAP=10\n")
        _put(repo, "config/app.env.sample", "SUPERVISION_RATIO=4\n")
        _put(repo, "config/app.env.template", "CLINIC_MAX=12\n")
        (repo / "config" / "symlink.env").symlink_to(outside_env)

        _put(
            repo,
            "deploy/scheduler.service",
            f"""\
[Service]
Environment="CALL_CAP=6" "ENABLE_DUTY_HOUR_AUDIT=true" "SUPERVISION_RATIO=${{SUPERVISION_RATIO}}"
EnvironmentFile=config/prod.env
EnvironmentFile=.env.example
EnvironmentFile=config/app.env.sample
EnvironmentFile=config/app.env.template
EnvironmentFile=config/symlink.env
EnvironmentFile=../../{outside_env.name}
ExecStart=/usr/bin/docker run --rm \\
  -e DUTY_HOUR_LIMIT=80 \\
  -e SHIFT_CAP \\
  -e WORKLOAD_TARGET="${{WORKLOAD_TARGET}}" \\
  --env-file .env.example \\
  --env-file config/symlink.env \\
  --env-file ../{outside_env.name} \\
  ghcr.io/acme/scheduler:1.0
""",
        )

        res = ManipulatorExtractionResult(nodes=[], edges=[], routes=[])
        augment_container_launchers(repo, ".", res)

        m1 = [f for f in res.findings if f.rule_code == "MANIP-001"]
        flagged = {(f.source_file, f.title) for f in m1}
        assert len(m1) == 3
        assert any(sf == "config/prod.env" and "WEEKLY_MAX" in title for sf, title in flagged)
        assert any(sf == "deploy/scheduler.service" and "CALL_CAP" in title for sf, title in flagged)
        assert any(sf == "deploy/scheduler.service" and "DUTY_HOUR_LIMIT" in title for sf, title in flagged)
        assert not any(".example" in sf or ".sample" in sf or ".template" in sf for sf, _ in flagged)
        assert not any("99" in f.title for f in m1)
        assert res.nodes[0].status == "policy_in_code"
    finally:
        outside_env.unlink(missing_ok=True)


@pytest.mark.parametrize(
    ("kind", "exec_payload", "expect_manip_004"),
    [
        ("systemd", "ExecStart=/usr/bin/docker run --rm -e PORT=$PORT acme/api:1.0", True),
        ("systemd", "ExecStart=/usr/local/bin/container run --mount type=bind,source=~/repo,target=/w,readonly acme/api:1.0", True),
        ("systemd", 'ExecStart=/bin/sh -c "docker run --rm -e PORT=$PORT acme/api:1.0"', False),
        ("systemd", "ExecStart=/usr/bin/docker run --rm -e TAG=$$LITERAL acme/api:1.0", False),
        ("launchd", ["/usr/local/bin/container", "run", "--rm", "$APP_IMAGE"], True),
        ("launchd", ["/usr/local/bin/container", "run", "-v", "~/src:/src:ro", "acme/api:1.0"], True),
        ("launchd", ["/bin/sh", "-lc", "container run --rm $APP_IMAGE"], False),
    ],
)
def test_manip_004_unexpanded_vars_in_non_shell_launchd_and_systemd(
    tmp_path: Path,
    kind: str,
    exec_payload: object,
    expect_manip_004: bool,
) -> None:
    if kind == "systemd":
        _put(tmp_path, "ops/app.service", f"[Service]\n{exec_payload}\n")
    else:
        _put_plist(tmp_path, "launchagents/com.acme.app.plist", {"Label": "com.acme.app", "ProgramArguments": exec_payload})

    res = ManipulatorExtractionResult(nodes=[], edges=[], routes=[])
    augment_container_launchers(tmp_path, ".", res)
    m4 = [f for f in res.findings if f.rule_code == "MANIP-004"]
    assert bool(m4) is expect_manip_004


def test_unresolved_dynamic_image_tags_external_digests_and_micro_vm_docs(tmp_path: Path) -> None:
    _put(tmp_path, "Dockerfile", "FROM python:3.12-slim\nCMD [\"python\", \"-V\"]\n")
    _put(
        tmp_path,
        "scripts/deploy.sh",
        """\
#!/usr/bin/env bash
docker run --rm ghcr.io/acme/api:$IMAGE_TAG
container run --rm gcr.io/distroless/python3-debian12@sha256:0123456789abcdef
podman run --rm postgres:16-alpine
""",
    )

    res = ManipulatorExtractionResult(nodes=[], edges=[], routes=[])
    augment_container_sources(tmp_path, ".", res)

    valid_ids = {n.id for n in res.nodes}
    assert all(e.source_id in valid_ids and e.target_id in valid_ids for e in res.edges)
    assert not any(e.target_id == "m:dockerfile:Dockerfile" for e in res.edges)

    cov_notes = [n for n in res.notes if n.startswith("Container CLI launcher coverage:")]
    assert len(cov_notes) == 1
    note = cov_notes[0]
    assert "unresolved dynamic image reference(s):" in note
    assert "$IMAGE_TAG" in note
    assert "unresolved external/digest-pinned image(s):" in note
    assert "distroless/python3-debian12@sha256:0123456789abcdef" in note
    assert "postgres:16-alpine" in note

    import os
    import subprocess
    import sys

    from app.adapters.dockerfile_sources import parse_dockerfile

    containerfile_parsed = parse_dockerfile(REPO_ROOT / "Containerfile", REPO_ROOT)
    assert containerfile_parsed is not None

    sec_text = " ".join((REPO_ROOT / "SECURITY.md").read_text(encoding="utf-8").split())
    arch_text = " ".join(
        (REPO_ROOT / "docs" / "architecture" / "containers-security-and-plugins.md")
        .read_text(encoding="utf-8")
        .split()
    )
    for doc_txt in (sec_text, arch_text):
        assert "container run --rm --network none" in doc_txt
        assert "target=/workspace/target,readonly" in doc_txt
        assert "wythe scan /workspace/target" in doc_txt
        assert "--read-only --network=none" in doc_txt
        assert "WYTHE_STATE_DIR=/tmp/wythe-state" in doc_txt
        assert "target_code_executed: false" in doc_txt
        assert "automated_security_audit: false" in doc_txt

    # M12 runtime check: read-only HOME (`0o500`) + `WYTHE_DATABASE_URL` (without `WYTHE_STATE_DIR`) succeeds!
    ro_home = tmp_path / "readonly_home"
    ro_home.mkdir(mode=0o500)
    db_path = tmp_path / "scratch.db"
    target_repo = tmp_path / "scan_target"
    _put(target_repo, "pyproject.toml", '[project]\nname = "mini"\ndependencies = ["fastapi"]\n')
    _put(target_repo, "app/main.py", "from fastapi import FastAPI\napp = FastAPI()\n@app.get('/ok')\ndef ok(): return 1\n")
    try:
        env = {
            **os.environ,
            "HOME": str(ro_home),
            "WYTHE_DATABASE_URL": f"sqlite:///{db_path.as_posix()}",
            "PYTHONPATH": str(REPO_ROOT / "backend"),
        }
        env.pop("WYTHE_STATE_DIR", None)
        env.pop("TRUTH_ATLAS_STATE_DIR", None)
        proc = subprocess.run(
            [sys.executable, "-m", "app.cli", "scan", str(target_repo), "--profile", "auto"],
            env=env,
            capture_output=True,
            text=True,
            check=False,
        )
        assert proc.returncode == 0, proc.stderr
    finally:
        os.chmod(ro_home, 0o700)


def test_b3_h3_third_party_images_sole_dockerfile_and_value_flags(tmp_path: Path) -> None:
    # B3(a): Sole root Dockerfile must NOT be linked to unmatched third-party images
    sole = tmp_path / "sole_df"
    _put(sole, "app/main.py", "def create_app():\n    return 1\n")
    _put(
        sole,
        "Dockerfile",
        'FROM python:3.12-slim\nWORKDIR /app\nCOPY app /app/app\nCMD ["uvicorn", "app.main:create_app", "--factory"]\n',
    )
    _put(
        sole,
        "scripts/observability.sh",
        "#!/bin/sh\n"
        "docker run -d --name loki grafana/loki:2.9.0\n"
        "docker run -d --name mongo mongo:7\n"
        "docker run --rm amazon/aws-cli:2.15.0 s3 ls\n",
    )
    res_sole = ManipulatorExtractionResult(nodes=[], edges=[], routes=[])
    augment_container_sources(sole, ".", res_sole)
    assert not any(
        e.source_id == "m:script:scripts/observability.sh" and e.target_id.startswith("m:dockerfile:")
        for e in res_sole.edges
    )
    assert any("0 Dockerfile-linked" in n and "grafana/loki:2.9.0" in n for n in res_sole.notes)

    # B3(b): Launcher filename token (`worker-telemetry.service`) must NOT link OTel collector to `services/worker/Dockerfile`
    tok = tmp_path / "tok_overlap"
    _put(tok, "services/worker/main.py", "def run():\n    return 1\n")
    _put(tok, "services/worker/Dockerfile", 'FROM python:3.12-slim\nWORKDIR /srv\nCOPY main.py /srv/main.py\nCMD ["python", "main.py"]\n')
    _put(
        tok,
        "deploy/worker-telemetry.service",
        "[Service]\nExecStart=/usr/bin/docker run --rm otel/opentelemetry-collector-contrib:0.98.0\n",
    )
    res_tok = ManipulatorExtractionResult(nodes=[], edges=[], routes=[])
    augment_container_sources(tok, ".", res_tok)
    assert not any(
        e.source_id == "m:systemd:deploy/worker-telemetry.service"
        for e in res_tok.edges
    )

    # H3: Value-taking flags (`--sysctl`, `--detach-keys`, `--authfile`, `--cgroups`) & unknown long flags
    inv_sys = parse_container_run_argv(
        ["docker", "run", "-d", "--sysctl", "net.core.somaxconn=1024", "--name", "api", "acme/api:1.0", "uvicorn", "app.main:app"]
    )
    assert inv_sys is not None and inv_sys.image == "acme/api:1.0" and inv_sys.command_argv == ("uvicorn", "app.main:app")

    inv_dk = parse_container_run_argv(["docker", "run", "-it", "--detach-keys", "ctrl-x", "acme/api:1.0", "python", "worker.py"])
    assert inv_dk is not None and inv_dk.image == "acme/api:1.0"

    inv_af = parse_container_run_argv(["podman", "run", "--rm", "--authfile", "/etc/auth.json", "ghcr.io/acme/api:1.0", "python", "worker.py"])
    assert inv_af is not None and inv_af.image == "ghcr.io/acme/api:1.0"

    inv_cg = parse_container_run_argv(["podman", "run", "--rm", "--cgroups", "no-conmon", "ghcr.io/acme/api:1.0", "python", "worker.py"])
    assert inv_cg is not None and inv_cg.image == "ghcr.io/acme/api:1.0"

    inv_unk = parse_container_run_argv(["docker", "run", "--future-unknown-flag", "some-arg", "acme/api:1.0"])
    assert inv_unk is not None and inv_unk.image is None and inv_unk.unresolved_flag == "--future-unknown-flag"


def test_m4_m5_m8_m9_m13_l8_container_launcher_regressions(tmp_path: Path) -> None:
    """Negative controls for M4, M5, M8 (fails under nomount_plugin), M9, M13, and L8."""
    import time

    from app.adapters.compose_sources import augment_container_sources, classify_backing_image
    from app.adapters.container_launchers import (
        MAX_UNIT_FILE_BYTES,
        _extract_run_command_targets,
        _is_external_base_image,
        extract_shell_container_runs,
        parse_launchd_plist,
    )
    from app.adapters.dockerfile_sources import parse_dockerfile

    # M4: Single-line 12,000 `$(...)` placeholders completes in well under 1.0s (linear regex sub)
    t0 = time.perf_counter()
    invs_perf, _, _ = extract_shell_container_runs(
        " ".join(["$(x)"] * 12000) + "\ndocker run --rm acme/api:1.0 python worker.py\n"
    )
    assert time.perf_counter() - t0 < 1.0
    assert len(invs_perf) == 1 and invs_perf[0].image == "acme/api:1.0"

    # M5: Systemd `${VAR}` and whole-word `$VAR` do NOT trigger MANIP-004 and substitute `Environment=`
    sys_repo = tmp_path / "m5_systemd"
    _put(sys_repo, "app/main.py", "def create_app():\n    return 1\n")
    _put(
        sys_repo,
        "Dockerfile",
        'FROM python:3.12-slim\nWORKDIR /app\nCOPY app /app/app\nCMD ["uvicorn", "app.main:create_app", "--factory"]\n',
    )
    _put(sys_repo, "scripts/build.sh", "#!/bin/sh\ndocker build -t ghcr.io/acme/api:1.0 .\n")
    _put(
        sys_repo,
        "deploy/ok.service",
        "[Service]\nEnvironment=IMAGE=ghcr.io/acme/api:1.0\nEnvironment=PORT=8080\n"
        "ExecStart=/usr/bin/docker run --rm -p ${PORT}:8080 $IMAGE\n",
    )
    _put(
        sys_repo,
        "deploy/bad.service",
        "[Service]\nExecStart=/usr/bin/docker run --rm -p$PORT:8080 ghcr.io/acme/api:1.0\n",
    )
    res_sys = ManipulatorExtractionResult(nodes=[], edges=[], routes=[])
    augment_container_sources(sys_repo, ".", res_sys)
    m4_files = [f.source_file for f in res_sys.findings if f.rule_code == "MANIP-004"]
    assert m4_files == ["deploy/bad.service"]
    assert any(
        e.source_id == "m:systemd:deploy/ok.service" and e.target_id == "m:dockerfile:Dockerfile"
        for e in res_sys.edges
    )

    # M8: `$PWD` bind mount resolves without any static vars (and distinguishes mounted dir from root `main.py`)
    pwd_repo = tmp_path / "m8_pwd"
    _put(pwd_repo, "main.py", "def root_cli():\n    return 0\n")
    _put(pwd_repo, "services/worker/main.py", "def worker_loop():\n    return 1\n")
    _put(
        pwd_repo,
        "run_worker.sh",
        '#!/bin/sh\ndocker run --rm -v "$PWD/services/worker:/srv" -w /srv python:3.12-slim python main.py\n',
    )
    res_pwd = ManipulatorExtractionResult(nodes=[], edges=[], routes=[])
    augment_container_sources(pwd_repo, ".", res_pwd)
    pwd_targets = {e.target_id for e in res_pwd.edges if e.source_id == "m:script:run_worker.sh"}
    assert pwd_targets == {"m:script:services/worker/main.py"}

    # M9: Merging whole-module (`[]`) and symbol-specific (`*->create_app`) runs keeps whole-module (`[]`) in both orders
    for order in ("whole_first", "symbol_first"):
        m9_repo = tmp_path / f"m9_{order}"
        _put(m9_repo, "backend/app/__init__.py", "")
        _put(m9_repo, "backend/app/main.py", "def create_app():\n    return 1\n\ndef main():\n    return 2\n")
        whole = "docker run --rm -v ./backend:/app -w /app python:3.12-slim python -m app.main\n"
        sym = "docker run --rm -v ./backend:/app -w /app python:3.12-slim uvicorn app.main:create_app --factory\n"
        _put(m9_repo, "scripts/ops.sh", whole + sym if order == "whole_first" else sym + whole)
        res_m9 = ManipulatorExtractionResult(nodes=[], edges=[], routes=[])
        augment_container_sources(m9_repo, ".", res_m9)
        ops_edges = [e for e in res_m9.edges if e.source_id == "m:script:scripts/ops.sh"]
        assert len(ops_edges) == 1 and ops_edges[0].symbol_links == []

    # M13: Shell assignment `$(...)`, `if`/`then`/`!`, `$DOCKER` var CLI, `#` mid-word, and unparsed CLI note
    shell_src = (
        "CID=$(docker run -d --name api acme/api:1.0 uvicorn app.main:app)\n"
        'if [ -n "$X" ]; then docker run --rm acme/api:1.0 python worker.py; fi\n'
        "if docker run --rm acme/api:1.0 python check.py; then echo ok; fi\n"
        "! docker run --rm acme/api:1.0 python neg.py\n"
        "DOCKER=docker\n"
        "$DOCKER run --rm -e TAG=${VERSION#v} acme/api:1.0 python tagged.py\n"
    )
    invs_m13, _, _ = extract_shell_container_runs(shell_src)
    assert [i.command_argv[-1] for i in invs_m13] == [
        "app.main:app",
        "worker.py",
        "check.py",
        "neg.py",
        "tagged.py",
    ]

    unparsed_repo = tmp_path / "m13_unparsed"
    _put(unparsed_repo, "scripts/dyn.sh", "#!/bin/sh\n$UNKNOWN_DOCKER_BIN run --rm acme/api:1.0\n")
    res_unp = ManipulatorExtractionResult(nodes=[], edges=[], routes=[])
    augment_container_sources(unparsed_repo, ".", res_unp)
    assert any("scripts/dyn.sh:2" in n for n in res_unp.notes)

    # L8: Launchd env line numbers, `--entrypoint ""` reset, `acme/python-worker` non-external, oversized file note
    l8_repo = tmp_path / "l8_misc"
    _put(
        l8_repo,
        "LaunchAgents/com.acme.agent.plist",
        '<?xml version="1.0" encoding="UTF-8"?>\n<plist version="1.0">\n<dict>\n'
        "  <key>Label</key><string>com.acme.agent</string>\n"
        "  <key>ProgramArguments</key><array><string>/usr/bin/true</string></array>\n"
        "  <key>EnvironmentVariables</key>\n  <dict>\n    <key>WEEKLY_MAX</key>\n    <string>80</string>\n  </dict>\n"
        "</dict>\n</plist>\n",
    )
    _put(l8_repo, "scripts/huge.sh", "#" + ("x" * (MAX_UNIT_FILE_BYTES + 10)))
    punit, _ = parse_launchd_plist(l8_repo / "LaunchAgents/com.acme.agent.plist", l8_repo)
    assert punit is not None and punit.environment[0].line == 9

    res_l8 = ManipulatorExtractionResult(nodes=[], edges=[], routes=[])
    augment_container_sources(l8_repo, ".", res_l8)
    assert any("Skipped shell script scripts/huge.sh" in n for n in res_l8.notes)

    _put(
        l8_repo,
        "Dockerfile",
        'FROM python:3.12-slim\nWORKDIR /app\nCOPY . /app\nENTRYPOINT ["python", "old_ep.py"]\n',
    )
    pdf = parse_dockerfile(l8_repo / "Dockerfile", l8_repo)
    assert pdf is not None
    inv_ep_clear = parse_container_run_argv(
        ["docker", "run", "--entrypoint", "", "acme/python-worker:1.0", "python", "new_worker.py"]
    )
    assert inv_ep_clear is not None and inv_ep_clear.entrypoint == ""
    ep_targets = _extract_run_command_targets(inv_ep_clear, pdf.select_stage())
    assert [t.value for t in ep_targets] == ["new_worker.py"]
    assert _is_external_base_image("acme/python-worker:1.0", classify_backing_image) is False
    assert _is_external_base_image("python:3.12-slim", classify_backing_image) is True
