"""Regression tests for Wave 2 external review remediation (Findings 1 & 6)."""

from __future__ import annotations

import json
import os
import socket
import subprocess
import sys
import threading
import time
import urllib.request
from pathlib import Path

import pytest

from app.adapters.plugin_registry import ENTRY_POINT_GROUP
from app.schemas.atlas import (
    MicroStratumZoom,
    StratumExpansionResult,
    StratumMicroEdge,
    StratumMicroNode,
    TargetProjectCreate,
    TruthAtlasReport,
    ViewportCommand,
)
from app.services.governance_service import get_target_by_slug, register_target
from app.services.scanner_service import run_target_scan
from app.services.stratum_service import (
    build_node_stratum_drilldown,
    compact_stratum_subgraph,
)
from app.services.viewport_service import (
    clear_viewport_state,
    get_viewport_state,
    publish_viewport_command,
    viewport_delivery_scope,
)

REPO_ROOT = Path(__file__).resolve().parents[2]


def _free_loopback_port() -> int:
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
        sock.bind(("127.0.0.1", 0))
        return int(sock.getsockname()[1])


def _make_target_repo(repo_dir: Path) -> Path:
    (repo_dir / "backend" / "app").mkdir(parents=True)
    (repo_dir / "backend" / "schema.sql").write_text(
        "CREATE TABLE limits (id INTEGER PRIMARY KEY, lo INTEGER, hi INTEGER);\n",
        encoding="utf-8",
    )
    (repo_dir / "backend" / "app" / "solver.py").write_text(
        "def solve_model(db):\n"
        '    return db.execute("SELECT id, lo, hi FROM limits")\n',
        encoding="utf-8",
    )
    return repo_dir


def test_cross_process_cli_mcp_sqlite_bus_live_sse_and_server_url_fail_closed(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Verify cross-process SQLite IPC bus, live /viewport/stream SSE, --server-url HTTP delivery, and closed-port fail-closed."""
    state_a = tmp_path / "state-a"
    state_b = tmp_path / "state-b"
    state_a.mkdir()
    state_b.mkdir()
    repo_dir = _make_target_repo(tmp_path / "ipc-target")

    env_a = {
        **os.environ,
        "PYTHONPATH": str(REPO_ROOT / "backend"),
        "WYTHE_STATE_DIR": str(state_a),
        "WYTHE_DATABASE_URL": f"sqlite:///{(state_a / 'wythe.db').as_posix()}",
    }
    env_a.pop("WYTHE_SERVER_URL", None)

    port = _free_loopback_port()
    base_url = f"http://127.0.0.1:{port}"
    server = subprocess.Popen(
        [
            sys.executable,
            "-m",
            "uvicorn",
            "app.main:app",
            "--host",
            "127.0.0.1",
            "--port",
            str(port),
            "--log-level",
            "error",
        ],
        env=env_a,
        stdout=subprocess.DEVNULL,
        stderr=subprocess.PIPE,
    )
    sse_events: list[dict[str, object]] = []
    sse_connected = threading.Event()
    sse_two_received = threading.Event()

    no_proxy_opener = urllib.request.build_opener(urllib.request.ProxyHandler({}))

    def _read_live_sse() -> None:
        url = f"{base_url}/api/v1/viewport/stream?target_slug=ipc-target"
        with no_proxy_opener.open(url, timeout=10.0) as resp:
            cur_id: int | None = None
            cur_data: str | None = None
            while True:
                raw_line = resp.readline()
                if not raw_line:
                    break
                line = raw_line.decode("utf-8", errors="replace").rstrip("\r\n")
                if line.startswith(": viewport-bus connected"):
                    sse_connected.set()
                elif line.startswith("id: "):
                    cur_id = int(line.removeprefix("id: ").strip())
                elif line.startswith("data: "):
                    cur_data = line.removeprefix("data: ").strip()
                elif line == "" and cur_data is not None:
                    sse_events.append({"id": cur_id, "data": json.loads(cur_data)})
                    cur_id = None
                    cur_data = None
                    if len(sse_events) >= 2:
                        sse_two_received.set()
                        break

    sse_thread: threading.Thread | None = None
    try:
        for _ in range(100):
            try:
                no_proxy_opener.open(f"{base_url}/healthz", timeout=1.0).close()
                break
            except OSError:
                time.sleep(0.05)
        else:
            pytest.fail("Uvicorn test server did not become healthy in time")

        sse_thread = threading.Thread(target=_read_live_sse, daemon=True)
        sse_thread.start()
        assert sse_connected.wait(timeout=5.0), "Live SSE /viewport/stream did not connect"

        # 1. Separate `app.cli mcp` process via shared SQLite IPC bus (`state_a`, no `--server-url`)
        msg_1 = {
            "jsonrpc": "2.0",
            "id": 1,
            "method": "tools/call",
            "params": {
                "name": "wythe_focus_camera",
                "arguments": {
                    "target": str(repo_dir),
                    "profile": "python-services",
                    "caption": "sqlite ipc beat",
                },
            },
        }
        proc_1 = subprocess.run(
            [sys.executable, "-m", "app.cli", "mcp"],
            input=json.dumps(msg_1) + "\n",
            env=env_a,
            text=True,
            capture_output=True,
            timeout=30.0,
            check=False,
        )
        assert proc_1.returncode == 0, proc_1.stderr
        rpc_1 = json.loads(proc_1.stdout)
        assert rpc_1["result"]["isError"] is False

        with no_proxy_opener.open(
            f"{base_url}/api/v1/viewport/state?target_slug=ipc-target", timeout=5.0
        ) as st_resp:
            st_1 = json.loads(st_resp.read().decode("utf-8"))
        assert st_1["latest"] is not None
        assert st_1["latest"]["seq"] == 1
        assert st_1["latest"]["command"]["caption"] == "sqlite ipc beat"

        # 2. Separate `app.cli mcp --server-url` process with DIFFERENT `WYTHE_STATE_DIR` (`state_b`)
        env_b = {
            **env_a,
            "WYTHE_STATE_DIR": str(state_b),
            "WYTHE_DATABASE_URL": f"sqlite:///{(state_b / 'wythe.db').as_posix()}",
        }
        msg_2 = {
            "jsonrpc": "2.0",
            "id": 2,
            "method": "tools/call",
            "params": {
                "name": "wythe_focus_camera",
                "arguments": {
                    "target": str(repo_dir),
                    "profile": "python-services",
                    "caption": "http server-url beat",
                },
            },
        }
        proc_2 = subprocess.run(
            [sys.executable, "-m", "app.cli", "mcp", "--server-url", base_url],
            input=json.dumps(msg_2) + "\n",
            env=env_b,
            text=True,
            capture_output=True,
            timeout=30.0,
            check=False,
        )
        assert proc_2.returncode == 0, proc_2.stderr
        rpc_2 = json.loads(proc_2.stdout)
        assert rpc_2["result"]["isError"] is False
        assert "seq=2" in rpc_2["result"]["content"][0]["text"]

        assert sse_two_received.wait(timeout=5.0), f"Live SSE stream only received: {sse_events}"
        assert [ev["id"] for ev in sse_events] == [1, 2]
        assert [ev["data"]["command"]["caption"] for ev in sse_events] == [  # type: ignore[index]
            "sqlite ipc beat",
            "http server-url beat",
        ]
    finally:
        server.terminate()
        server.wait(timeout=10.0)
        if sse_thread is not None:
            sse_thread.join(timeout=2.0)

    # 3. Server is now stopped (`port` closed): `--server-url` MUST fail closed!
    closed_port = _free_loopback_port()
    proc_closed = subprocess.run(
        [
            sys.executable,
            "-m",
            "app.cli",
            "mcp",
            "--server-url",
            f"http://127.0.0.1:{closed_port}",
        ],
        input=json.dumps(msg_2) + "\n",
        env=env_b,
        text=True,
        capture_output=True,
        timeout=15.0,
        check=False,
    )
    rpc_closed = json.loads(proc_closed.stdout)
    assert rpc_closed["result"]["isError"] is True
    assert "unreachable" in rpc_closed["result"]["content"][0]["text"].lower()

    # Remote non-private host rejected unless `allow_remote=True`, and link-local always rejected
    monkeypatch.setenv("WYTHE_STATE_DIR", str(state_b))
    with pytest.raises(ValueError, match="not loopback or private"):
        publish_viewport_command(
            ViewportCommand(target_slug="ipc-target", caption="remote blocked"),
            server_url="https://93.184.216.34:8780",
        )
    with pytest.raises(ValueError, match="link-local"):
        publish_viewport_command(
            ViewportCommand(target_slug="ipc-target", caption="metadata blocked"),
            server_url="http://169.254.169.254:80",
            allow_remote=True,
        )

    # Verify `clear_viewport_state` and dynamic `WYTHE_STATE_DIR` switching
    monkeypatch.setenv("WYTHE_STATE_DIR", str(state_a))
    assert get_viewport_state("ipc-target").latest is not None
    clear_viewport_state("ipc-target")
    assert get_viewport_state("ipc-target").latest is None

    # Verify `viewport_delivery_scope` enforces `server_url` and `local_only` for zero-kwarg callers
    with (
        viewport_delivery_scope(server_url=f"http://127.0.0.1:{closed_port}"),
        pytest.raises(RuntimeError, match="unreachable"),
    ):
        publish_viewport_command(ViewportCommand(target_slug="ipc-target", caption="scoped fail"))

    monkeypatch.setenv("WYTHE_SERVER_URL", f"http://127.0.0.1:{closed_port}")
    with viewport_delivery_scope(local_only=True):
        ack_local = publish_viewport_command(
            ViewportCommand(target_slug="ipc-target", caption="local override")
        )
        assert ack_local.seq >= 1
    monkeypatch.delenv("WYTHE_SERVER_URL", raising=False)


def test_iterative_stratum_compaction_deep_chains_and_cycles_via_drilldown(
    isolated_db_url: str,
    db_session,
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Verify 1,500-node and 5,000-node deep thunk chains + cyclic thunks succeed with zero RecursionError."""
    assert isolated_db_url.startswith("sqlite:")

    for depth in (1500, 5000):
        chain_nodes = [
            StratumMicroNode(
                id=f"n{i}",
                label=f"swift_retain_{i}",
                kind="symbol",
                zoom=2,
                verification="verified",
            )
            for i in range(depth)
        ]
        chain_edges = [
            StratumMicroEdge(
                id=f"e{i}",
                source_id=f"n{i - 1}" if i else "parent",
                target_id=f"n{i}",
                kind="calls",
                verification="verified",
            )
            for i in range(depth)
        ]
        s_nodes, s_edges, raw_n, comp_n, fold_n = compact_stratum_subgraph(
            "parent", chain_nodes, chain_edges
        )
        assert (raw_n, comp_n, fold_n) == (depth, 0, depth)
        assert s_nodes == []
        assert len(s_edges) == 1
        assert s_edges[0].collapsed_count == depth

    class _DeepCyclicStratumPlugin:
        name = "deep-cyclic-ir"
        version = "1.0.0"
        description = "1500-node chain + cyclic witness SCC plugin"
        supported_zooms = (2,)

        def summarize_zoom1_badges(self, repo_root: Path, report: TruthAtlasReport):
            _ = (repo_root, report)
            return {}

        def expand_node_stratum(
            self,
            repo_root: Path,
            report: TruthAtlasReport,
            node_id: str,
            zoom: MicroStratumZoom,
        ) -> StratumExpansionResult:
            _ = (repo_root, report, zoom)
            nodes = [
                StratumMicroNode(
                    id="ir:callee",
                    label="domain_callee",
                    kind="sil_fn",
                    zoom=2,
                    verification="verified",
                ),
                *[
                    StratumMicroNode(
                        id=f"ir:chain:{i}",
                        label=f"thunk for step_{i}",
                        kind="thunk",
                        zoom=2,
                        verification="verified",
                    )
                    for i in range(1500)
                ],
                StratumMicroNode(
                    id="ir:cyc1",
                    label="protocol witness for CycA",
                    kind="witness",
                    zoom=2,
                    verification="verified",
                ),
                StratumMicroNode(
                    id="ir:cyc2",
                    label="reabstraction thunk CycB",
                    kind="thunk",
                    zoom=2,
                    verification="verified",
                ),
            ]
            edges = [
                *[
                    StratumMicroEdge(
                        id=f"e:c:{i}",
                        source_id=node_id if i == 0 else f"ir:chain:{i - 1}",
                        target_id=f"ir:chain:{i}",
                        kind="calls_ir",
                        verification="verified",
                    )
                    for i in range(1500)
                ],
                StratumMicroEdge(
                    id="e:c:end",
                    source_id="ir:chain:1499",
                    target_id="ir:cyc1",
                    kind="calls_ir",
                    verification="verified",
                ),
                StratumMicroEdge(
                    id="e:cyc:12",
                    source_id="ir:cyc1",
                    target_id="ir:cyc2",
                    kind="calls_ir",
                    verification="declared",
                ),
                StratumMicroEdge(
                    id="e:cyc:21",
                    source_id="ir:cyc2",
                    target_id="ir:cyc1",
                    kind="calls_ir",
                    verification="verified",
                ),
                StratumMicroEdge(
                    id="e:cyc:out",
                    source_id="ir:cyc2",
                    target_id="ir:callee",
                    kind="calls_ir",
                    verification="verified",
                ),
            ]
            return StratumExpansionResult(nodes=nodes, edges=edges)

    class _EP:
        name = "deep-cyclic-ir"
        value = "pkg:deep"
        group = ENTRY_POINT_GROUP

        class dist:
            version = "1.0.0"

        def load(self):
            return _DeepCyclicStratumPlugin()

    repo_dir = _make_target_repo(tmp_path / "drill-repo")
    register_target(
        db_session,
        TargetProjectCreate(
            slug="drill-repo",
            name="Drill Repo",
            repo_path=str(repo_dir),
            stack_profile_slug="python-services",
            backend_subdir="backend",
        ),
    )
    target = get_target_by_slug(db_session, "drill-repo")
    assert target is not None
    monkeypatch.setattr("importlib.metadata.entry_points", lambda *, group: [_EP()])
    report = run_target_scan(db_session, target, strict_gate=True, persist_snapshot=False)
    svc_node = next(n for n in report.nodes if "solver.py" in (n.source_file or ""))

    drill = build_node_stratum_drilldown(repo_dir, report, svc_node.id, zoom=2)
    assert drill.raw_node_count == 1503
    assert drill.compacted_node_count == 1
    assert drill.collapsed_thunk_count == 1502
    bridged = next(e for e in drill.edges if e.id.startswith("s:bridged:"))
    assert bridged.target_id == "ir:callee"
    assert bridged.collapsed_count == 1502
    assert bridged.verification == "declared"
