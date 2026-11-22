"""Regression tests for Wave 0.2.9 (#96 UI + #101 Items 1-3): vanilla ES UIs, mount prefixes, EventSource, method param scoping, and a11y."""

from __future__ import annotations

from pathlib import Path

import pytest

from app.adapters import typescript_nextjs
from app.adapters.frontend_common import scan_a11y_markup_findings
from app.adapters.python_services import PythonServicesAdapter
from app.adapters.sql_ddl_truth import SqlDdlTruthAdapter
from app.adapters.typescript_nextjs import TypeScriptNextJsAdapter, _normalize_ts_url
from app.adapters.typescript_react import TypeScriptReactSpaAdapter
from app.models import TargetProject
from app.services.scanner_service import run_target_scan


def _write(root: Path, rel: str, text: str) -> Path:
    p = root / rel
    p.parent.mkdir(parents=True, exist_ok=True)
    p.write_text(text, encoding="utf-8")
    return p


@pytest.mark.parametrize("disable_ts", [False, True])
def test_vanilla_es_module_discovery_client_stems_and_html_reachability(
    tmp_path: Path,
    db_session,
    monkeypatch: pytest.MonkeyPatch,
    disable_ts: bool,
) -> None:
    if disable_ts:
        monkeypatch.setenv("WYTHE_DISABLE_TREESITTER", "1")
        monkeypatch.setattr(typescript_nextjs, "extract_ts_http_calls_cst", lambda *a, **kw: None)
    else:
        monkeypatch.delenv("WYTHE_DISABLE_TREESITTER", raising=False)

    # Include a Python src/ directory alongside a root-level vanilla ES UI so src/ does not mask UI root.
    _write(
        tmp_path,
        "src/ops_daemon/server.py",
        "from http.server import BaseHTTPRequestHandler\n"
        "class OpsHandler(BaseHTTPRequestHandler):\n"
        "    def do_GET(self):\n"
        "        if self.path == '/api/v1/runs':\n"
        "            return 200\n"
        "        if self.path == '/api/v1/events':\n"
        "            return 200\n",
    )
    _write(
        tmp_path,
        "ops_portal/index.html",
        "<!doctype html>\n<html><body>\n"
        "<div id='root'></div>\n"
        "<script type='module' src='./app.js'></script>\n"
        "</body></html>\n",
    )
    _write(
        tmp_path,
        "ops_portal/app.js",
        "import { renderRuns } from './views/runs.js';\n"
        "import { openEvents } from './utils/sse_stream.js';\n"
        "export function boot() {\n"
        "  renderRuns();\n"
        "  openEvents();\n"
        "}\n"
        "boot();\n",
    )
    _write(
        tmp_path,
        "ops_portal/router.js",
        "export const routes = ['/runs'];\n",
    )
    _write(
        tmp_path,
        "ops_portal/views/runs.js",
        "import { fetchRuns } from '../core/live-client.js';\n"
        "export async function renderRuns() {\n"
        "  return fetchRuns();\n"
        "}\n",
    )
    _write(
        tmp_path,
        "ops_portal/views/Orders-Client.js",
        "export const loadOrders = () => fetch('/api/v1/runs');\n",
    )
    _write(
        tmp_path,
        "ops_portal/core/live-client.js",
        "export class LiveClient {\n"
        "  apiPrefix = '';\n"
        "  async list() {\n"
        "    return fetch(`${this.apiPrefix}/api/v1/runs`);\n"
        "  }\n"
        "}\n"
        "export async function fetchRuns() {\n"
        "  return new LiveClient().list();\n"
        "}\n",
    )
    _write(
        tmp_path,
        "ops_portal/core/unused_client.js",
        "export async function staleCall() {\n"
        "  return fetch('/api/v1/missing-orphan');\n"
        "}\n",
    )
    _write(
        tmp_path,
        "ops_portal/utils/sse_stream.js",
        "export function openEvents() {\n"
        "  return new EventSource('/api/v1/events');\n"
        "}\n",
    )
    _write(
        tmp_path,
        "ops_portal/shared/ws-transport.js",
        "export const pingTransport = () => fetch('/api/v1/runs');\n",
    )
    _write(
        tmp_path,
        "ops_portal/lib/user-client.js",
        "export const fetchProfile = () => fetch('/api/v1/runs');\n",
    )
    _write(
        tmp_path,
        "ops_portal/core/ops_service.js",
        "export const serviceInfo = () => fetch('/api/v1/runs');\n",
    )

    disp = TypeScriptReactSpaAdapter().extract(tmp_path, "ops_portal")
    nodes_by_src = {n.source_file: n for n in disp.nodes}
    assert nodes_by_src["ops_portal/app.js"].subkind == "page"
    assert nodes_by_src["ops_portal/router.js"].subkind == "page"
    assert nodes_by_src["ops_portal/views/runs.js"].subkind == "page"
    for client_rel in (
        "ops_portal/views/Orders-Client.js",
        "ops_portal/core/live-client.js",
        "ops_portal/core/unused_client.js",
        "ops_portal/utils/sse_stream.js",
        "ops_portal/shared/ws-transport.js",
        "ops_portal/lib/user-client.js",
        "ops_portal/core/ops_service.js",
    ):
        assert nodes_by_src[client_rel].subkind == "api_client", (client_rel, nodes_by_src[client_rel])

    edge_pairs = {(e.source_id, e.target_id) for e in disp.edges}
    assert (nodes_by_src["ops_portal/index.html"].id, nodes_by_src["ops_portal/app.js"].id) in edge_pairs
    assert (nodes_by_src["ops_portal/app.js"].id, nodes_by_src["ops_portal/views/runs.js"].id) in edge_pairs
    assert (nodes_by_src["ops_portal/views/runs.js"].id, nodes_by_src["ops_portal/core/live-client.js"].id) in edge_pairs

    calls_by_file = {c.source_file: c for c in disp.http_calls}
    assert calls_by_file["ops_portal/core/live-client.js"].reachable is True
    assert calls_by_file["ops_portal/core/live-client.js"].entry_node_ids
    assert calls_by_file["ops_portal/utils/sse_stream.js"].reachable is True
    assert calls_by_file["ops_portal/core/unused_client.js"].reachable is False

    # End-to-end scan confirms live calls are verified and unimported call stays DISP-007 (never live/DISP-004).
    target = TargetProject(
        id=0,
        slug="ops-portal-test",
        name="Ops Portal",
        repo_path=str(tmp_path),
        stack_profile_slug="python-services-react",
        backend_subdir=".",
        frontend_subdir="ops_portal",
        is_active=True,
    )
    report = run_target_scan(db_session, target, strict_gate=True, persist_snapshot=False)
    disp_007 = [f for f in report.findings if f.rule_code == "DISP-007"]
    disp_004 = [f for f in report.findings if f.rule_code == "DISP-004"]
    assert {f.source_file for f in disp_007} == {"ops_portal/core/unused_client.js"}
    assert disp_004 == []
    # Also ensure root Python src/ never breaks root vanilla discovery.
    root_ui = tmp_path / "root_ui_case"
    _write(root_ui, "src/backend_pkg/mod.py", "def ok():\n    return 1\n")
    _write(root_ui, "index.html", "<!doctype html><html><body><script type='module' src='index.js'></script></body></html>\n")
    _write(root_ui, "index.js", "import { ping } from './core/ping-client.js';\nping();\n")
    _write(root_ui, "core/ping-client.js", "export const ping = () => fetch('/api/v1/runs');\n")
    root_disp = TypeScriptReactSpaAdapter().extract(root_ui, ".")
    root_by_src = {n.source_file: n for n in root_disp.nodes}
    assert root_by_src["index.html"].id != root_by_src["index.js"].id
    assert next(c for c in root_disp.http_calls if c.source_file == "core/ping-client.js").reachable is True
    assert SqlDdlTruthAdapter is not None and PythonServicesAdapter is not None


@pytest.mark.parametrize("disable_ts", [False, True])
def test_mount_prefix_normalization_html_base_eventsource_and_method_param_scoping(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    disable_ts: bool,
) -> None:
    if disable_ts:
        monkeypatch.setenv("WYTHE_DISABLE_TREESITTER", "1")
        monkeypatch.setattr(typescript_nextjs, "extract_ts_http_calls_cst", lambda *a, **kw: None)
    else:
        monkeypatch.delenv("WYTHE_DISABLE_TREESITTER", raising=False)

    assert _normalize_ts_url("${this.apiPrefix}/api/v1/slices/${sliceId}") == "/api/v1/slices/{param}"
    assert _normalize_ts_url('${this.apiPrefix || ""}/api/v1/slices/${sliceId}') == "/api/v1/slices/{param}"
    assert _normalize_ts_url('${window.__BASE_PATH__ ?? ""}/api/v1/runs') == "/api/v1/runs"
    assert _normalize_ts_url("/ops/api/v1/slices/${id}", mount_prefixes=("/ops",)) == "/api/v1/slices/{param}"

    _write(
        tmp_path,
        "ui/index.html",
        "<!doctype html>\n<html><head>\n"
        "<base href='/ops/'>\n"
        "<meta name='api-base' content='/ops'>\n"
        "</head><body>\n"
        "<script type='module' src='./core/live-client.js'></script>\n"
        "</body></html>\n",
    )
    _write(
        tmp_path,
        "ui/core/live-client.js",
        "const RUNTIME_BASE = window.__BASE_PATH__ ?? '';\n"
        "export class LiveClient {\n"
        "  apiPrefix = '';\n"
        "  async loadSlice(sliceId) {\n"
        "    await fetch(`${this.apiPrefix}/api/v1/slices/${sliceId}`);\n"
        "    return fetch(`${this.apiPrefix || \"\"}/api/v1/slices/${sliceId}/meta`, { method: 'POST' });\n"
        "  }\n"
        "  watchSlice(sliceId) {\n"
        "    const streamUrl = `${this.apiPrefix || \"\"}/api/v1/slices/${sliceId}/events`;\n"
        "    const directEs = new window.EventSource(`${window.__BASE_PATH__ ?? \"\"}/api/v1/stream`);\n"
        "    const plainEs = new EventSource(streamUrl);\n"
        "    return [directEs, plainEs];\n"
        "  }\n"
        "  async listMounted() {\n"
        "    await fetch(`${RUNTIME_BASE}/api/v1/mounted`);\n"
        "    await fetch('/ops/api/v1/static-prefixed');\n"
        "    return fetch('api/v1/rel-health');\n"
        "  }\n"
        "  async probeModels(params: { probe: { baseUrl: string } }): Promise<{ ok: boolean }> {\n"
        "    const res = await fetch(`${params.probe.baseUrl}/models`);\n"
        "    return { ok: res.ok };\n"
        "  }\n"
        "  async probeChat(base: string): Promise<Response> {\n"
        "    const url = `${base}/chat/completions`;\n"
        "    return fetch(url, { method: 'POST' });\n"
        "  }\n"
        "}\n"
        "export const probeHelper = {\n"
        "  async ask(base) {\n"
        "    return new EventSource(`${base}/events-should-stay-blocked`);\n"
        "  },\n"
        "};\n"
        "export async function probeLoop(endpoints: string[]) {\n"
        "  for (const base of endpoints) {\n"
        "    await fetch(`${base}/models`);\n"
        "  }\n"
        "}\n",
    )

    disp = TypeScriptReactSpaAdapter().extract(tmp_path, "ui")
    calls = {(c.http_method, c.normalized_path) for c in disp.http_calls}
    assert ("GET", "/api/v1/slices/{param}") in calls
    assert ("POST", "/api/v1/slices/{param}/meta") in calls
    assert ("GET", "/api/v1/stream") in calls
    assert ("GET", "/api/v1/slices/{param}/events") in calls
    assert ("GET", "/api/v1/mounted") in calls
    assert ("GET", "/api/v1/static-prefixed") in calls
    assert ("GET", "/api/v1/rel-health") in calls
    assert not any(
        "models" in p or "completions" in p or "should-stay-blocked" in p
        for _m, p in calls
    ), calls

    # Also confirm Next.js adapter shares identical mount-prefix, EventSource, and method scoping behavior.
    next_dir = tmp_path / "next_case"
    _write(
        next_dir,
        "src/lib/stream-client.ts",
        "export class StreamClient {\n"
        "  apiPrefix = '';\n"
        "  watch(id: string) {\n"
        "    const url = `${this.apiPrefix || ''}/api/v1/jobs/${id}/events`;\n"
        "    return new window.EventSource(url);\n"
        "  }\n"
        "  async externalProbe(params: { probe: { baseUrl: string } }): Promise<void> {\n"
        "    await fetch(`${params.probe.baseUrl}/models`);\n"
        "  }\n"
        "}\n",
    )
    _write(
        next_dir,
        "src/app/page.tsx",
        "import { StreamClient } from '@/lib/stream-client';\n"
        "export default function Page() { void new StreamClient().watch('1'); return <main>Ok</main>; }\n",
    )
    next_disp = TypeScriptNextJsAdapter().extract(next_dir, ".")
    next_calls = {(c.http_method, c.normalized_path) for c in next_disp.http_calls}
    assert ("GET", "/api/v1/jobs/{param}/events") in next_calls
    assert not any("models" in p for _m, p in next_calls)


def test_a11y_disp005_html_comment_script_style_blanking_and_js_literal_only() -> None:
    html_src = (
        "<!doctype html>\n"
        "<html>\n"
        "<head>\n"
        "  <style>\n"
        "    /* <img src='/in-style.png'> */\n"
        "  </style>\n"
        "</head>\n"
        "<body>\n"
        "  <!-- <img src='/commented.png'> <input type='text'> -->\n"
        "  <img src='/bad-banner.png'>\n"
        "  <input type='text' placeholder='Filter'>\n"
        "  <script type='module'>\n"
        "    const ok = a < img && b > 0;\n"
        "    const p: Promise<HTMLInputElement> = null;\n"
        "  </script>\n"
        "</body>\n"
        "</html>\n"
    )
    html_hits = scan_a11y_markup_findings(html_src, "d:page:index", "ui/index.html")
    assert [(f.line, f.title.split("`")[1]) for f in html_hits] == [
        (10, "<img>"),
        (11, "<input>"),
    ]

    js_src = (
        "// <img src='/line-comment.png'>\n"
        "/* <button><svg></svg></button> */\n"
        "export function checkComparisons(a: number, div: number, b: number): Promise<HTMLInputElement> | null {\n"
        "  const ok = a < div && b > 0;\n"
        "  const cmp = a < img && b > 0;\n"
        "  const fn = (x: Ref<div>) => x;\n"
        "  const rx = /<img[^>]*>/;\n"
        "  const fakeStr = 'Promise<input> and x<img && y>0';\n"
        "  const goodBtn = `<button><svg></svg>${ok}</button>`;\n"
        "  const badTpl = `\n"
        "    <div onclick='openItem()'>Row</div>\n"
        "    <button type='button'><svg></svg></button>\n"
        "  `;\n"
        "  return null;\n"
        "}\n"
    )
    js_hits = scan_a11y_markup_findings(js_src, "d:page:views.runs", "ui/views/runs.ts")
    assert [(f.line, f.title.split("`")[1]) for f in js_hits] == [
        (11, "<div>"),
        (12, "<button>"),
    ]
