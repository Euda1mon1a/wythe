"""Source-only regressions exposed by a pinned Open WebUI audit."""

from __future__ import annotations

import os
import subprocess
import sys
import time
from pathlib import Path

import pytest

from app.adapters.a11y_inspect import scan_a11y_markup_findings
from app.adapters.base import TruthExtractionResult
from app.adapters.postgres_sqlalchemy import PostgresSqlAlchemyAdapter
from app.adapters.python_fastapi import PythonFastApiAdapter
from app.adapters.sveltekit_display import SvelteKitDisplayAdapter
from app.adapters.typescript_nextjs import _IMPORT_RE


def put(root: Path, rel: str, source: str) -> Path:
    path = root / rel
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(source)
    return path


@pytest.mark.parametrize("prefix", ["export let value = 0;", "export *"])
def test_exported_svelte_prop_does_not_stall_import_extraction(prefix):
    # Svelte markup becomes whitespace to preserve source locations. An exported
    # prop followed by that padding used to trigger unbounded regex backtracking.
    program = (
        "from app.adapters.typescript_nextjs import _IMPORT_RE\n"
        f"source = {prefix!r} + '\\n' + (' ' * 1000 + '\\n') * 200\n"
        "assert list(_IMPORT_RE.finditer(source)) == []\n"
    )
    subprocess.run(
        [sys.executable, "-c", program],
        env={**os.environ, "PYTHONPATH": str(Path(__file__).parents[1])},
        check=True,
        timeout=5,
        capture_output=True,
    )


@pytest.mark.parametrize(
    "source,expected",
    [
        ("export const note = 'from \"./ghost\"';", []),
        ("export default 'unrelated';", []),
        ("import './init'; export * as tools from './tools';", ["./init", "./tools"]),
        ("import Main, { type Item, value as other } from './types';", ["./types"]),
        ("import type { Item,\n Other } from './types'; export { x } from './x';", ["./types", "./x"]),
        ("import Main, * as everything from './main';", ["./main"]),
    ],
)
def test_import_specifiers_stay_inside_import_or_reexport_declarations(source, expected):
    assert [m.group("spec") for m in _IMPORT_RE.finditer(source)] == expected


def named_app(root: Path, name: str = "example_ui") -> None:
    put(root, f"backend/{name}/__init__.py", "raise AssertionError('must not import target')\n")
    put(root, f"backend/{name}/main.py", f"""from fastapi import FastAPI
from {name}.routers import records
app = FastAPI()
app.include_router(records.router, prefix='/api/v1/records')
""")
    put(root, f"backend/{name}/routers/records.py", f"""from fastapi import APIRouter
from {name}.models.records import Records
router = APIRouter()
@router.get('/{{record_id}}')
def read_record(record_id):
    return Records.get_by_id(record_id)
""")
    put(root, f"backend/{name}/models/records.py", """from sqlalchemy.orm import DeclarativeBase
class Base(DeclarativeBase): pass
class Record(Base):
    __tablename__ = 'record'
class RecordRepository:
    def get_by_id(self, record_id):
        return session.query(Record).filter(Record.id == record_id).first()
Records = RecordRepository()
""")


def test_named_fastapi_package_preserves_router_and_repository_table_lineage(tmp_path):
    named_app(tmp_path)
    truth = PostgresSqlAlchemyAdapter().extract(tmp_path, "backend")
    result = PythonFastApiAdapter().extract(tmp_path, "backend", truth)
    assert "Record" in truth.table_symbol_map
    assert truth.class_modules["Record"] == {"example_ui.models.records"}
    route = next(r for r in result.routes if r.full_path == "/api/v1/records/{record_id}")
    route_node = next(n for n in result.nodes if n.id == route.node_id)
    assert route_node.subkind == "route"
    repo = next(n for n in result.nodes if n.source_file.endswith("models/records.py"))
    assert any(e.source_id == route.node_id and e.target_id == repo.id for e in result.edges)
    assert any(e.source_id == repo.id and e.target_id == truth.table_symbol_map["Record"]
               and e.kind == "reads_truth" for e in result.edges)


def test_ambiguous_named_apps_do_not_silently_choose_one(tmp_path):
    named_app(tmp_path, "one")
    named_app(tmp_path, "two")
    result = PythonFastApiAdapter().extract(tmp_path, "backend", TruthExtractionResult([], {}, {}))
    assert not result.nodes
    assert any("ambiguous" in note.lower() for note in result.notes)


def test_external_symlink_is_not_a_named_app(tmp_path):
    named_app(tmp_path / "outside")
    root = tmp_path / "repo"
    (root / "backend").mkdir(parents=True)
    (root / "backend/example_ui").symlink_to(tmp_path / "outside/backend/example_ui")
    result = PythonFastApiAdapter().extract(root, "backend", TruthExtractionResult([], {}, {}))
    assert not result.nodes


def test_pure_models_stay_caller_only_while_mixed_repositories_are_mechanisms(tmp_path):
    named_app(tmp_path)
    put(tmp_path, "backend/example_ui/models/pure.py", """from sqlalchemy.orm import DeclarativeBase
class Base(DeclarativeBase): pass
class Pure(Base):
    __tablename__ = 'pure'
def inspect_only(value: Pure) -> Pure:
    return value
if False:
    session.query(Pure)
""")
    truth = PostgresSqlAlchemyAdapter().extract(tmp_path, "backend")
    result = PythonFastApiAdapter().extract(tmp_path, "backend", truth)
    assert "Pure" in truth.table_symbol_map
    assert not any(n.source_file.endswith("models/pure.py") for n in result.nodes)
    assert any(n.source_file.endswith("models/records.py") for n in result.nodes)


def test_svelte_plural_apis_client_preserves_import_and_http_lineage(tmp_path):
    put(tmp_path, "src/routes/+page.svelte", """<script lang="ts">
import { getRecord } from '$lib/apis/records';
let record = getRecord('123');
</script>
<p>{record}</p>
""")
    put(tmp_path, "src/lib/apis/records/index.ts", """const API_BASE_URL = '/api/v1';
export const getRecord = (id: string) =>
fetch(`${API_BASE_URL}/records/${id}`);
""")
    result = SvelteKitDisplayAdapter().extract(tmp_path, ".")
    client = next(n for n in result.nodes if n.source_file.endswith("apis/records/index.ts"))
    page = next(n for n in result.nodes if n.subkind == "page")
    assert client.subkind == "api_client"
    assert any(e.source_id == page.id and e.target_id == client.id for e in result.edges)
    call = next(c for c in result.http_calls if c.caller_node_id == client.id)
    assert call.http_method == "GET"
    assert call.normalized_path == "/api/v1/records/{param}"


def test_api_path_literal_does_not_invent_a_get_request(tmp_path):
    put(tmp_path, "src/lib/stores/session.ts", """export function createSession(connection) {
    return terminalRequest(connection, '/api/terminals', { method: 'POST' });
}
export const documentationExample = '/api/examples';
""")
    result = SvelteKitDisplayAdapter().extract(tmp_path, ".")
    assert result.nodes
    assert not result.http_calls


@pytest.mark.parametrize("attrs,missing", [
    ('{src} {alt}', False),
    ('src="/img" { alt } class="image"', False),
    ('src="/img"', True),
    ('src="/img" title="{alt}"', True),
    ('src="/img" data-name={alt}', True),
    ('src="/img" on:error={() => { alt }}', True),
])
def test_svelte_image_alt_shorthand(attrs, missing):
    findings = scan_a11y_markup_findings(f'<img {attrs} />', 'd:image', 'Image.svelte')
    assert any('missing `alt`' in f.title for f in findings) is missing


def test_imported_same_origin_url_constants_and_shadowing(
    tmp_path: Path, monkeypatch
) -> None:
    """Resolve static empty-base & imported same-origin URL constants with strict shadowing & fallback parity."""
    from app.adapters.sveltekit_display import SvelteKitDisplayAdapter

    (tmp_path / "src" / "lib" / "apis" / "records").mkdir(parents=True)
    (tmp_path / "src" / "routes" / "records" / "[id]").mkdir(parents=True)

    (tmp_path / "src" / "lib" / "constants.ts").write_text(
        "export const BASE = '';\n"
        "export const API = `${BASE}/api/v1`;\n"
        "export const ALIAS = API;\n"
        "export const REMOTE = 'https://evil.example.com';\n"
        "export const PROTO_REL = '//cdn.example.com';\n"
        "export const DYNAMIC = window.location.origin;\n",
        encoding="utf-8",
    )
    (tmp_path / "src" / "lib" / "barrel.ts").write_text(
        "export { API as BARREL_API, BASE } from './constants.js';\n",
        encoding="utf-8",
    )
    (tmp_path / "src" / "lib" / "cyc_a.ts").write_text(
        "import { CYC_B } from './cyc_b';\nexport const CYC_A = `${CYC_B}/a`;\n",
        encoding="utf-8",
    )
    (tmp_path / "src" / "lib" / "cyc_b.ts").write_text(
        "import { CYC_A } from './cyc_a';\nexport const CYC_B = `${CYC_A}/b`;\n",
        encoding="utf-8",
    )
    (tmp_path / "src" / "lib" / "apis" / "records" / "index.ts").write_text(
        "import { API, ALIAS, REMOTE, PROTO_REL, DYNAMIC, BASE } from '$lib/constants';\n"
        "import { BARREL_API as REX_API } from '../../barrel';\n"
        "import { CYC_A } from '$lib/cyc_a';\n"
        "export const getRecord = (id: string) => fetch(`${API}/records/${id}`);\n"
        "export const listViaAlias = () => fetch(`${ALIAS}/records`);\n"
        "export const createViaBarrel = () => fetch(`${REX_API}/records`, { method: 'POST' });\n"
        "export const rejectEmpty = () => fetch(BASE);\n"
        "export const rejectRemote = () => fetch(`${REMOTE}/leak`);\n"
        "export const rejectProtoRel = () => fetch(`${PROTO_REL}/leak`);\n"
        "export const rejectDynamic = () => fetch(`${DYNAMIC}/leak`);\n"
        "export const rejectCycle = () => fetch(`${CYC_A}/leak`);\n"
        "export const paramShadow = (API: string) => fetch(`${API}/shadowed-param`);\n"
        "export const localShadow = () => {\n"
        "  const API = 'https://other.example.com';\n"
        "  return fetch(`${API}/shadowed-local`);\n"
        "};\n"
        "export const varShadow = () => {\n"
        "  let REX_API = '/temp';\n"
        "  REX_API = '/reassigned';\n"
        "  return fetch(`${REX_API}/shadowed-reassign`);\n"
        "};\n",
        encoding="utf-8",
    )
    (tmp_path / "src" / "routes" / "records" / "[id]" / "+page.svelte").write_text(
        "<script lang='ts'>import { getRecord } from '$lib/apis/records';</script><main>Ok</main>\n",
        encoding="utf-8",
    )

    adapter = SvelteKitDisplayAdapter()
    for disable_ts in ("0", "1"):
        if disable_ts == "1":
            monkeypatch.setenv("WYTHE_DISABLE_TREESITTER", "1")
        else:
            monkeypatch.delenv("WYTHE_DISABLE_TREESITTER", raising=False)
        res = adapter.extract(tmp_path, ".")
        calls = {(c.http_method, c.normalized_path) for c in res.http_calls}
        assert ("GET", "/api/v1/records/{param}") in calls
        assert ("GET", "/api/v1/records") in calls
        assert ("POST", "/api/v1/records") in calls
        assert not any("leak" in p or "shadowed" in p or p == "/" for _, p in calls), calls
        assert any("imported same-origin URL constants" in n for n in res.notes)


def test_opaque_and_local_component_a11y_inspection(tmp_path: Path) -> None:
    """Inspect local component text semantics before firing DISP-005; keep opaque components unobserved."""
    from app.adapters.sveltekit_display import SvelteKitDisplayAdapter

    (tmp_path / "src" / "lib" / "components" / "common").mkdir(parents=True)
    (tmp_path / "src" / "lib" / "components" / "icons").mkdir(parents=True)
    (tmp_path / "src" / "routes").mkdir(parents=True)

    (tmp_path / "src" / "lib" / "components" / "common" / "Tooltip.svelte").write_text(
        "<script lang='ts'>export let as = 'div'; export let content = '';</script>\n"
        "<svelte:element this={as}><slot /></svelte:element>\n",
        encoding="utf-8",
    )
    (tmp_path / "src" / "lib" / "components" / "common" / "ModelSettingsLabel.svelte").write_text(
        "<script lang='ts'>\n"
        "  import Tooltip from '$lib/components/common/Tooltip.svelte';\n"
        "  export let label = '';\n"
        "  export let description = '';\n"
        "</script>\n"
        "{#if description}\n"
        "  <Tooltip as='span' content={description}><span>{label}</span></Tooltip>\n"
        "{:else}\n"
        "  <span>{label}</span>\n"
        "{/if}\n",
        encoding="utf-8",
    )
    (tmp_path / "src" / "lib" / "components" / "icons" / "ChevronRight.svelte").write_text(
        "<script lang='ts'>export let label = ''; export let className = 'size-3';</script>\n"
        "<svg aria-hidden='true' viewBox='0 0 24 24' class={className}><path d='M8 4l8 8-8 8' /></svg>\n",
        encoding="utf-8",
    )
    (tmp_path / "src" / "routes" / "+page.svelte").write_text(
        "<script lang='ts'>\n"
        "  import ModelSettingsLabel from '$lib/components/common/ModelSettingsLabel.svelte';\n"
        "  import ChevronRight from '$lib/components/icons/ChevronRight.svelte';\n"
        "  import { Menu } from 'lucide-svelte';\n"
        "  import { OpaqueWidget } from '@external/ui';\n"
        "</script>\n"
        "<button type='button'><ModelSettingsLabel label={$i18n.t('Defaults')} description='desc' /><ChevronRight /></button>\n"
        "<button type='button'><ModelSettingsLabel /></button>\n"
        "<button type='button'><ModelSettingsLabel label='' /></button>\n"
        "<button type='button'><ChevronRight label='unused prop' /></button>\n"
        "<button type='button'><OpaqueWidget label='Unknown' /></button>\n"
        "<button type='button'><Menu /></button>\n",
        encoding="utf-8",
    )

    res = SvelteKitDisplayAdapter().extract(tmp_path, ".")
    disp_005 = [f for f in res.findings if f.rule_code == "DISP-005"]
    lines = sorted(f.line for f in disp_005)
    # Line 7 (ModelSettingsLabel with text) -> clean; Line 11 (OpaqueWidget) -> unobserved (not DISP-005)
    assert lines == [8, 9, 10, 12], disp_005
    assert any("unobserved" in n.lower() and "OpaqueWidget" in n for n in res.notes), res.notes


def test_template_literal_import_and_nested_block_shadowing(tmp_path: Path, monkeypatch) -> None:
    """Ignore fake imports/exports in template literals & isolate nested block lexical shadowing."""
    put(tmp_path, "src/lib/local.ts", "export const API = '/internal';\n")
    put(
        tmp_path,
        "src/lib/constants.ts",
        "export const API = '/api/v1';\n"
        "export const DOC = `\nexport const FAKED = '/bad';\n`;\n",
    )
    put(
        tmp_path,
        "src/routes/demo/+page.ts",
        "import { API as EXT_API } from 'external-config';\n"
        "import { API as REAL_API, FAKED } from '$lib/constants';\n"
        "const docs = `\nimport { EXT_API } from '../lib/local';\n`;\n"
        "const SCOPED = '/scoped';\n"
        "{\n"
        "  let SCOPED;\n"
        "  SCOPED = '/shadowed';\n"
        "}\n"
        "export function load(cond: boolean) {\n"
        "  fetch(`${EXT_API}/should-not-emit`);\n"
        "  fetch(`${SCOPED}/items`);\n"
        "  fetch(`${FAKED}/never`);\n"
        "  if (cond) {\n"
        "    REAL_API = '/mutated';\n"
        "  }\n"
        "  return fetch(`${REAL_API}/after-mutation`);\n"
        "}\n",
    )
    put(tmp_path, "src/routes/demo/+page.svelte", "<main>Demo</main>\n")

    adapter = SvelteKitDisplayAdapter()
    for disable_ts in ("0", "1"):
        if disable_ts == "1":
            monkeypatch.setenv("WYTHE_DISABLE_TREESITTER", "1")
        else:
            monkeypatch.delenv("WYTHE_DISABLE_TREESITTER", raising=False)
        res = adapter.extract(tmp_path, ".")
        paths = {c.normalized_path for c in res.http_calls}
        assert "/scoped/items" in paths, (disable_ts, paths)
        assert "/internal/should-not-emit" not in paths, (disable_ts, paths)
        assert "/bad/never" not in paths, (disable_ts, paths)
        assert "/api/v1/after-mutation" not in paths, (disable_ts, paths)


def test_inline_script_imports_and_child_local_expr_a11y(tmp_path: Path) -> None:
    """Resolve inline single-line <script> imports and treat non-prop child exprs as unobserved."""
    put(
        tmp_path,
        "src/lib/components/SaveLabel.svelte",
        "<script lang='ts'>const label = 'Save';</script><span>{label}</span>\n",
    )
    put(
        tmp_path,
        "src/lib/components/I18nLabel.svelte",
        "<script lang='ts'>const key = 'actions.save'; const t = (k: string) => k;</script><span>{t(key)}</span>\n",
    )
    put(
        tmp_path,
        "src/routes/+page.svelte",
        "<script lang='ts'>import { Menu } from 'lucide-svelte'; "
        "import SaveLabel from '$lib/components/SaveLabel.svelte'; "
        "import I18nLabel from '$lib/components/I18nLabel.svelte';</script>"
        "<button type='button'><Menu /></button>"
        "<button type='button'><SaveLabel /></button>"
        "<button type='button'><I18nLabel /></button>\n",
    )
    res = SvelteKitDisplayAdapter().extract(tmp_path, ".")
    disp_005 = [f for f in res.findings if f.rule_code == "DISP-005"]
    assert len(disp_005) == 1, disp_005


def test_barrel_explicit_export_masks_star_reexport_and_svelte_slot_opaque(
    tmp_path: Path,
) -> None:
    """Explicit unresolved exports shadow `export *`, and `<slot />` preserves opaque children."""
    put(tmp_path, "src/lib/local.ts", "export const API = '/internal';\n")
    put(
        tmp_path,
        "src/lib/barrel.ts",
        "export * from './local';\n"
        "export const API = process.env.PUBLIC_API;\n",
    )
    put(
        tmp_path,
        "src/lib/Wrapper.svelte",
        "<span class='wrap'><slot /></span>\n",
    )
    put(
        tmp_path,
        "src/routes/+page.ts",
        "import { API } from '$lib/barrel';\n"
        "export function load() {\n"
        "  return fetch(`${API}/users`);\n"
        "}\n",
    )
    put(
        tmp_path,
        "src/routes/+page.svelte",
        "<script lang='ts'>\n"
        "import { ThirdPartyLabel, MenuIcon } from 'third-party-ui';\n"
        "import Wrapper from '$lib/Wrapper.svelte';\n"
        "</script>\n"
        "<button type='button'><Wrapper><ThirdPartyLabel /></Wrapper></button>\n"
        "<button type='button'><Wrapper><MenuIcon /></Wrapper></button>\n"
        "<button type='button'><svg aria-hidden='true' /></button>\n",
    )
    res = SvelteKitDisplayAdapter().extract(tmp_path, ".")
    paths = {c.normalized_path for c in res.http_calls}
    assert "/internal/users" not in paths, paths
    disp_005 = [f for f in res.findings if f.rule_code == "DISP-005"]
    assert [(f.source_file, f.line) for f in disp_005] == [("src/routes/+page.svelte", 7)], disp_005


def test_icon_component_aria_label_and_forwarded_undefined_prop_defaults(tmp_path: Path) -> None:
    """Icon components honor ARIA name props and forwarded omitted props keep `undefined`."""
    from app.adapters.typescript_nextjs import TypeScriptNextJsAdapter

    put(
        tmp_path,
        "components/Labels.tsx",
        "export function Label({ text = 'Save' }: { text?: string | null }) {\n"
        "  return <span>{text}</span>;\n"
        "}\n"
        "export function Wrapper({ text }: { text?: string | null }) {\n"
        "  return <Label text={text} />;\n"
        "}\n"
        "export function WrapperProps(props: { text?: string | null }) {\n"
        "  return <Label text={props.text} />;\n"
        "}\n",
    )
    put(
        tmp_path,
        "app/page.tsx",
        "import { Search } from 'lucide-react';\n"
        "import { Wrapper, WrapperProps } from '../components/Labels';\n"
        "export function Page() {\n"
        "  return (\n"
        "    <div>\n"
        "      <button><Search aria-hidden={false} aria-label='Search' /></button>\n"
        "      <button><Search aria-hidden={true} aria-label='Hidden' /></button>\n"
        "      <button><Search /></button>\n"
        "      <button><Wrapper /></button>\n"
        "      <button><Wrapper text={undefined} /></button>\n"
        "      <button><Wrapper text='' /></button>\n"
        "      <button><Wrapper text={null} /></button>\n"
        "      <button><WrapperProps /></button>\n"
        "    </div>\n"
        "  );\n"
        "}\n",
    )
    res = TypeScriptNextJsAdapter().extract(tmp_path, ".")
    disp_005 = [f for f in res.findings if f.rule_code == "DISP-005"]
    lines = sorted(f.line for f in disp_005)
    assert lines == [7, 8, 11, 12], disp_005


def test_vue_bound_prop_expressions_and_concat_url_origin_resolution(
    tmp_path: Path, monkeypatch
) -> None:
    """Vue `:prop` evaluates expressions; concatenated URL constants check full expanded origin."""
    from app.adapters.typescript_nextjs import _extract_ts_http_calls
    from app.adapters.vue_sfc import VueSfcDisplayAdapter

    put(
        tmp_path,
        "src/components/Label.vue",
        "<script setup lang='ts'>defineProps<{ text?: string | null }>();</script>\n"
        "<template><span>{{ text }}</span></template>\n",
    )
    put(
        tmp_path,
        "src/App.vue",
        "<script setup lang='ts'>\n"
        "import { Search } from 'lucide-vue-next';\n"
        "import Label from './components/Label.vue';\n"
        "</script>\n"
        "<template>\n"
        "  <button><Label :text=\"''\" /></button>\n"
        "  <button><Label :text='null' /></button>\n"
        "  <button><Label v-bind:text=\"''\" /></button>\n"
        "  <button><Label :text=\"'Save'\" /></button>\n"
        "  <button><Search :aria-label=\"'Find'\" /></button>\n"
        "  <button><Search :aria-label=\"''\" /></button>\n"
        "</template>\n",
    )
    res = VueSfcDisplayAdapter().extract(tmp_path, ".")
    disp_lines = sorted(f.line for f in res.findings if f.rule_code == "DISP-005")
    assert disp_lines == [6, 7, 8, 11], res.findings

    src = (
        "const HOST = '/evil.example';\n"
        "const PROTO = '//evil.example';\n"
        "const BASE = '/api';\n"
        "const SUB = '/v1';\n"
        "fetch('/' + HOST + '/users');\n"
        "fetch(`/${HOST}/users`);\n"
        "fetch('/' + PROTO + '/users');\n"
        "fetch('' + PROTO + '/users');\n"
        "fetch(BASE + SUB + '/items');\n"
    )
    cst_calls = {url for _v, url, _l in _extract_ts_http_calls(src)}
    assert "//evil.example/users" not in cst_calls
    assert "/${HOST}/users" not in cst_calls
    assert "/evil.example/users" not in cst_calls
    assert "/api/v1/items" in cst_calls

    import app.adapters.typescript_nextjs as tsnext

    monkeypatch.setattr(tsnext, "extract_ts_http_calls_cst", lambda *a, **k: None)
    rx_calls = {url for _v, url, _l in _extract_ts_http_calls(src)}
    assert "//evil.example/users" not in rx_calls
    assert "/${HOST}/users" not in rx_calls


def test_aria_named_elements_and_nullish_vs_or_coalescing_a11y(tmp_path: Path) -> None:
    """ARIA-named wrapper elements, nullish coalescing, forwarded children, and stacked export lists."""
    from app.adapters.sveltekit_display import SvelteKitDisplayAdapter
    from app.adapters.typescript_nextjs import TypeScriptNextJsAdapter

    put(
        tmp_path,
        "src/lib/urls.ts",
        "const A = '/api/alpha';\n"
        "const B = '/api/beta';\n"
        "export { A }\n"
        "export { B }\n",
    )
    put(
        tmp_path,
        "src/lib/sep.ts",
        "const C = '/api/gamma'; const D = '/api/delta'; export { C }; export { D }\n",
    )
    put(
        tmp_path,
        "src/routes/+page.ts",
        "import { A, B } from '$lib/urls';\n"
        "import { C, D } from '$lib/sep';\n"
        "export function load() {\n"
        "  return Promise.all([fetch(A), fetch(B), fetch(C), fetch(D)]);\n"
        "}\n",
    )
    s_res = SvelteKitDisplayAdapter().extract(tmp_path, ".")
    s_urls = {c.normalized_path for c in s_res.http_calls}
    assert {"/api/alpha", "/api/beta", "/api/gamma", "/api/delta"}.issubset(s_urls), s_urls

    put(
        tmp_path,
        "components/Coalesce.tsx",
        "export function NullishLabel({ text }: { text?: string | null }) {\n"
        "  return <span>{text ?? 'Save'}</span>;\n"
        "}\n"
        "export function OrLabel({ text }: { text?: string | null }) {\n"
        "  return <span>{text || 'Save'}</span>;\n"
        "}\n"
        "export function ChildLeaf({ children }: { children?: unknown }) {\n"
        "  return <span>{children}</span>;\n"
        "}\n"
        "export function ChildWrapper({ children }: { children?: unknown }) {\n"
        "  return <ChildLeaf children={children} />;\n"
        "}\n",
    )
    put(
        tmp_path,
        "app/page.tsx",
        "import { ChildWrapper, NullishLabel, OrLabel } from '../components/Coalesce';\n"
        "export function Page() {\n"
        "  return (\n"
        "    <div>\n"
        "      <button><span role='img' aria-label='Save'><svg /></span></button>\n"
        "      <button><span role='img' aria-label=''><svg /></span></button>\n"
        "      <button><span role='presentation' aria-label='Save'><svg /></span></button>\n"
        "      <button><span aria-hidden={true}>Hidden</span><svg /></button>\n"
        "      <button><NullishLabel text='' /></button>\n"
        "      <button><NullishLabel text={null} /></button>\n"
        "      <button><NullishLabel text={undefined} /></button>\n"
        "      <button><NullishLabel /></button>\n"
        "      <button><NullishLabel text='   ' /></button>\n"
        "      <button><OrLabel text='' /></button>\n"
        "      <button><OrLabel text='   ' /></button>\n"
        "      <button><OrLabel text={null} /></button>\n"
        "      <button><NullishLabel text={false} /></button>\n"
        "      <button><OrLabel text={false} /></button>\n"
        "      <button><ChildWrapper>Save</ChildWrapper></button>\n"
        "      <button><span><i>Save</i></span></button>\n"
        "      <button><span><i className='icon' /></span></button>\n"
        "      <button><span><svg role='img'><title>Save</title></svg></span></button>\n"
        "      <button><span><svg role='none'><title>Save</title></svg></span></button>\n"
        "      <button><span><i aria-hidden='true'>Save</i></span></button>\n"
        "    </div>\n"
        "  );\n"
        "}\n",
    )
    res = TypeScriptNextJsAdapter().extract(tmp_path, ".")
    disp_lines = sorted(f.line for f in res.findings if f.rule_code == "DISP-005")
    assert disp_lines == [6, 7, 8, 9, 13, 15, 17, 21, 23, 24], res.findings


def test_vue_kebab_case_and_framework_boolean_semantics_a11y(tmp_path: Path) -> None:
    """Vue kebab-case components stay resolved/opaque and Svelte/Vue booleans render text."""
    from app.adapters.sveltekit_display import SvelteKitDisplayAdapter
    from app.adapters.vue_sfc import VueSfcDisplayAdapter

    vue_root = tmp_path / "vue_app"
    put(
        vue_root,
        "src/components/LabelText.vue",
        "<template><span>Save</span></template>\n",
    )
    put(
        vue_root,
        "src/components/BoolText.vue",
        "<script setup>\nconst props = defineProps({ text: String });\n</script>\n"
        "<template><span>{{ text }}</span></template>\n",
    )
    put(
        vue_root,
        "src/components/EmptyBadge.vue",
        "<script setup>\nconst props = defineProps({ empty: Boolean });\n</script>\n"
        "<template><span /></template>\n",
    )
    put(
        vue_root,
        "src/App.vue",
        "<script setup>\n"
        "import LabelText from './components/LabelText.vue';\n"
        "import BoolText from './components/BoolText.vue';\n"
        "import EmptyBadge from './components/EmptyBadge.vue';\n"
        "</script>\n"
        "<template>\n"
        "  <button><svg /><label-text /></button>\n"
        "  <button><svg /><unknown-widget /></button>\n"
        "  <button><bool-text :text=\"false\" /></button>\n"
        "  <button><svg /><empty-badge /></button>\n"
        "</template>\n",
    )
    vue_res = VueSfcDisplayAdapter().extract(vue_root, ".")
    vue_disp = [f.line for f in vue_res.findings if f.rule_code == "DISP-005"]
    assert vue_disp == [10], vue_res.findings

    sv_root = tmp_path / "svelte_app"
    put(
        sv_root,
        "src/lib/BoolLabel.svelte",
        "<script>export let text;</script>\n<span>{text}</span>\n",
    )
    put(
        sv_root,
        "src/routes/+page.svelte",
        "<script>import BoolLabel from '$lib/BoolLabel.svelte';</script>\n"
        "<button><BoolLabel text={false} /></button>\n"
        "<button><BoolLabel text={true} /></button>\n"
        "<button><BoolLabel text='' /></button>\n",
    )
    sv_res = SvelteKitDisplayAdapter().extract(sv_root, ".")
    sv_disp = [f.line for f in sv_res.findings if f.rule_code == "DISP-005"]
    assert sv_disp == [4], sv_res.findings


def test_named_export_aliases_reexports_and_explicit_empty_children_a11y(tmp_path: Path) -> None:
    """Resolve export aliases/re-exports before local helpers and distinguish omitted vs empty children."""
    from app.adapters.typescript_nextjs import TypeScriptNextJsAdapter

    put(
        tmp_path,
        "components/ExportAliases.tsx",
        "function Label() { return <svg />; }\n"
        "function TextLabel() { return <span>Save</span>; }\n"
        "export { TextLabel as Label };\n",
    )
    put(
        tmp_path,
        "components/barrel.ts",
        "export { Label as Aliased } from './ExportAliases';\n",
    )
    put(
        tmp_path,
        "components/ChildrenDefaults.tsx",
        "export function DefaultChild({ children = 'Save' }: { children?: unknown }) {\n"
        "  return <span>{children}</span>;\n"
        "}\n"
        "export function NullishChild({ children }: { children?: unknown }) {\n"
        "  return <span>{children ?? 'Save'}</span>;\n"
        "}\n"
        "export function OrChild({ children }: { children?: unknown }) {\n"
        "  return <span>{children || 'Save'}</span>;\n"
        "}\n",
    )
    put(
        tmp_path,
        "app/page.tsx",
        "import { Label as ImportedLabel } from '../components/ExportAliases';\n"
        "import { Aliased } from '../components/barrel';\n"
        "import { DefaultChild, NullishChild, OrChild } from '../components/ChildrenDefaults';\n"
        "function Label() { return <svg />; }\n"
        "export function Page() {\n"
        "  return (\n"
        "    <div>\n"
        "      <button><Label /></button>\n"
        "      <button><ImportedLabel /></button>\n"
        "      <button><Aliased /></button>\n"
        "      <button><DefaultChild /></button>\n"
        "      <button><DefaultChild>{undefined}</DefaultChild></button>\n"
        "      <button><DefaultChild>{null}</DefaultChild></button>\n"
        "      <button><DefaultChild>{false}</DefaultChild></button>\n"
        "      <button><DefaultChild>{''}</DefaultChild></button>\n"
        "      <button><DefaultChild><span /></DefaultChild></button>\n"
        "      <button><NullishChild /></button>\n"
        "      <button><NullishChild>{null}</NullishChild></button>\n"
        "      <button><NullishChild>{false}</NullishChild></button>\n"
        "      <button><NullishChild>{''}</NullishChild></button>\n"
        "      <button><NullishChild><span /></NullishChild></button>\n"
        "      <button><OrChild /></button>\n"
        "      <button><OrChild>{null}</OrChild></button>\n"
        "      <button><OrChild>{false}</OrChild></button>\n"
        "      <button><OrChild>{''}</OrChild></button>\n"
        "      <button><OrChild><span /></OrChild></button>\n"
        "    </div>\n"
        "  );\n"
        "}\n",
    )
    res = TypeScriptNextJsAdapter().extract(tmp_path, ".")
    disp_lines = sorted(f.line for f in res.findings if f.rule_code == "DISP-005")
    assert disp_lines == [8, 13, 14, 15, 16, 19, 20, 21, 26], res.findings


def test_zero_falsy_injected_html_expr_returns_case_isolation_and_lexical_scope_a11y(
    tmp_path: Path,
) -> None:
    """Verify exact JSX tag casing, zero in `||`, injected HTML, expr-only returns, and lexical helpers."""
    from app.adapters.typescript_nextjs import TypeScriptNextJsAdapter

    put(
        tmp_path,
        "components/Span.tsx",
        "export default function Span() { return <svg />; }\n",
    )
    put(
        tmp_path,
        "app/page.tsx",
        "import Span from '../components/Span';\n"
        "function ZeroOrEmpty() { return <span>{0 || ''}</span>; }\n"
        "function ZeroNullish() { return <span>{0 ?? ''}</span>; }\n"
        "function NullReturn() { return null; }\n"
        "function FalseReturn() { return false; }\n"
        "function EmptyStrReturn() { return ''; }\n"
        "const ArrowNullReturn = () => null;\n"
        "const ArrowTextReturn = () => 'Save';\n"
        "function First() {\n"
        "  function Label() { return <svg />; }\n"
        "  return <button><span><Label /></span></button>;\n"
        "}\n"
        "function Second() {\n"
        "  function Label() { return <span>Save</span>; }\n"
        "  return <button><span><Label /></span></button>;\n"
        "}\n"
        "export function Page({ dynamicHtml }: { dynamicHtml: { __html: string } }) {\n"
        "  return (\n"
        "    <div>\n"
        "      <button><span>Save</span></button>\n"
        "      <button><ZeroOrEmpty /></button>\n"
        "      <button><ZeroNullish /></button>\n"
        "      <button><NullReturn /></button>\n"
        "      <button><FalseReturn /></button>\n"
        "      <button><EmptyStrReturn /></button>\n"
        "      <button><ArrowNullReturn /></button>\n"
        "      <button><ArrowTextReturn /></button>\n"
        "      <button><span dangerouslySetInnerHTML={{ __html: 'Save' }} /><svg /></button>\n"
        "      <button><span dangerouslySetInnerHTML={dynamicHtml} /><svg /></button>\n"
        "      <button><span dangerouslySetInnerHTML={{ __html: '' }} /><svg /></button>\n"
        "      <button dangerouslySetInnerHTML={{ __html: 'Save' }}></button>\n"
        "      <button dangerouslySetInnerHTML={{ __html: '<svg />' }}></button>\n"
        "    </div>\n"
        "  );\n"
        "}\n",
    )
    res = TypeScriptNextJsAdapter().extract(tmp_path, ".")
    disp_lines = sorted(f.line for f in res.findings if f.rule_code == "DISP-005")
    assert disp_lines == [11, 21, 23, 24, 25, 26, 30, 32], res.findings


def test_shadowing_presentational_italic_dynamic_components_and_portals_a11y(
    tmp_path: Path,
) -> None:
    """Verify local shadowing over imports, `<i role=presentation>`, dynamic components, and portals."""
    from app.adapters.sveltekit_display import SvelteKitDisplayAdapter
    from app.adapters.typescript_nextjs import TypeScriptNextJsAdapter
    from app.adapters.vue_sfc import VueSfcDisplayAdapter

    tsx_root = tmp_path / "tsx_app"
    put(
        tsx_root,
        "components/Icon.tsx",
        "export default function Icon() { return <svg />; }\n",
    )
    put(
        tsx_root,
        "app/page.tsx",
        "import Label from '../components/Icon';\n"
        "import { Check as LucideIcon } from 'lucide-react';\n"
        "import { createPortal } from 'react-dom';\n"
        "function wrapHelper(node: unknown) { return node; }\n"
        "function TooltipPortal() { return createPortal(<span>Save</span>, document.body); }\n"
        "function ReactDomPortal() { return ReactDOM.createPortal(<span>Save</span>, document.body); }\n"
        "function Wrapped() { return wrapHelper(<span>Save</span>); }\n"
        "export function App() {\n"
        "  const Label = () => <span>Save</span>;\n"
        "  const LucideIcon = () => <span>Save</span>;\n"
        "  return (\n"
        "    <div>\n"
        "      <button><Label /></button>\n"
        "      <button><LucideIcon /></button>\n"
        "      <button><span><i role='presentation'>Save</i></span></button>\n"
        "      <button><span><i role='none'>Save</i></span></button>\n"
        "      <button><span><i role='presentation' /></span></button>\n"
        "      <button><span><i aria-hidden='true'>Save</i></span></button>\n"
        "      <button><svg /><TooltipPortal /></button>\n"
        "      <button><svg /><ReactDomPortal /></button>\n"
        "      <button><svg />{createPortal(<span>Save</span>, document.body)}</button>\n"
        "      <button><svg /><Wrapped /></button>\n"
        "    </div>\n"
        "  );\n"
        "}\n"
        "export function Unshadowed() { return <button><Label /></button>; }\n"
        "export function UnshadowedIcon() { return <button><LucideIcon /></button>; }\n",
    )
    tsx_res = TypeScriptNextJsAdapter().extract(tsx_root, ".")
    tsx_lines = sorted(f.line for f in tsx_res.findings if f.rule_code == "DISP-005")
    assert tsx_lines == [17, 18, 19, 20, 21, 26, 27], tsx_res.findings

    vue_root = tmp_path / "vue_app"
    put(vue_root, "src/components/Label.vue", "<template><span>Save</span></template>\n")
    put(vue_root, "src/components/IconOnly.vue", "<template><svg /></template>\n")
    put(
        vue_root,
        "src/App.vue",
        "<script setup>\n"
        "import Label from './components/Label.vue';\n"
        "import IconOnly from './components/IconOnly.vue';\n"
        "const dynamicComp = 'unknown';\n"
        "</script>\n"
        "<template>\n"
        "  <button><component :is=\"Label\" /><svg /></button>\n"
        "  <button><component :is=\"IconOnly\" /></button>\n"
        "  <button><component :is=\"dynamicComp\" /><svg /></button>\n"
        "</template>\n",
    )
    vue_res = VueSfcDisplayAdapter().extract(vue_root, ".")
    vue_lines = sorted(f.line for f in vue_res.findings if f.rule_code == "DISP-005")
    assert vue_lines == [8], vue_res.findings

    sv_root = tmp_path / "svelte_app"
    put(sv_root, "src/lib/Label.svelte", "<span>Save</span>\n")
    put(sv_root, "src/lib/IconOnly.svelte", "<svg />\n")
    put(
        sv_root,
        "src/routes/+page.svelte",
        "<script>import Label from '$lib/Label.svelte'; import IconOnly from '$lib/IconOnly.svelte'; let dynamicComp;</script>\n"
        "<button><svelte:component this={Label} /><svg /></button>\n"
        "<button><svelte:component this={IconOnly} /></button>\n"
        "<button><svelte:component this={dynamicComp} /><svg /></button>\n",
    )
    sv_res = SvelteKitDisplayAdapter().extract(sv_root, ".")
    sv_lines = sorted(f.line for f in sv_res.findings if f.rule_code == "DISP-005")
    assert sv_lines == [3], sv_res.findings


def test_named_slot_fallback_v_text_nested_method_returns_and_linear_resolver_scaling(
    tmp_path: Path,
):
    from app.adapters.typescript_nextjs import TypeScriptNextJsAdapter
    from app.adapters.vue_sfc import VueSfcDisplayAdapter

    # 1. Named slots: inspect fallback when caller omits content; stay opaque when caller passes content.
    # 2. Vue v-text / :textContent / :text-content / :innerText / :inner-text literal text & booleans.
    vue_root = tmp_path / "vue_slots_and_text"
    put(
        vue_root,
        "src/components/NamedLabel.vue",
        "<template><slot name=\"label\">Save</slot><svg /></template>\n",
    )
    put(
        vue_root,
        "src/components/NamedIconOnly.vue",
        "<template><slot name=\"icon\"><svg /></slot></template>\n",
    )
    put(
        vue_root,
        "src/components/NamedEmpty.vue",
        "<template><slot name=\"label\" /><svg /></template>\n",
    )
    put(
        vue_root,
        "src/components/VTextLabel.vue",
        "<script setup>defineProps(['label']);</script>\n"
        "<template><span v-text=\"label\" /><svg /></template>\n",
    )
    put(
        vue_root,
        "src/App.vue",
        "<script setup>\n"
        "import NamedLabel from './components/NamedLabel.vue';\n"
        "import NamedIconOnly from './components/NamedIconOnly.vue';\n"
        "import NamedEmpty from './components/NamedEmpty.vue';\n"
        "import VTextLabel from './components/VTextLabel.vue';\n"
        "const label = 'Run';\n"
        "</script>\n"
        "<template>\n"
        "  <button><NamedLabel /></button>\n"
        "  <button><NamedIconOnly /></button>\n"
        "  <button><NamedEmpty><template #label>Filled</template></NamedEmpty></button>\n"
        "  <button v-text=\"label\"><svg /></button>\n"
        "  <button :textContent=\"'<svg />'\"></button>\n"
        "  <button><span :text-content=\"'Save'\" /><svg /></button>\n"
        "  <button><span :innerText=\"label\" /><svg /></button>\n"
        "  <button v-text=\"''\"><svg /></button>\n"
        "  <button><VTextLabel :label=\"false\" /></button>\n"
        "</template>\n",
    )
    vue_res = VueSfcDisplayAdapter().extract(vue_root, ".")
    vue_lines = sorted(f.line for f in vue_res.findings if f.rule_code == "DISP-005")
    assert vue_lines == [10, 16], vue_res.findings

    # Same named-slot behavior in Svelte.
    sv_root = tmp_path / "svelte_slots"
    put(sv_root, "src/lib/NamedLabel.svelte", "<slot name=\"label\">Save</slot><svg />\n")
    put(sv_root, "src/lib/NamedIconOnly.svelte", "<slot name=\"icon\"><svg /></slot>\n")
    put(
        sv_root,
        "src/routes/+page.svelte",
        "<script>import NamedLabel from '$lib/NamedLabel.svelte'; import NamedIconOnly from '$lib/NamedIconOnly.svelte';</script>\n"
        "<button><NamedLabel /></button>\n"
        "<button><NamedIconOnly /></button>\n",
    )
    sv_res = SvelteKitDisplayAdapter().extract(sv_root, ".")
    sv_lines = sorted(f.line for f in sv_res.findings if f.rule_code == "DISP-005")
    assert sv_lines == [3], sv_res.findings

    # 3. Nested object/class method returns in TSX must not masquerade as component output.
    tsx_root = tmp_path / "tsx_nested_methods"
    put(
        tsx_root,
        "app/page.tsx",
        "function HelperIcon() {\n"
        "  const sym = Symbol('label');\n"
        "  const obj = {\n"
        "    label() { return <span>Save</span>; },\n"
        "    async asyncLabel(): Promise<{ text: string }> { return { text: 'Save' }; },\n"
        "    get text(): string { return 'Save'; },\n"
        "    *gen() { yield 1; return <span>Save</span>; },\n"
        "    [sym]() { return <span>Sym</span>; },\n"
        "  };\n"
        "  class HelperClass {\n"
        "    render(): string { return 'Save'; }\n"
        "  }\n"
        "  void obj; void HelperClass;\n"
        "  return <svg />;\n"
        "}\n"
        "function ConditionalNamed({ ready }: { ready: boolean }) {\n"
        "  if (ready) { return <span>Save</span>; }\n"
        "  return <span>Done</span>;\n"
        "}\n"
        "export function Page({ ready }: { ready: boolean }) {\n"
        "  return (\n"
        "    <div>\n"
        "      <button><HelperIcon /></button>\n"
        "      <button><ConditionalNamed ready={ready} /><svg /></button>\n"
        "    </div>\n"
        "  );\n"
        "}\n",
    )
    tsx_res = TypeScriptNextJsAdapter().extract(tsx_root, ".")
    tsx_lines = sorted(f.line for f in tsx_res.findings if f.rule_code == "DISP-005")
    assert tsx_lines == [23], tsx_res.findings

    # 4. Performance regression: caching lexical index avoids O(N^2) scaling across 400 usages.
    perf_root = tmp_path / "tsx_perf"
    usages = "\n".join(
        "      <button><LocalIcon /><span>ok</span></button>" for _ in range(399)
    ) + "\n      <button><LocalIcon /></button>"
    put(
        perf_root,
        "app/page.tsx",
        "function LocalIcon() { return <svg />; }\n"
        "const unrelatedA = 1;\n"
        "const unrelatedB = 2;\n"
        "export function Page() {\n"
        "  return (\n"
        "    <div>\n"
        f"{usages}\n"
        "    </div>\n"
        "  );\n"
        "}\n",
    )
    t0 = time.perf_counter()
    perf_res = TypeScriptNextJsAdapter().extract(perf_root, ".")
    elapsed = time.perf_counter() - t0
    perf_lines = [f for f in perf_res.findings if f.rule_code == "DISP-005"]
    assert [f.line for f in perf_lines] == [406], perf_lines
    assert elapsed < 1.0, f"Resolver took {elapsed:.3f}s for 400 local usages"


def test_bare_jsx_props_svelte_if_branches_and_native_hidden_a11y(
    tmp_path: Path,
) -> None:
    """Verify bare boolean props, Svelte directives & `{#if}` branches, and native `hidden` attrs."""
    from app.adapters.sveltekit_display import SvelteKitDisplayAdapter
    from app.adapters.typescript_nextjs import TypeScriptNextJsAdapter

    tsx_root = tmp_path / "tsx_app"
    put(
        tsx_root,
        "app/page.tsx",
        "function Label({ text = 'Save' }: { text?: unknown }) {\n"
        "  return <span>{text}</span>;\n"
        "}\n"
        "export function App() {\n"
        "  return (\n"
        "    <div>\n"
        "      <button><Label /><svg /></button>\n"
        "      <button><Label text=\"Save\" /><svg /></button>\n"
        "      <button><Label text /><svg /></button>\n"
        "      <button><span title=\"Show hidden\">Save</span></button>\n"
        "      <button hidden><svg /></button>\n"
        "      <button><span hidden>Save</span><svg /></button>\n"
        "      <button><i hidden>Save</i><svg /></button>\n"
        "      <button><svg hidden><title>Save</title></svg><svg /></button>\n"
        "      <button><img hidden alt=\"Save\" /><svg /></button>\n"
        "      <button><svg hidden><title>Save</title></svg></button>\n"
        "      <input type=\"text\" hidden />\n"
        "    </div>\n"
        "  );\n"
        "}\n",
    )
    tsx_res = TypeScriptNextJsAdapter().extract(tsx_root, ".")
    tsx_lines = sorted(f.line for f in tsx_res.findings if f.rule_code == "DISP-005")
    assert tsx_lines == [9, 12, 13, 14, 15], tsx_res.findings

    svelte_root = tmp_path / "svelte_app"
    put(
        svelte_root,
        "src/lib/IfLabel.svelte",
        "<script>\n"
        "  export let show = false;\n"
        "</script>\n"
        "{#if show}<span>Save</span>{/if}<svg />\n",
    )
    put(
        svelte_root,
        "src/lib/DynBothLabel.svelte",
        "<script>\n"
        "  export let dynamicFlag;\n"
        "</script>\n"
        "{#if dynamicFlag}<span>Save</span>{:else}<span>Done</span>{/if}\n",
    )
    put(
        svelte_root,
        "src/routes/+page.svelte",
        "<script>\n"
        "  import IfLabel from '$lib/IfLabel.svelte';\n"
        "  import DynBothLabel from '$lib/DynBothLabel.svelte';\n"
        "  export let dynamicFlag;\n"
        "</script>\n"
        "<button on:click={() => {}}><IfLabel on:click={() => {}} /></button>\n"
        "<button><IfLabel show /></button>\n"
        "<button><DynBothLabel /></button>\n"
        "<button>{#if false}<span>Save</span>{:else}<svg />{/if}</button>\n"
        "<button>{#if dynamicFlag}<span>Save</span>{:else}<svg />{/if}</button>\n"
        "<button>{#if dynamicFlag}<span>Save</span>{:else}<span>Done</span>{/if}</button>\n"
        "<button><svg><title hidden>Save</title></svg></button>\n",
    )
    svelte_res = SvelteKitDisplayAdapter().extract(svelte_root, ".")
    svelte_lines = sorted(f.line for f in svelte_res.findings if f.rule_code == "DISP-005")
    assert svelte_lines == [6, 9, 12], svelte_res.findings


def test_vue_conditional_rendering_and_svelte_raw_html_a11y(
    tmp_path: Path,
) -> None:
    """Verify Vue `v-if`/`v-else`/`v-show` visibility and Svelte `{@html ...}` markup parsing."""
    from app.adapters.sveltekit_display import SvelteKitDisplayAdapter
    from app.adapters.vue_sfc import VueSfcDisplayAdapter

    vue_root = tmp_path / "vue_conditionals"
    put(
        vue_root,
        "src/components/VIfFalse.vue",
        "<template><span v-if=\"false\">Save</span><svg /></template>\n",
    )
    put(
        vue_root,
        "src/components/VShowFalse.vue",
        "<template><span v-show=\"false\">Save</span><svg /></template>\n",
    )
    put(
        vue_root,
        "src/components/VIfDynamic.vue",
        "<script setup>defineProps(['dynamicFlag']);</script>\n"
        "<template><span v-if=\"dynamicFlag\">Save</span><svg /></template>\n",
    )
    put(
        vue_root,
        "src/components/VShowDynamic.vue",
        "<script setup>defineProps(['dynamicFlag']);</script>\n"
        "<template><span v-show=\"dynamicFlag\">Save</span><svg /></template>\n",
    )
    put(
        vue_root,
        "src/components/VIfElseBoth.vue",
        "<script setup>defineProps(['dynamicFlag']);</script>\n"
        "<template><span v-if=\"dynamicFlag\">Save</span><span v-else>Done</span><svg /></template>\n",
    )
    put(
        vue_root,
        "src/components/VIfPropShow.vue",
        "<script setup>defineProps({ show: { default: false } });</script>\n"
        "<template><span v-if=\"show\">Save</span><svg v-else /></template>\n",
    )
    put(
        vue_root,
        "src/App.vue",
        "<script setup>\n"
        "import VIfFalse from './components/VIfFalse.vue';\n"
        "import VShowFalse from './components/VShowFalse.vue';\n"
        "import VIfDynamic from './components/VIfDynamic.vue';\n"
        "import VShowDynamic from './components/VShowDynamic.vue';\n"
        "import VIfElseBoth from './components/VIfElseBoth.vue';\n"
        "import VIfPropShow from './components/VIfPropShow.vue';\n"
        "</script>\n"
        "<template>\n"
        "  <button><VIfFalse /></button>\n"
        "  <button><VShowFalse /></button>\n"
        "  <button><VIfDynamic :dynamic-flag=\"cond\" /></button>\n"
        "  <button><VShowDynamic :dynamic-flag=\"cond\" /></button>\n"
        "  <button><VIfElseBoth :dynamic-flag=\"cond\" /></button>\n"
        "  <button><VIfPropShow /></button>\n"
        "  <button><VIfPropShow show /></button>\n"
        "  <button><span v-if=\"false\">Save</span><svg /></button>\n"
        "</template>\n",
    )
    vue_res = VueSfcDisplayAdapter().extract(vue_root, ".")
    vue_lines = sorted(f.line for f in vue_res.findings if f.rule_code == "DISP-005")
    assert vue_lines == [10, 11, 15, 17], vue_res.findings

    sv_root = tmp_path / "svelte_raw_html"
    put(sv_root, "src/lib/RawIcon.svelte", "{@html '<svg></svg>'}\n")
    put(sv_root, "src/lib/RawText.svelte", "{@html '<span>Save</span>'}<svg />\n")
    put(
        sv_root,
        "src/lib/RawDyn.svelte",
        "<script>export let rawHtml = '<span>Save</span>';</script>\n"
        "{@html rawHtml}<svg />\n",
    )
    put(sv_root, "src/lib/RawEmpty.svelte", "{@html ''}<svg />\n")
    put(
        sv_root,
        "src/routes/+page.svelte",
        "<script>\n"
        "  import RawIcon from '$lib/RawIcon.svelte';\n"
        "  import RawText from '$lib/RawText.svelte';\n"
        "  import RawDyn from '$lib/RawDyn.svelte';\n"
        "  import RawEmpty from '$lib/RawEmpty.svelte';\n"
        "  export let dynamicHtml;\n"
        "</script>\n"
        "<button><RawIcon /></button>\n"
        "<button><RawText /></button>\n"
        "<button><RawDyn /></button>\n"
        "<button><RawEmpty /></button>\n"
        "<button>{@html '<svg></svg>'}</button>\n"
        "<button>{@html dynamicHtml}<svg /></button>\n",
    )
    sv_res = SvelteKitDisplayAdapter().extract(sv_root, ".")
    sv_lines = sorted(f.line for f in sv_res.findings if f.rule_code == "DISP-005")
    assert sv_lines == [8, 11, 12], sv_res.findings



