"""Source-only regressions exposed by a pinned Open WebUI audit."""

from __future__ import annotations

import os
import subprocess
import sys
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
