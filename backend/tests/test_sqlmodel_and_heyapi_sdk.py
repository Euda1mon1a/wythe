"""Regression tests for SQLModel + nested Alembic (#32) and Hey API SDK lineage (#33)."""

from pathlib import Path

import pytest
from sqlalchemy.orm import Session

from app.adapters.postgres_sqlalchemy import PostgresSqlAlchemyAdapter
from app.adapters.typescript_react import TypeScriptReactSpaAdapter
from app.schemas.atlas import TargetProjectCreate
from app.services.governance_service import get_target_by_slug, register_target
from app.services.scanner_service import run_target_scan


def _write(root: Path, rel: str, content: str) -> None:
    p = root / rel
    p.parent.mkdir(parents=True, exist_ok=True)
    p.write_text(content, encoding="utf-8")


def test_sqlmodel_tables_inherited_columns_fks_and_nested_alembic(
    db_session: Session, tmp_path: Path
) -> None:
    _write(
        tmp_path,
        "backend/alembic.ini",
        "[alembic]\nscript_location = app/alembic\n",
    )
    _write(
        tmp_path,
        "backend/app/alembic/versions/0001_init.py",
        "revision = '0001'\ndown_revision = None\nfrom alembic import op\nimport sqlalchemy as sa\n"
        "def upgrade():\n"
        "    op.create_table('user', sa.Column('id', sa.Integer(), primary_key=True))\n"
        "    op.create_table('item', sa.Column('id', sa.Integer(), primary_key=True))\n",
    )
    _write(
        tmp_path,
        "backend/app/alembic/env.py",
        "target_metadata = None\n",
    )
    _write(
        tmp_path,
        "backend/app/models_base.py",
        "from sqlmodel import Field, SQLModel\n"
        "class ItemBase(SQLModel):\n"
        "    title: str = Field(max_length=255)\n"
        "    description: str | None = None\n",
    )
    _write(
        tmp_path,
        "backend/app/models.py",
        "from typing import ClassVar\n"
        "from sqlmodel import Field, Relationship, SQLModel\n"
        "from app.models_base import ItemBase\n"
        "class UserBase(SQLModel):\n"
        "    email: str\n"
        "class User(UserBase, table=True):\n"
        "    id: int | None = Field(default=None, primary_key=True)\n"
        "    items: list['Item'] = Relationship(back_populates='owner')\n"
        "class UserCreate(UserBase):\n"
        "    password: str\n"
        "class Item(ItemBase, table=True):\n"
        "    metadata_tag: ClassVar[str] = 'v1'\n"
        "    id: int | None = Field(default=None, primary_key=True)\n"
        "    owner_id: int = Field(foreign_key='user.id')\n",
    )
    _write(
        tmp_path,
        "backend/app/api/routes/items.py",
        "from fastapi import APIRouter\nfrom sqlmodel import select\n"
        "from app.models import Item\n"
        "router = APIRouter(prefix='/items')\n"
        "@router.get('/')\n"
        "def read_items(session):\n"
        "    return session.exec(select(Item)).all()\n"
        "@router.post('/')\n"
        "def create_item(session, payload):\n"
        "    item = Item.model_validate(payload)\n"
        "    session.add(item)\n"
        "    return item\n",
    )
    _write(
        tmp_path,
        "backend/app/main.py",
        "from fastapi import FastAPI\nfrom app.api.routes import items\n"
        "app = FastAPI()\napp.include_router(items.router, prefix='/api/v1')\n",
    )
    truth = PostgresSqlAlchemyAdapter().extract(tmp_path, "backend")
    by_id = {n.id: n for n in truth.nodes}
    assert set(by_id) == {"t:user", "t:item"}
    assert "email" in by_id["t:user"].columns and "id" in by_id["t:user"].columns
    assert {"title", "description", "id", "owner_id"} <= set(by_id["t:item"].columns)
    assert "items" not in by_id["t:item"].columns
    assert "metadata_tag" not in by_id["t:item"].columns
    assert not [f for f in truth.findings if f.rule_code == "TRUTH-002"]
    assert "t:item" in truth.db_readers.get("t:user", {})

    register_target(
        db_session,
        TargetProjectCreate(
            slug="sqlmodel-demo",
            name="SQLModel Demo",
            repo_path=str(tmp_path),
            stack_profile_slug="fastapi-sqlalchemy-nextjs",
        ),
    )
    report = run_target_scan(db_session, get_target_by_slug(db_session, "sqlmodel-demo"), persist_snapshot=False)
    edge_set = {(e.source_id, e.kind, e.target_id) for e in report.edges}
    assert ("m:route:api.routes.items", "reads_truth", "t:item") in edge_set
    assert ("m:route:api.routes.items", "writes_truth", "t:item") in edge_set
    assert not [f for f in report.findings if f.rule_code == "MANIP-003" and "alembic" in f.source_file]


def test_heyapi_object_requests_provenance_method_reachability_and_fallback(
    db_session: Session, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    _write(
        tmp_path,
        "backend/schema.sql",
        "CREATE TABLE items (id INTEGER PRIMARY KEY);\nCREATE TABLE users (id INTEGER PRIMARY KEY);\n",
    )
    _write(
        tmp_path,
        "backend/app/models.py",
        "from sqlmodel import Field, SQLModel\n"
        "class Items(SQLModel, table=True):\n"
        "    id: int | None = Field(default=None, primary_key=True)\n"
        "class Users(SQLModel, table=True):\n"
        "    id: int | None = Field(default=None, primary_key=True)\n",
    )
    _write(
        tmp_path,
        "backend/app/api/routes/items.py",
        "from fastapi import APIRouter\nfrom sqlmodel import select\nfrom app.models import Items\n"
        "router = APIRouter(prefix='/api/v1')\n"
        "@router.get('/items/')\n"
        "def list_items(session): return session.exec(select(Items)).all()\n"
        "@router.post('/items/')\n"
        "def create_item(session): session.add(Items(id=1))\n"
        "@router.delete('/items/{id}')\n"
        "def delete_item(session, id: int): session.delete(session.get(Items, id))\n",
    )
    _write(
        tmp_path,
        "backend/app/api/routes/utils.py",
        "from fastapi import APIRouter\n"
        "router = APIRouter(prefix='/api/v1')\n"
        "@router.post('/utils/test-email/')\n"
        "def test_email(): return {'ok': True}\n",
    )
    _write(
        tmp_path,
        "backend/app/api/routes/users.py",
        "from fastapi import APIRouter\nfrom sqlmodel import select\nfrom app.models import Users\n"
        "router = APIRouter(prefix='/api/v1')\n"
        "@router.get('/users/')\n"
        "def list_users(session): return session.exec(select(Users)).all()\n",
    )
    _write(
        tmp_path,
        "backend/app/main.py",
        "from fastapi import FastAPI\nfrom app.api.routes import items, users, utils\n"
        "app = FastAPI()\n"
        "app.include_router(items.router)\n"
        "app.include_router(users.router)\n"
        "app.include_router(utils.router)\n",
    )
    _write(tmp_path, "frontend/openapi-ts.config.ts", "export default { input: './openapi.json', output: './src/client' };\n")
    _write(tmp_path, "frontend/src/client/index.ts", "export { ItemsService, UsersService, UtilsService } from './sdk.gen';\n")
    _write(tmp_path, "frontend/src/client/types.gen.ts", "export type ItemOut = { id: number };\n")
    _write(
        tmp_path,
        "frontend/src/client/sdk.gen.ts",
        "// This file is auto-generated by @hey-api/openapi-ts\n"
        "import type { Options } from './types.gen';\n"
        "import { client } from './client.gen';\n"
        "export class ItemsService {\n"
        "  public static readItems<T>(options?: Options<T>) {\n"
        "    return (options?.client ?? client).get({ url: '/api/v1/items/', ...options });\n"
        "  }\n"
        "  public static createItem<T>(options: Options<T>) {\n"
        "    return (options?.client ?? client).post({ url: '/api/v1/items/', ...options });\n"
        "  }\n"
        "  public static deleteItem<T>(options: Options<T>) {\n"
        "    return (options?.client ?? client).delete({ url: '/api/v1/items/{id}', ...options });\n"
        "  }\n"
        "}\n"
        "export class UtilsService {\n"
        "  public static testEmail<T>(options?: Options<T>) {\n"
        "    return client.post({ url: '/api/v1/utils/test-email/', ...options });\n"
        "  }\n"
        "  public static overrideDynamic(pathVar: string) {\n"
        "    return client.get({ url: '/api/v1/items/', url: pathVar });\n"
        "  }\n"
        "}\n"
        "export class UsersService {\n"
        "  public static listUsers<T>(options?: Options<T>) {\n"
        "    return client.request({ method: 'get', url: '/api/v1/users/' });\n"
        "  }\n"
        "}\n"
        "trackTelemetry({ url: '/should/not/be-http' });\n",
    )
    _write(tmp_path, "frontend/src/client/client.gen.ts", "export const client = {};\n")
    _write(tmp_path, "frontend/src/client/rawApi.ts", "export const loadRaw = () => fetch('/api/v1/items/');\n")
    _write(
        tmp_path,
        "frontend/src/routes/_layout/items.tsx",
        "import { ItemsService } from '@/client';\n"
        "import { loadRaw } from '@/client/rawApi';\n"
        "export function ItemsPage() {\n"
        "  loadRaw();\n"
        "  ItemsService.deleteItem({ path: { id: 1 } });\n"
        "  return ItemsService.readItems({ query: { skip: 0 } });\n"
        "}\n",
    )
    _write(
        tmp_path,
        "frontend/src/routes/_layout/users.tsx",
        "import { UsersService } from '@/client';\n"
        "export function UsersPage() { return UsersService.listUsers(); }\n",
    )

    disp = TypeScriptReactSpaAdapter().extract(tmp_path, "frontend")
    calls_by_sym = {c.caller_symbol: c for c in disp.http_calls if c.source_file.endswith("sdk.gen.ts")}
    assert calls_by_sym["ItemsService.readItems"].http_method == "GET"
    assert calls_by_sym["ItemsService.readItems"].reachable is True
    assert calls_by_sym["ItemsService.createItem"].reachable is False
    assert calls_by_sym["ItemsService.deleteItem"].reachable is True
    assert calls_by_sym["UtilsService.testEmail"].reachable is False
    assert "UtilsService.overrideDynamic" not in calls_by_sym
    assert "/should/not/be-http" not in {c.raw_path for c in disp.http_calls}
    assert calls_by_sym["UsersService.listUsers"].http_method == "GET"
    assert calls_by_sym["UsersService.listUsers"].reachable is True
    disp003 = [f for f in disp.findings if f.rule_code == "DISP-003"]
    assert {f.source_file for f in disp003} == {"frontend/src/client/rawApi.ts"}

    register_target(
        db_session,
        TargetProjectCreate(
            slug="heyapi-demo",
            name="HeyAPI Demo",
            repo_path=str(tmp_path),
            stack_profile_slug="fastapi-react-spa",
        ),
    )
    report = run_target_scan(db_session, get_target_by_slug(db_session, "heyapi-demo"), persist_snapshot=False)
    chain_pairs = {(c.display_node_id, c.http_method, c.http_path) for c in report.chains}
    assert ("d:page:routes._layout.items", "GET", "/api/v1/items") in chain_pairs
    assert ("d:page:routes._layout.items", "DELETE", "/api/v1/items/{id}") in chain_pairs
    assert ("d:page:routes._layout.users", "GET", "/api/v1/users") in chain_pairs
    assert ("d:page:routes._layout.items", "POST", "/api/v1/items") not in chain_pairs
    assert ("d:page:routes._layout.items", "GET", "/api/v1/users") not in chain_pairs
    decl_edges = [e for e in report.edges if e.verification == "declared" and e.target_id.startswith("m:route:")]
    assert any("test-email" in e.evidence_note for e in decl_edges)
    items_mut = next(
        e for e in report.edges if e.target_id == "m:route:api.routes.items" and e.kind == "mutates_endpoint"
    )
    assert items_mut.verification == "verified"

    monkeypatch.setenv("WYTHE_DISABLE_TREESITTER", "1")
    fallback_disp = TypeScriptReactSpaAdapter().extract(tmp_path, "frontend")
    fb_calls = [
        (c.caller_symbol, c.http_method, c.normalized_path, c.reachable)
        for c in fallback_disp.http_calls
        if c.source_file.endswith("sdk.gen.ts")
    ]
    assert ("ItemsService", "GET", "/api/v1/items", True) in fb_calls
    assert ("ItemsService", "DELETE", "/api/v1/items/{id}", True) in fb_calls
    assert not any(sym == "UtilsService" and path == "/api/v1/items" and m == "GET" for sym, m, path, _ in fb_calls)


def test_pinned_full_stack_fastapi_template_corpus_lineage(db_session: Session) -> None:
    corpus_repo = Path("/private/tmp/wythe-corpus-20261113/full-stack-fastapi-template")
    if not corpus_repo.is_dir():
        pytest.skip("Pinned full-stack-fastapi-template corpus checkout not present")
    register_target(
        db_session,
        TargetProjectCreate(
            slug="fst-corpus",
            name="FastAPI Template",
            repo_path=str(corpus_repo),
            stack_profile_slug="fastapi-react-spa",
        ),
    )
    report = run_target_scan(db_session, get_target_by_slug(db_session, "fst-corpus"), persist_snapshot=False)
    nodes_by_id = {n.id: n for n in report.nodes}
    assert {"t:user", "t:item"} <= set(nodes_by_id)
    assert "email" in nodes_by_id["t:user"].columns
    assert {"title", "owner_id"} <= set(nodes_by_id["t:item"].columns)
    assert not [f for f in report.findings if f.rule_code == "TRUTH-002"]
    assert not [f for f in report.findings if f.rule_code == "DISP-003"]
    assert any(c.display_node_id == "d:page:routes._layout.items" and c.http_method == "GET" and "t:item" in c.truth_table_ids for c in report.chains)
    assert not any(c.display_node_id == "d:page:routes._layout.items" and "/utils/" in c.http_path for c in report.chains)
