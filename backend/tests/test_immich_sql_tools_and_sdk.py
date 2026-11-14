"""Tests for @immich/sql-tools Truth extraction, inherited NestJS DI, and @immich/sdk lineage."""

from __future__ import annotations

from pathlib import Path

import pytest
from sqlalchemy.orm import Session

from app.adapters.autodetect import detect_repository_stack
from app.models import TargetProject
from app.services.scanner_service import run_target_scan

PINNED_IMMICH_DIR = Path("/private/tmp/wythe-corpus-20261113/immich")


def _target(repo: Path, slug: str, profile: str, be: str = "server", fe: str = "web") -> TargetProject:
    return TargetProject(
        id=0,
        slug=slug,
        name=slug,
        repo_path=str(repo),
        stack_profile_slug=profile,
        backend_subdir=be,
        frontend_subdir=fe,
        description=slug,
        is_active=True,
    )


def _write_immich_shaped_fixture(repo: Path) -> None:
    for d in (
        repo / "machine-learning",
        repo / "server" / "src" / "schema" / "tables",
        repo / "server" / "src" / "repositories",
        repo / "server" / "src" / "services",
        repo / "server" / "src" / "controllers",
        repo / "packages" / "sdk" / "src",
        repo / "web" / "src" / "lib" / "managers",
        repo / "web" / "src" / "lib" / "services",
        repo / "web" / "src" / "routes" / "(user)" / "explore",
        repo / "web" / "src" / "routes" / "(user)" / "albums",
        repo / "web" / "src" / "routes" / "(user)" / "untyped",
    ):
        d.mkdir(parents=True, exist_ok=True)

    (repo / "package.json").write_text('{"name": "immich-monorepo", "private": true}', encoding="utf-8")
    (repo / "machine-learning" / "pyproject.toml").write_text(
        '[project]\nname = "immich-ml"\nversion = "0.1.0"\n',
        encoding="utf-8",
    )
    (repo / "server" / "package.json").write_text(
        '{"dependencies": {"@nestjs/common": "^10.0.0", "@immich/sql-tools": "^0.1.0", "kysely": "^0.27.0"}}',
        encoding="utf-8",
    )
    (repo / "server" / "src" / "app.common.ts").write_text(
        "export async function configureApp(app: any) { app.setGlobalPrefix('api'); }\n",
        encoding="utf-8",
    )
    (repo / "server" / "src" / "enum.ts").write_text(
        "export enum RouteKey {\n  Asset = 'assets',\n  Album = 'albums',\n}\n",
        encoding="utf-8",
    )
    (repo / "server" / "src" / "schema" / "functions.ts").write_text(
        "import { registerFunction } from '@immich/sql-tools';\n"
        "export const immichUuidV7 = registerFunction({ name: 'immich_uuid_v7', args: [], returns: 'uuid' });\n",
        encoding="utf-8",
    )
    (repo / "server" / "src" / "schema" / "tables" / "asset.table.ts").write_text(
        "import {\n"
        "  Check,\n"
        "  Column,\n"
        "  ForeignKeyColumn,\n"
        "  Index,\n"
        "  PrimaryGeneratedUuidV7Column,\n"
        "  Table,\n"
        "  Unique,\n"
        "  UpdatedAtTrigger,\n"
        "} from '@immich/sql-tools';\n"
        "import { immichUuidV7 } from '../functions';\n"
        "export class NonTableHelper { label = 'skip'; }\n"
        "@Table('asset')\n"
        "@Index({ name: 'idx_asset_owner', columns: ['ownerId'] })\n"
        "@Unique({ name: 'uq_asset_checksum', columns: ['ownerId', 'checksum'] })\n"
        "@Check({ name: 'chk_asset_type', expression: \"type IN ('IMAGE', 'VIDEO')\" })\n"
        "@UpdatedAtTrigger({ name: 'trg_asset_updated', function: immichUuidV7 })\n"
        "export class AssetTable {\n"
        "  @PrimaryGeneratedUuidV7Column()\n  id!: string;\n"
        "  @ForeignKeyColumn(() => UserTable)\n  ownerId!: string;\n"
        "  @Column()\n  checksum!: string;\n"
        "}\n"
        "@Table({ name: 'album' })\n"
        "export class AlbumTable {\n"
        "  @PrimaryGeneratedUuidV7Column()\n  id!: string;\n"
        "  @Column()\n  albumName!: string;\n"
        "}\n"
        "@Table('user')\n"
        "export class UserTable {\n"
        "  @PrimaryGeneratedUuidV7Column()\n  id!: string;\n"
        "}\n"
        "const dynamicExpr = buildExpr();\n"
        "@Table('asset_face')\n"
        "@Check({ name: 'chk_dynamic', expression: dynamicExpr })\n"
        "export class AssetFaceTable {\n"
        "  @PrimaryGeneratedUuidV7Column()\n  id!: string;\n"
        "}\n",
        encoding="utf-8",
    )
    (repo / "server" / "src" / "repositories" / "asset.repository.ts").write_text(
        "export class AssetRepository {\n"
        "  getById(id: string) { return db.selectFrom('asset').selectAll().where('id', '=', id).executeTakeFirst(); }\n"
        "  updateMany(ids: string[]) { return db.updateTable('asset').set({ id: ids[0] }).execute(); }\n"
        "}\n",
        encoding="utf-8",
    )
    (repo / "server" / "src" / "repositories" / "album.repository.ts").write_text(
        "export class AlbumRepository {\n"
        "  getById(id: string) { return db.selectFrom('album').selectAll().where('id', '=', id).executeTakeFirst(); }\n"
        "}\n",
        encoding="utf-8",
    )
    (repo / "server" / "src" / "services" / "base.service.ts").write_text(
        "import { AssetRepository } from '../repositories/asset.repository';\n"
        "import { AlbumRepository } from '../repositories/album.repository';\n"
        "export const BASE_SERVICE_DEPENDENCIES = [AssetRepository, AlbumRepository];\n"
        "export class BaseService {\n"
        "  constructor(\n"
        "    protected assetRepository: AssetRepository,\n"
        "    protected albumRepository: AlbumRepository,\n"
        "  ) {}\n"
        "}\n",
        encoding="utf-8",
    )
    (repo / "server" / "src" / "services" / "asset.service.ts").write_text(
        "import { BaseService } from './base.service';\n"
        "export class AssetService extends BaseService {\n"
        "  getAsset(id: string) { return this.assetRepository.getById(id); }\n"
        "  updateMany(ids: string[]) { return this.assetRepository.updateMany(ids); }\n"
        "}\n",
        encoding="utf-8",
    )
    (repo / "server" / "src" / "controllers" / "asset.controller.ts").write_text(
        "import { Controller, Get, Put } from '@nestjs/common';\n"
        "import { RouteKey } from '../enum';\n"
        "import { AssetService } from '../services/asset.service';\n"
        "@Controller(RouteKey.Asset)\n"
        "export class AssetController {\n"
        "  constructor(private service: AssetService) {}\n"
        "  @Get(':id')\n  getAssetInfo(id: string) { return this.service.getAsset(id); }\n"
        "  @Put()\n  updateAssets(ids: string[]) { return this.service.updateMany(ids); }\n"
        "}\n"
        "const dynamicControllerPrefix = getPrefix();\n"
        "@Controller(dynamicControllerPrefix)\n"
        "export class UnresolvedPrefixController {\n"
        "  @Get('ping')\n  ping() { return 'ok'; }\n"
        "}\n",
        encoding="utf-8",
    )
    (repo / "packages" / "sdk" / "package.json").write_text(
        '{"name": "@immich/sdk", "main": "./build/index.js"}',
        encoding="utf-8",
    )
    (repo / "packages" / "sdk" / "src" / "index.ts").write_text(
        "export * from './fetch-client.js';\n"
        "export function buildSharePath(id: string) {\n"
        "  return `/share/${id}`;\n"
        "}\n",
        encoding="utf-8",
    )
    (repo / "packages" / "sdk" / "src" / "fetch-client.ts").write_text(
        'import * as Oazapfts from "@oazapfts/runtime";\n'
        'import * as QS from "@oazapfts/runtime/query";\n'
        'export const defaults = { headers: {}, baseUrl: "/api" };\n'
        "const oazapfts = Oazapfts.runtime(defaults);\n"
        "export type AssetResponseDto = { id: string };\n"
        "export function getAssetInfo({ id, key }: { id: string; key?: string }, opts?: Oazapfts.RequestOpts) {\n"
        "  return oazapfts.fetchJson<{\n"
        "    status: 200;\n"
        "    data: AssetResponseDto;\n"
        "  } | {\n"
        "    status: 400;\n"
        "    data: unknown;\n"
        "  }>(`/assets/${encodeURIComponent(id)}${QS.query(QS.explode({\n"
        "    key,\n"
        "  }))}`, {\n"
        "    ...opts,\n"
        "  });\n"
        "}\n"
        "export function updateAssets({ dto }: { dto: unknown }, opts?: Oazapfts.RequestOpts) {\n"
        '  return oazapfts.fetchJson<{ status: 204 }>("/assets", oazapfts.json({\n'
        "    ...opts,\n"
        '    method: "PUT",\n'
        "    body: dto,\n"
        "  }));\n"
        "}\n"
        "export function deleteAsset({ id }: { id: string }, opts?: Oazapfts.RequestOpts) {\n"
        "  return oazapfts.fetchJson<{ status: 204 }>(`/assets/${id}`, {\n"
        "    ...opts,\n"
        '    method: "DELETE",\n'
        "  });\n"
        "}\n",
        encoding="utf-8",
    )
    (repo / "web" / "package.json").write_text(
        '{"dependencies": {"@sveltejs/kit": "^2.0.0", "svelte": "^5.0.0"}}',
        encoding="utf-8",
    )
    (repo / "web" / "tsconfig.json").write_text(
        '{"compilerOptions": {"baseUrl": ".", "paths": {"#lib/*": ["src/lib/*"]}}}',
        encoding="utf-8",
    )
    (repo / "web" / "src" / "lib" / "managers" / "asset-manager.ts").write_text(
        "export const ASSET_STATE = 'ready';\n",
        encoding="utf-8",
    )
    (repo / "web" / "src" / "lib" / "services" / "asset.service.ts").write_text(
        "import { ASSET_STATE } from '#lib/managers/asset-manager';\n"
        "export const assetLabel = ASSET_STATE;\n",
        encoding="utf-8",
    )
    (repo / "web" / "src" / "routes" / "(user)" / "explore" / "+page.svelte").write_text(
        '<script lang="ts">\n'
        "  import { getAssetInfo, updateAssets, type AssetResponseDto } from '@immich/sdk';\n"
        "  import { assetLabel } from '#lib/services/asset.service';\n"
        "  let asset: AssetResponseDto | null = null;\n"
        "  async function load(id: string) {\n"
        "    asset = await getAssetInfo({ id });\n"
        "    await updateAssets({ dto: { ids: [id] } });\n"
        "  }\n"
        "</script>\n"
        "<button type=\"button\" onclick={() => load(assetLabel)}>Go</button>\n",
        encoding="utf-8",
    )
    (repo / "web" / "src" / "routes" / "(user)" / "albums" / "+page.svelte").write_text(
        '<script lang="ts">\n'
        "  import type { AssetResponseDto } from '@immich/sdk';\n"
        "  import { deleteAsset, buildSharePath } from '@immich/sdk';\n"
        "  const url = buildSharePath('123');\n"
        "</script>\n"
        "<p>{url}</p>\n",
        encoding="utf-8",
    )
    (repo / "web" / "src" / "routes" / "(user)" / "untyped" / "+page.svelte").write_text(
        '<script lang="ts">\n'
        "  async function pingRaw() {\n"
        "    return fetch('/api/raw-untyped');\n"
        "  }\n"
        "</script>\n"
        "<button type=\"button\" onclick={pingRaw}>Ping</button>\n",
        encoding="utf-8",
    )


@pytest.mark.parametrize("disable_ts", ["0", "1"])
def test_immich_sql_tools_inherited_di_and_sdk_lineage(
    monkeypatch: pytest.MonkeyPatch,
    db_session: Session,
    tmp_path: Path,
    disable_ts: str,
) -> None:
    """Verify @immich/sql-tools Truth, inherited NestJS DI precision, #lib/ resolution, and @immich/sdk lineage."""
    if disable_ts == "1":
        monkeypatch.setenv("WYTHE_DISABLE_TREESITTER", "1")
    else:
        monkeypatch.delenv("WYTHE_DISABLE_TREESITTER", raising=False)

    repo = tmp_path / "immich_shaped"
    _write_immich_shaped_fixture(repo)

    det = detect_repository_stack(db_session, str(repo))
    assert det.recommended_profile_slug == "node-sql-tools-sveltekit"
    assert det.truth_adapter == "sql-tools"
    assert det.manipulator_adapter == "typescript-node"
    assert det.display_adapter == "sveltekit"
    assert det.coverage_complete is True

    result = run_target_scan(
        db_session,
        _target(repo, "immich-syn", det.recommended_profile_slug, det.backend_subdir, det.frontend_subdir),
    )

    node_by_id = {n.id: n for n in result.nodes}
    assert "t:asset" in node_by_id
    assert {"id", "ownerId", "checksum"}.issubset(set(node_by_id["t:asset"].columns))
    assert "t:album" in node_by_id
    assert "t:user" in node_by_id
    assert "t:asset_face" in node_by_id
    assert not any("NonTableHelper" in n.label or "non_table_helper" in n.id for n in result.nodes)
    assert any(n.tier == "truth" and n.subkind == "sql_function" and "immich_uuid_v7" in n.label for n in result.nodes)

    edge_pairs = {(e.source_id, e.target_id) for e in result.edges}
    assert ("t:asset", "t:user") in edge_pairs
    assert ("fn:immich_uuid_v7", "t:asset") in edge_pairs
    svc_id = next(n.id for n in result.nodes if n.tier == "manipulate" and "asset.service" in n.source_file)
    album_repo_id = next(n.id for n in result.nodes if n.tier == "manipulate" and "album.repository" in n.source_file)
    asset_repo_id = next(n.id for n in result.nodes if n.tier == "manipulate" and "asset.repository" in n.source_file)
    assert (svc_id, asset_repo_id) in edge_pairs
    assert (asset_repo_id, "t:asset") in edge_pairs
    assert (svc_id, album_repo_id) not in edge_pairs
    assert (svc_id, "t:album") not in edge_pairs

    fe_service_id = next(
        n.id for n in result.nodes if n.tier == "display" and "lib/services/asset.service.ts" in n.source_file
    )
    fe_mgr_id = next(
        n.id for n in result.nodes if n.tier == "display" and "lib/managers/asset-manager.ts" in n.source_file
    )
    explore_id = next(n.id for n in result.nodes if n.tier == "display" and "explore/+page.svelte" in n.source_file)
    albums_id = next(n.id for n in result.nodes if n.tier == "display" and "albums/+page.svelte" in n.source_file)
    assert node_by_id[fe_service_id].subkind == "api_client"
    assert node_by_id[fe_mgr_id].subkind == "hook"
    assert (explore_id, fe_service_id) in edge_pairs
    assert (fe_service_id, fe_mgr_id) in edge_pairs

    assert any(
        c.display_node_id == explore_id and c.http_method == "GET" and "t:asset" in c.truth_table_ids
        for c in result.chains
    )
    assert any(
        c.display_node_id == explore_id and c.http_method == "PUT" and "t:asset" in c.truth_table_ids
        for c in result.chains
    )
    assert not any(c.display_node_id == albums_id for c in result.chains)

    disp004_files = {f.source_file for f in result.findings if f.rule_code == "DISP-004"}
    assert not any("explore/+page.svelte" in sf or "albums/+page.svelte" in sf for sf in disp004_files)
    assert any("untyped/+page.svelte" in sf for sf in disp004_files)
    notes_blob = "\n".join(result.scan_notes)
    assert "Unresolved @Check expression" in notes_blob
    assert "Unresolved @Controller prefix expression" in notes_blob
    assert all("/assets/ping" not in n.http_paths for n in result.nodes if n.subkind == "route")
    assert not any(f.rule_code == "MANIP-003" and "server/src/schema/" in f.source_file for f in result.findings)


def test_sql_tools_catalog_probe_truth_002(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    """Emit TRUTH-002 only when pg_dsn catalog probe runs and finds schema tables missing from live DB."""
    from app.adapters.sql_tools_truth import SqlToolsSchemaAdapter

    repo = tmp_path / "immich_probe"
    _write_immich_shaped_fixture(repo)

    no_dsn = SqlToolsSchemaAdapter().extract(repo, "server", pg_dsn=None)
    assert not any(f.rule_code == "TRUTH-002" for f in no_dsn.findings)

    monkeypatch.setattr(
        "app.adapters.sql_tools_truth.probe_live_catalog_tables",
        lambda _dsn: (frozenset({"user", "album"}), "pg_catalog_live"),
    )
    with_dsn = SqlToolsSchemaAdapter().extract(repo, "server", pg_dsn="postgresql://stub/db")
    missing_nodes = {f.node_id for f in with_dsn.findings if f.rule_code == "TRUTH-002"}
    assert {"t:asset", "t:asset_face"} == missing_nodes


@pytest.mark.skipif(not PINNED_IMMICH_DIR.is_dir(), reason="pinned immich corpus checkout not present")
def test_immich_pinned_corpus_end_to_end(db_session: Session) -> None:
    """Validate pinned Immich corpus scan: sql-tools Truth, inherited DI, #lib/, and @immich/sdk chains."""
    det = detect_repository_stack(db_session, str(PINNED_IMMICH_DIR))
    assert det.recommended_profile_slug == "node-sql-tools-sveltekit"
    assert det.truth_adapter == "sql-tools"
    assert det.manipulator_adapter == "typescript-node"
    assert det.display_adapter == "sveltekit"
    assert det.coverage_complete is True

    result = run_target_scan(
        db_session,
        _target(PINNED_IMMICH_DIR, "immich-corpus", det.recommended_profile_slug, det.backend_subdir, det.frontend_subdir),
    )
    assert result.summary.truth_tables >= 65
    assert result.summary.sql_functions >= 20
    assert len(result.chains) == 300
    assert any(c.http_path == "/assets/{id}" and "t:asset" in c.truth_table_ids for c in result.chains)
    assert any("explore/+page.svelte" in (e.evidence_path or "") and "/api/assets" in e.evidence_note for e in result.edges)
