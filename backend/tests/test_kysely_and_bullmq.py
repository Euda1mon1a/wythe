"""Tests for Kysely SchemaBuilder migrations, query lineage, TS call graphs, and NestJS BullMQ queues."""

from __future__ import annotations

from pathlib import Path

import pytest
from sqlalchemy.orm import Session

from app.adapters.autodetect import detect_repository_stack
from app.adapters.kysely_schema import KyselySchemaAdapter
from app.models import TargetProject
from app.services.scanner_service import run_target_scan


def _make_target(repo: Path, slug: str, profile: str, be: str = "apps/server", fe: str = "apps/client") -> TargetProject:
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


@pytest.mark.parametrize("disable_ts", ["0", "1"])
def test_kysely_migrations_camel_case_cte_and_negative_controls(
    monkeypatch: pytest.MonkeyPatch,
    db_session: Session,
    tmp_path: Path,
    disable_ts: str,
) -> None:
    """Replay up() only, handle alter/drop/CTE/CamelCasePlugin, and reject unrelated selectFrom."""
    if disable_ts == "1":
        monkeypatch.setenv("WYTHE_DISABLE_TREESITTER", "1")
    else:
        monkeypatch.delenv("WYTHE_DISABLE_TREESITTER", raising=False)

    repo = tmp_path / "kysely_app"
    mig_dir = repo / "apps" / "server" / "src" / "database" / "migrations"
    repo_dir = repo / "apps" / "server" / "src" / "repos"
    ctrl_dir = repo / "apps" / "server" / "src" / "controllers"
    fe_dir = repo / "apps" / "client" / "src" / "pages"
    for d in (mig_dir, repo_dir, ctrl_dir, fe_dir):
        d.mkdir(parents=True)

    (repo / "apps" / "server" / "package.json").write_text(
        '{"dependencies": {"@nestjs/common": "^10.0.0", "kysely": "^0.27.0"}}',
        encoding="utf-8",
    )
    (repo / "apps" / "client" / "package.json").write_text(
        '{"dependencies": {"react": "^18.3.0"}}',
        encoding="utf-8",
    )
    (repo / "apps" / "server" / "tsconfig.json").write_text(
        '{\n  // JSONC comment\n  "compilerOptions": {\n    "baseUrl": "./",\n    "paths": { "@db/*": ["./src/database/*"], },\n  },\n}\n',
        encoding="utf-8",
    )
    (repo / "apps" / "server" / "src" / "database" / "database.module.ts").write_text(
        "import { CamelCasePlugin } from 'kysely';\nexport const dbCfg = { plugins: [new CamelCasePlugin()] };\n",
        encoding="utf-8",
    )

    (mig_dir / "001_init.ts").write_text(
        """
import { Kysely, sql } from 'kysely';
async function createHelper(db: Kysely<any>) {
  await db.schema.createTable('helper_items').addColumn('id', 'uuid').execute();
}
async function neverCalledHelper(db: Kysely<any>) {
  await db.schema.createTable('ghost_uncalled').addColumn('id', 'uuid').execute();
}
export async function up(db: Kysely<any>): Promise<void> {
  await sql`CREATE OR REPLACE FUNCTION touch_updated() RETURNS trigger AS $$ BEGIN RETURN NEW; END; $$ LANGUAGE plpgsql;`.execute(db);
  await db.schema
    .createTable('pages')
    .addColumn('id', 'uuid', (col) => col.primaryKey())
    .addColumn('title', 'text')
    .execute();
  await db.schema
    .createTable('draft_verifications')
    .addColumn('id', 'uuid', (col) => col.references('pages.id'))
    .addColumn('old_col', 'text')
    .execute();
  await db.schema.createTable('temp_scratch').addColumn('id', 'uuid').execute();
  await db.schema.dropTable('temp_scratch').execute();
  await createHelper(db);
}
export async function down(db: Kysely<any>): Promise<void> {
  await db.schema.dropTable('pages').execute();
  await db.schema.dropTable('draft_verifications').execute();
}
""".lstrip(),
        encoding="utf-8",
    )
    (mig_dir / "002_alter.ts").write_text(
        """
import { Kysely } from 'kysely';
export async function up(db: Kysely<any>): Promise<void> {
  await db.schema.alterTable('draft_verifications').addColumn('reviewed_at', 'timestamp').execute();
  await db.schema.alterTable('draft_verifications').dropColumn('old_col').execute();
  await db.schema.alterTable('draft_verifications').renameColumn('id', 'page_id').execute();
  await db.schema.alterTable('draft_verifications').renameTo('page_verifications').execute();
}
""".lstrip(),
        encoding="utf-8",
    )

    # Repo uses CTE + CamelCasePlugin table name + dynamic unresolved table
    (repo_dir / "page.repo.ts").write_text(
        """
import { Kysely } from 'kysely';
export class PageRepo {
  constructor(private readonly db: Kysely<any>) {}
  async listPages(dynTbl: string) {
    await this.db
      .withRecursive('tree_cte', (qb) => qb.selectFrom('pages').select('id'))
      .selectFrom('tree_cte')
      .selectAll()
      .execute();
    await this.db.selectFrom('pageVerifications').selectAll().execute();
    await this.db.insertInto('pages').values({ title: 'x' }).execute();
    await this.db.selectFrom(dynTbl).selectAll().execute();
  }
}
""".lstrip(),
        encoding="utf-8",
    )
    # Negative control: non-Kysely object with .selectFrom()
    (repo_dir / "menu.helper.ts").write_text(
        """
export const buildMenu = (menu: any) => menu.selectFrom('pages');
""".lstrip(),
        encoding="utf-8",
    )
    (repo_dir / "unused.service.ts").write_text(
        "export class UnusedService { ping() { return 'unused'; } }\n",
        encoding="utf-8",
    )
    (repo_dir / "type_only.ts").write_text(
        "export class OnlyTypeDto { name = 'dto'; }\n",
        encoding="utf-8",
    )
    (ctrl_dir / "page.controller.ts").write_text(
        """
import { Controller, Get, Post } from '@nestjs/common';
import type { OnlyTypeDto } from '../repos/type_only';
import { UnusedService } from '../repos/unused.service';
import { PageRepo } from '../repos/page.repo';
import { buildMenu } from '../repos/menu.helper';

@Controller('pages')
export class PageController {
  constructor(
    private readonly pageRepo: PageRepo,
    private readonly unusedSvc: UnusedService,
  ) {}
  @Get('list')
  list(dto: OnlyTypeDto) {
    return dto ? this.pageRepo.listPages('pages') : buildMenu({});
  }
  @Post('create')
  create() {
    return this.pageRepo.listPages('pages');
  }
}
""".lstrip(),
        encoding="utf-8",
    )
    (fe_dir / "PagesView.tsx").write_text(
        """
export function PagesView() {
  void fetch('/api/pages/list');
  return <main><h1>Pages</h1></main>;
}
""".lstrip(),
        encoding="utf-8",
    )

    det = detect_repository_stack(db_session, str(repo))
    assert det.truth_adapter == "kysely-migrations"
    assert det.recommended_profile_slug == "node-kysely-react"

    rep = run_target_scan(
        db_session,
        _make_target(repo, "kysely-app", det.recommended_profile_slug),
        strict_gate=False,
        persist_snapshot=False,
    )
    node_map = {n.id: n for n in rep.nodes}
    assert "t:pages" in node_map
    assert "t:page_verifications" in node_map
    assert "t:draft_verifications" not in node_map
    assert "t:temp_scratch" not in node_map
    assert "t:ghost_uncalled" not in node_map
    assert "t:helper_items" in node_map
    assert "fn:touch_updated" in node_map
    pv_cols = node_map["t:page_verifications"].columns
    assert "page_id" in pv_cols
    assert "reviewed_at" in pv_cols
    assert "old_col" not in pv_cols
    assert "t:tree_cte" not in node_map

    repo_edges = {(e.kind, e.target_id, e.verification) for e in rep.edges if e.source_id == "m:service:src.repos.page.repo"}
    assert ("reads_truth", "t:pages", "verified") in repo_edges
    assert ("reads_truth", "t:page_verifications", "verified") in repo_edges
    assert ("writes_truth", "t:pages", "verified") in repo_edges

    menu_db_edges = [e for e in rep.edges if e.source_id == "m:service:src.repos.menu.helper" and e.kind in ("reads_truth", "writes_truth")]
    assert menu_db_edges == []

    # Type-only excluded, uninvoked DI is `declared` (and triggers MANIP-003), used DI is `verified`
    ctrl_edges = {(e.target_id, e.kind, e.verification) for e in rep.edges if e.source_id == "m:route:src.controllers.page.controller"}
    assert not any(tgt == "m:service:src.repos.type_only" for tgt, _, _ in ctrl_edges)
    assert ("m:service:src.repos.unused.service", "calls_helper", "declared") in ctrl_edges
    assert ("m:service:src.repos.page.repo", "calls_helper", "verified") in ctrl_edges
    assert any(f.rule_code == "MANIP-003" and f.node_id == "m:service:src.repos.unused.service" for f in rep.findings)
    assert any("Unresolved dynamic Kysely table expression" in n for n in rep.scan_notes)
    assert any(c.verified and c.http_path == "/pages/list" and "t:pages" in c.truth_table_ids for c in rep.chains)

    # Without CamelCasePlugin, camelCase query does NOT map to snake_case table
    (repo / "apps" / "server" / "src" / "database" / "database.module.ts").unlink()
    no_camel_truth = KyselySchemaAdapter().extract(repo, "apps/server")
    assert "page_verifications" in no_camel_truth.table_symbol_map
    assert "pageVerifications" not in no_camel_truth.table_symbol_map


@pytest.mark.parametrize("disable_ts", ["0", "1"])
def test_nestjs_bullmq_queues_hash_tags_barrels_and_negative_controls(
    monkeypatch: pytest.MonkeyPatch,
    db_session: Session,
    tmp_path: Path,
    disable_ts: str,
) -> None:
    """Resolve BullMQ @Processor, @InjectQueue + .add(), hash-tag separation, and negative controls."""
    if disable_ts == "1":
        monkeypatch.setenv("WYTHE_DISABLE_TREESITTER", "1")
    else:
        monkeypatch.delenv("WYTHE_DISABLE_TREESITTER", raising=False)

    repo = tmp_path / "bullmq_app"
    q_dir = repo / "apps" / "server" / "src" / "integrations" / "queue"
    for sub in ("constants", "processors"):
        (q_dir / sub).mkdir(parents=True)
    (repo / "apps" / "server" / "src" / "database" / "migrations").mkdir(parents=True)
    (repo / "apps" / "server" / "src" / "controllers").mkdir(parents=True)
    (repo / "apps" / "server" / "src" / "services").mkdir(parents=True)
    (repo / "apps" / "client" / "src").mkdir(parents=True)

    (repo / "apps" / "server" / "package.json").write_text(
        '{"dependencies": {"@nestjs/common": "^10.0.0", "@nestjs/bullmq": "^10.0.0", "bullmq": "^5.0.0", "kysely": "^0.27.0"}}',
        encoding="utf-8",
    )
    (repo / "apps" / "client" / "package.json").write_text(
        '{"dependencies": {"react": "^18.3.0"}}',
        encoding="utf-8",
    )
    (repo / "apps" / "server" / "src" / "database" / "migrations" / "001.ts").write_text(
        "export async function up(db: any) { await db.schema.createTable('items').addColumn('id', 'uuid').execute(); }\n",
        encoding="utf-8",
    )
    (q_dir / "constants" / "queue.constants.ts").write_text(
        "export enum QueueName {\n  GENERAL_QUEUE = '{general-queue}',\n  PLAIN_QUEUE = 'general-queue',\n}\n",
        encoding="utf-8",
    )
    (q_dir / "constants" / "index.ts").write_text(
        "export * from './queue.constants';\n",
        encoding="utf-8",
    )
    (q_dir / "queue.module.ts").write_text(
        """
import { BullModule } from '@nestjs/bullmq';
import { QueueName } from './constants';
export const qReg = BullModule.registerQueue(
  { name: QueueName.GENERAL_QUEUE },
  { name: 'declared-only-queue' },
  { name: getDynamicQueue() },
);
""".lstrip(),
        encoding="utf-8",
    )
    (q_dir / "processors" / "general-queue.processor.ts").write_text(
        """
import { Processor, WorkerHost } from '@nestjs/bullmq';
import { QueueName } from '../constants';
@Processor(QueueName.GENERAL_QUEUE)
export class GeneralQueueProcessor extends WorkerHost {
  async process() { return; }
}
""".lstrip(),
        encoding="utf-8",
    )
    (q_dir / "processors" / "plain-queue.processor.ts").write_text(
        """
import { Processor, WorkerHost } from '@nestjs/bullmq';
import { QueueName } from '../constants';
@Processor(QueueName.PLAIN_QUEUE)
export class PlainQueueProcessor extends WorkerHost {
  async process() { return; }
}
""".lstrip(),
        encoding="utf-8",
    )
    (repo / "apps" / "server" / "src" / "services" / "item.service.ts").write_text(
        """
import { InjectQueue } from '@nestjs/bullmq';
import { Queue } from 'bullmq';
import { QueueName } from '../integrations/queue/constants';
export class ItemService {
  private readonly seen = new Set<string>();
  constructor(
    @InjectQueue(QueueName.GENERAL_QUEUE) private generalQueue: Queue,
    @InjectQueue('unused-injected') private unusedQueue: Queue,
    @InjectQueue(dynamicQueueVar) private dynQueue: Queue,
  ) {}
  enqueue(id: string) {
    this.seen.add(id);
    this.dynQueue.add('dyn', { id });
    return this.generalQueue
      .add('job', { id });
  }
}
""".lstrip(),
        encoding="utf-8",
    )
    (repo / "apps" / "server" / "src" / "controllers" / "item.controller.ts").write_text(
        """
import { Controller, Post } from '@nestjs/common';
import { ItemService } from '../services/item.service';
@Controller('items')
export class ItemController {
  constructor(private readonly items: ItemService) {}
  @Post('enqueue')
  run() { return this.items.enqueue('1'); }
}
""".lstrip(),
        encoding="utf-8",
    )

    rep = run_target_scan(
        db_session,
        _make_target(repo, "bullmq-app", "node-kysely-react"),
        strict_gate=False,
        persist_snapshot=False,
    )
    redis_stores = {n.id: n for n in rep.nodes if n.subkind == "cache_store"}
    hash_ids = [nid for nid, n in redis_stores.items() if "({general-queue})" in n.summary]
    plain_ids = [nid for nid, n in redis_stores.items() if "(general-queue)" in n.summary]
    assert len(hash_ids) == 1
    assert len(plain_ids) == 1
    assert hash_ids[0] != plain_ids[0]
    assert "t:redis:queue_declared-only-queue" in redis_stores

    hash_q = hash_ids[0]
    plain_q = plain_ids[0]
    edges_set = {(e.source_id, e.kind, e.target_id) for e in rep.edges}
    assert ("m:service:src.services.item.service", "writes_truth", hash_q) in edges_set
    assert ("m:service:src.integrations.queue.processors.general-queue.processor", "reads_truth", hash_q) in edges_set
    assert ("m:service:src.integrations.queue.processors.plain-queue.processor", "reads_truth", plain_q) in edges_set
    assert not any(t in ("t:redis:queue_declared-only-queue", "t:redis:queue_unused-injected") for _, _, t in edges_set)
    assert not any(
        f.rule_code == "MANIP-003" and "general-queue.processor" in f.source_file
        for f in rep.findings
    )
    assert any("Unresolved dynamic BullMQ" in n for n in rep.scan_notes)


def test_docmost_pinned_corpus_end_to_end(db_session: Session) -> None:
    """Verify real Docmost checkout if present locally."""
    docmost_dir = Path("/private/tmp/wythe-corpus-20261113/docmost")
    if not docmost_dir.is_dir():
        pytest.skip("Pinned Docmost corpus checkout not present locally.")

    det = detect_repository_stack(db_session, str(docmost_dir))
    assert det.truth_adapter == "kysely-migrations"
    assert det.manipulator_adapter == "typescript-node"
    assert det.recommended_profile_slug == "node-kysely-react"

    rep = run_target_scan(
        db_session,
        _make_target(docmost_dir, "docmost-pinned", det.recommended_profile_slug, det.backend_subdir, det.frontend_subdir),
        strict_gate=False,
        persist_snapshot=False,
    )
    node_ids = {n.id for n in rep.nodes}
    assert {"t:pages", "t:backlinks", "t:page_verifications", "fn:gen_uuid_v7", "fn:pages_tsvector_update"} <= node_ids

    edges_set = {(e.source_id, e.kind, e.target_id, e.verification) for e in rep.edges}
    assert ("m:service:src.database.repos.page.page.repo", "reads_truth", "t:pages", "verified") in edges_set
    assert ("m:service:src.database.repos.page.page.repo", "writes_truth", "t:pages", "verified") in edges_set
    assert ("m:service:src.integrations.queue.tasks.backlinks.task", "reads_truth", "t:backlinks", "verified") in edges_set
    assert ("m:service:src.integrations.queue.tasks.backlinks.task", "writes_truth", "t:backlinks", "verified") in edges_set
    assert ("m:service:src.integrations.queue.tasks.backlinks.task", "reads_truth", "t:pages", "verified") in edges_set

    general_q = next(n.id for n in rep.nodes if n.subkind == "cache_store" and "({general-queue})" in n.summary)
    assert ("m:service:src.core.page.services.page.service", "writes_truth", general_q, "verified") in edges_set
    assert ("m:service:src.integrations.queue.processors.general-queue.processor", "reads_truth", general_q, "verified") in edges_set
    assert ("m:service:src.integrations.queue.processors.general-queue.processor", "calls_helper", "m:service:src.integrations.queue.tasks.backlinks.task", "verified") in edges_set
    assert not any(
        f.rule_code == "MANIP-003" and "general-queue.processor" in f.source_file
        for f in rep.findings
    )
    assert any(
        c.verified and c.route_node_id == "m:route:src.core.page.page.controller" and "t:pages" in c.truth_table_ids
        for c in rep.chains
    )
