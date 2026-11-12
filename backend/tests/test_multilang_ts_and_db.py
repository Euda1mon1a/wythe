"""End-to-end 3-tier tests for TypeScript/Prisma/Drizzle stacks, auto-detect, and SQLite catalog."""

from __future__ import annotations

import sqlite3
from pathlib import Path

from fastapi.testclient import TestClient
from sqlalchemy import select
from sqlalchemy.orm import Session

from app.adapters.autodetect import detect_repository_stack
from app.cli import main as cli_main
from app.main import create_app
from app.models import StackProfile, TargetProject
from app.services.scanner_service import run_target_scan


def test_fullstack_nextjs_prisma_lineage_and_boundary_findings(
    db_session: Session, tmp_path: Path
) -> None:
    """Verify single-root Next.js App Router + Prisma schema/migrations + route.ts E2E scan."""
    repo = tmp_path / "next_prisma_app"
    (repo / "prisma" / "migrations" / "001_init").mkdir(parents=True)
    (repo / "src" / "services").mkdir(parents=True)
    (repo / "src" / "app" / "api" / "orders").mkdir(parents=True)
    (repo / "src" / "app" / "orders").mkdir(parents=True)

    (repo / "package.json").write_text(
        '{"dependencies": {"next": "15.0.0", "@prisma/client": "6.0.0"}}',
        encoding="utf-8",
    )
    (repo / "next.config.mjs").write_text("export default {};\n", encoding="utf-8")
    (repo / "prisma" / "schema.prisma").write_text(
        """
model Order {
  id Int @id
  @@map("orders")
}

model UnmigratedAudit {
  id Int @id
  @@map("unmigrated_audits")
}
""",
        encoding="utf-8",
    )
    (repo / "prisma" / "migrations" / "001_init" / "migration.sql").write_text(
        'CREATE TABLE "orders" ("id" SERIAL PRIMARY KEY);\n',
        encoding="utf-8",
    )
    (repo / "src" / "services" / "orderService.ts").write_text(
        """
export async function listOrders(prisma: any) {
  return prisma.order.findMany();
}
""",
        encoding="utf-8",
    )
    (repo / "src" / "app" / "api" / "orders" / "route.ts").write_text(
        """
import { listOrders } from '@/services/orderService';

export async function GET(req: Request) {
  return Response.json(await listOrders((globalThis as any).prisma));
}

export async function POST(req: Request) {
  return Response.json(await (globalThis as any).prisma.order.create({ data: {} }));
}
""",
        encoding="utf-8",
    )
    (repo / "src" / "app" / "orders" / "page.tsx").write_text(
        """
export default async function OrdersPage() {
  const res = await fetch('/api/orders');
  const created = await fetch('/api/orders', { method: 'POST' });
  return <div>{String(Boolean(res && created))}</div>;
}
""",
        encoding="utf-8",
    )

    det = detect_repository_stack(db_session, str(repo))
    assert det.recommended_profile_slug == "nextjs-prisma"
    assert det.backend_subdir == "."
    assert det.frontend_subdir == "."

    target = TargetProject(
        id=0,
        slug="next-prisma",
        name="Next Prisma",
        repo_path=str(repo),
        stack_profile_slug=det.recommended_profile_slug,
        backend_subdir=det.backend_subdir,
        frontend_subdir=det.frontend_subdir,
        description="Synthetic Next.js + Prisma",
        is_active=True,
    )
    report = run_target_scan(db_session, target, strict_gate=True, persist_snapshot=False)

    assert report.summary.truth_tables == 2
    assert report.summary.end_to_end_chains >= 2
    assert any(
        c.http_path == "/api/orders" and "t:orders" in c.truth_table_ids
        for c in report.chains
    )
    rule_codes = {f.rule_code for f in report.findings}
    # unmigrated_audits missing from migration.sql -> TRUTH-002; direct POST route prisma.order.create -> TRUTH-003
    assert "TRUTH-002" in rule_codes
    assert "TRUTH-003" in rule_codes


def test_express_drizzle_react_autodetect_and_sqlite_live_catalog_drift(
    isolated_db_url: str, db_session: Session, tmp_path: Path
) -> None:
    """Verify Express + Drizzle + React Vite SPA auto-detection, SQLite live DSN drift, and DB profile truth."""
    assert isolated_db_url.startswith("sqlite:")
    repo = tmp_path / "drizzle_vite_repo"
    (repo / "server" / "db" / "migrations").mkdir(parents=True)
    (repo / "server" / "services").mkdir(parents=True)
    (repo / "server" / "routes").mkdir(parents=True)
    (repo / "web" / "src" / "pages").mkdir(parents=True)

    (repo / "server" / "package.json").write_text(
        '{"dependencies": {"express": "4.21.0", "drizzle-orm": "0.38.0"}}',
        encoding="utf-8",
    )
    (repo / "server" / "drizzle.config.ts").write_text("export default {};\n", encoding="utf-8")
    (repo / "web" / "package.json").write_text(
        '{"dependencies": {"react": "18.3.0"}}',
        encoding="utf-8",
    )
    (repo / "web" / "vite.config.ts").write_text("export default {};\n", encoding="utf-8")

    (repo / "server" / "db" / "schema.ts").write_text(
        """
import { pgTable, serial, text } from 'drizzle-orm/pg-core';
export const invoices = pgTable('invoices', { id: serial('id').primaryKey(), ref: text('ref') });
""",
        encoding="utf-8",
    )
    (repo / "server" / "db" / "migrations" / "0001_init.sql").write_text(
        "CREATE TABLE invoices (id INTEGER PRIMARY KEY, ref TEXT);\n",
        encoding="utf-8",
    )
    (repo / "server" / "services" / "invoiceService.ts").write_text(
        """
import { invoices } from '../db/schema';
export async function fetchInvoices(db: any) {
  return db.select().from(invoices);
}
""",
        encoding="utf-8",
    )
    (repo / "server" / "routes" / "invoices.ts").write_text(
        """
import { fetchInvoices } from '../services/invoiceService';
export function mountRoutes(router: any, db: any) {
  router.get('/api/invoices', async (_req: any, res: any) => res.json(await fetchInvoices(db)));
}
""",
        encoding="utf-8",
    )
    (repo / "web" / "src" / "pages" / "InvoicesPage.tsx").write_text(
        """
export function InvoicesPage() {
  void fetch('/api/invoices');
  return null;
}
""",
        encoding="utf-8",
    )

    # 1. Clean CLI gate via `--profile auto` passes (0 blocking violations).
    assert cli_main(["gate", "--strict", str(repo)]) == 0

    # 2. Live read-only SQLite catalog missing `invoices` triggers TRUTH-002 (exit code 1).
    live_sqlite = tmp_path / "empty_live.sqlite"
    conn = sqlite3.connect(live_sqlite)
    conn.execute("CREATE TABLE unrelated_table (id INTEGER PRIMARY KEY)")
    conn.commit()
    conn.close()
    assert cli_main(["gate", "--strict", "--dsn", f"sqlite:///{live_sqlite}", str(repo)]) == 1

    # 3. DB truth check: disabling `node-drizzle-react` in `atlas_stack_profiles` shifts `/adapters/detect`.
    prof = db_session.scalar(
        select(StackProfile).where(StackProfile.slug == "node-drizzle-react")
    )
    assert prof is not None
    prof.is_enabled = False
    db_session.commit()

    app = create_app()
    with TestClient(app) as client:
        resp = client.get("/api/v1/adapters/detect", params={"repo_path": str(repo)})
        assert resp.status_code == 200
        # Falls back to next enabled Drizzle+Node profile (`postgres-drizzle-nextjs`) from DB truth!
        assert resp.json()["recommended_profile_slug"] == "postgres-drizzle-nextjs"


def test_nextjs_route_groups_prisma_wrapper_and_experimental_cli_banner(
    isolated_db_url: str, tmp_path: Path, capsys
) -> None:
    """Verify Next.js `(main)` route groups, `prisma.client.*`, `queries/` doors, and `[experimental]` CLI banner."""
    assert isolated_db_url.startswith("sqlite:")
    repo = tmp_path / "umami_style_app"
    (repo / "prisma" / "migrations" / "001_init").mkdir(parents=True)
    (repo / "src" / "queries" / "prisma").mkdir(parents=True)
    (repo / "src" / "app" / "api" / "websites" / "[websiteId]" / "[[...slug]]").mkdir(parents=True)
    (repo / "src" / "app" / "(main)" / "websites").mkdir(parents=True)

    (repo / "package.json").write_text(
        '{"dependencies": {"next": "15.0.0", "@prisma/client": "6.0.0"}}',
        encoding="utf-8",
    )
    (repo / "next.config.mjs").write_text("export default {};\n", encoding="utf-8")
    (repo / "prisma" / "schema.prisma").write_text(
        'model Website {\n  id String @id\n  @@map("website")\n}\n',
        encoding="utf-8",
    )
    (repo / "prisma" / "migrations" / "001_init" / "migration.sql").write_text(
        "CREATE TABLE website (id TEXT PRIMARY KEY);\n",
        encoding="utf-8",
    )
    (repo / "src" / "queries" / "prisma" / "website.ts").write_text(
        "import prisma from './client';\n"
        "export async function getWebsite(id: string) {\n"
        "  return prisma.client.website.findUnique({ where: { id } });\n"
        "}\n",
        encoding="utf-8",
    )
    (repo / "src" / "app" / "api" / "websites" / "[websiteId]" / "[[...slug]]" / "route.ts").write_text(
        "import { getWebsite } from '@/queries/prisma/website';\n"
        "export async function GET(_req: Request) {\n"
        "  const row = await getWebsite('w1');\n"
        "  return Response.json(row);\n"
        "}\n",
        encoding="utf-8",
    )
    (repo / "src" / "app" / "(main)" / "websites" / "page.tsx").write_text(
        "import type { paths } from '@/types/api-generated';\n"
        "export default function WebsitesPage() {\n"
        "  fetch('/websites/abc-123');\n"
        "  return <main><h1>Websites</h1></main>;\n"
        "}\n",
        encoding="utf-8",
    )

    rc = cli_main(["gate", "--strict", str(repo)])
    out = capsys.readouterr().out
    assert rc == 0
    assert "nextjs-prisma [experimental]" in out
    assert "1 end-to-end 3-tier chains" in out
