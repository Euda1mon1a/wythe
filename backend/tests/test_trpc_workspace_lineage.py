"""Tests for multi-root workspace backend discovery, .tsx routers, dynamic imports, and tRPC lineage."""

from __future__ import annotations

from pathlib import Path

import pytest
from sqlalchemy.orm import Session

from app.adapters.autodetect import detect_repository_stack
from app.models import TargetProject
from app.services.scanner_service import run_target_scan


def _write(root: Path, rel: str, content: str) -> None:
    path = root / rel
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(content.lstrip("\n"), encoding="utf-8")


def _make_target(
    repo: Path,
    slug: str,
    profile: str,
    be: str,
    fe: str,
) -> TargetProject:
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


def _build_trpc_monorepo(repo: Path) -> None:
    _write(
        repo,
        "package.json",
        '{"private": true, "workspaces": ["apps/*", "packages/*"], "dependencies": {"prisma": "^5.0.0", "@trpc/server": "^10.0.0"}}',
    )
    _write(
        repo,
        "packages/prisma/schema.prisma",
        """
datasource db {
  provider = "postgresql"
  url      = env("DATABASE_URL")
}
model SelectedSlots {
  id Int @id
}
model UnusedAudit {
  id Int @id
}
""",
    )
    _write(
        repo,
        "apps/web/package.json",
        '{"name": "@acme/web", "dependencies": {"next": "^14.2.0", "react": "^18.3.0"}}',
    )
    _write(
        repo,
        "apps/web/tsconfig.json",
        '{"compilerOptions": {"baseUrl": ".", "paths": {"~/*": ["modules/*"]}}}',
    )
    _write(
        repo,
        "apps/web/app/[user]/page.tsx",
        """
import type { TypeOnlyProps } from "~/bookings/hooks/useTypeOnly";
import { SlotPanel } from "@acme/web/modules/bookings/components/SlotPanel";

export default function BookingPage(_props: TypeOnlyProps) {
  return <SlotPanel />;
}
""",
    )
    _write(
        repo,
        "apps/web/modules/bookings/hooks/useTypeOnly.ts",
        "export type TypeOnlyProps = { ok?: boolean };\nexport function useTypeOnly() { return null; }\n",
    )
    _write(
        repo,
        "apps/web/modules/bookings/components/SlotPanel.tsx",
        """
import { useSlots } from "../hooks/useSlots";

export function SlotPanel() {
  const { reserve, missing, loadHealth } = useSlots();
  return <button onClick={() => { reserve(); missing(); loadHealth(); }}>Book</button>;
}
""",
    )
    _write(
        repo,
        "apps/web/modules/bookings/hooks/useSlots.ts",
        """
import { trpc } from "@acme/trpc/react";

export function useSlots() {
  const reserve = trpc.viewer.slots.reserveSlot.useMutation();
  const missing = trpc.viewer.slots.nonExistentProc.useMutation();
  const loadHealth = () => fetch("/api/health");
  return { reserve, missing, loadHealth };
}
""",
    )
    _write(
        repo,
        "apps/web/app/api/health/route.ts",
        """
import { prisma } from "@acme/trpc/lib/prisma";

export async function GET() {
  const rows = await prisma.selectedSlots.findMany();
  return Response.json(rows);
}
""",
    )
    _write(
        repo,
        "apps/web/pages/api/trpc/slots/[trpc].ts",
        """
import { createNextApiHandler } from "@trpc/server/adapters/next";
import { slotsRouter } from "@acme/trpc/server/routers/viewer/slots/_router";

export default createNextApiHandler({ router: slotsRouter });
""",
    )
    _write(
        repo,
        "packages/trpc/package.json",
        '{"name": "@acme/trpc", "dependencies": {"@trpc/server": "^10.0.0"}}',
    )
    _write(
        repo,
        "packages/trpc/tsconfig.server.json",
        '{"compilerOptions": {"baseUrl": ".", "paths": {"~/*": ["./*"]}}}',
    )
    _write(
        repo,
        "packages/trpc/lib/prisma.ts",
        "export const prisma = {} as any;\nexport const dbReady = true;\n",
    )
    _write(
        repo,
        "packages/trpc/server/trpc.ts",
        "export const router = <T>(r: T) => r;\nexport const publicProcedure = { query: (fn: unknown) => fn, mutation: (fn: unknown) => fn };\n",
    )
    _write(
        repo,
        "packages/trpc/server/routers/_app.ts",
        """
import { router } from "../trpc";
import { viewerRouter } from "./viewer/_router";

export const appRouter = router({
  viewer: viewerRouter,
});
""",
    )
    _write(
        repo,
        "packages/trpc/server/routers/viewer/_router.tsx",
        """
import { router } from "../../trpc";
import { slotsRouter } from "./slots/_router";

export const viewerRouter = router({
  slots: slotsRouter,
});
""",
    )
    _write(
        repo,
        "packages/trpc/server/routers/viewer/slots/_router.tsx",
        """
import { publicProcedure, router } from "../../../trpc";

type SlotsHandlerCache = {
  reserveSlot?: typeof import("./reserveSlot.handler").reserveSlotHandler;
  siblingProc?: typeof import("./sibling.handler").siblingHandler;
};

export const slotsRouter = router({
  reserveSlot: publicProcedure.mutation(async ({ input }: { input: { id: number } }) => {
    const { reserveSlotHandler } = await import("./reserveSlot.handler");
    return reserveSlotHandler(input);
  }),
  siblingProc: publicProcedure.query(async () => {
    const { siblingHandler } = await import("./sibling.handler");
    return siblingHandler();
  }),
  uninvokedProc: publicProcedure.mutation(async ({ spec }: { spec: string }) => {
    const { uninvokedHandler } = await import("./uninvoked.handler");
    return await import(spec);
  }),
});
""",
    )
    _write(
        repo,
        "packages/trpc/server/routers/viewer/slots/reserveSlot.handler.ts",
        """
import { prisma } from "~/lib/prisma";

export async function reserveSlotHandler(input: { id: number }) {
  return prisma.selectedSlots.upsert({ where: { id: input.id }, create: {}, update: {} });
}
""",
    )
    _write(
        repo,
        "packages/trpc/server/routers/viewer/slots/sibling.handler.ts",
        """
import { prisma } from "~/lib/prisma";

export async function siblingHandler() {
  return prisma.unusedAudit.findMany();
}
""",
    )
    _write(
        repo,
        "packages/trpc/server/routers/viewer/slots/uninvoked.handler.ts",
        "export async function uninvokedHandler() { return { ok: true }; }\n",
    )
    _write(
        repo,
        "packages/trpc/server/routers/viewer/slots/reserveSlot.test.ts",
        "import { reserveSlotHandler } from './reserveSlot.handler';\nexport const specTest = () => reserveSlotHandler({ id: 1 });\n",
    )


@pytest.mark.parametrize("disable_ts", ["0", "1"])
def test_trpc_workspace_dynamic_imports_and_isolation(
    monkeypatch: pytest.MonkeyPatch,
    db_session: Session,
    tmp_path: Path,
    disable_ts: str,
) -> None:
    """Verify multi-root tRPC, dynamic import execution, sibling isolation, and type-import exclusion."""
    if disable_ts == "1":
        monkeypatch.setenv("WYTHE_DISABLE_TREESITTER", "1")
    else:
        monkeypatch.delenv("WYTHE_DISABLE_TREESITTER", raising=False)

    repo = tmp_path / "trpc_mono"
    _build_trpc_monorepo(repo)

    det = detect_repository_stack(db_session, str(repo))
    assert det.truth_adapter == "prisma-schema"
    assert det.manipulator_adapter == "typescript-node"
    assert det.display_adapter == "typescript-nextjs"
    assert det.recommended_profile_slug == "nextjs-prisma"

    rep = run_target_scan(
        db_session,
        _make_target(repo, "trpc-mono", det.recommended_profile_slug, det.backend_subdir, det.frontend_subdir),
        strict_gate=False,
        persist_snapshot=False,
    )

    assert not any(".test." in n.source_file for n in rep.nodes if n.tier == "manipulate")

    edges_ver = {(e.source_id, e.kind, e.target_id, e.verification) for e in rep.edges}
    reserve_proc = "m:route:packages.trpc.server.routers.viewer.slots._router:reserveSlot"
    sibling_proc = "m:route:packages.trpc.server.routers.viewer.slots._router:siblingProc"
    uninvoked_proc = "m:route:packages.trpc.server.routers.viewer.slots._router:uninvokedProc"
    reserve_handler = "m:service:packages.trpc.server.routers.viewer.slots.reserveSlot.handler"
    sibling_handler = "m:service:packages.trpc.server.routers.viewer.slots.sibling.handler"
    uninvoked_handler = "m:service:packages.trpc.server.routers.viewer.slots.uninvoked.handler"

    assert (reserve_proc, "calls_helper", reserve_handler, "verified") in edges_ver
    assert (reserve_handler, "writes_truth", "t:selectedslots", "verified") in edges_ver
    assert (reserve_proc, "calls_helper", sibling_handler, "verified") not in edges_ver
    assert (reserve_proc, "calls_helper", sibling_handler, "declared") not in edges_ver
    assert (sibling_proc, "calls_helper", sibling_handler, "verified") in edges_ver

    # Uninvoked dynamic import stays declared rather than verified.
    assert (uninvoked_proc, "calls_helper", uninvoked_handler, "declared") in edges_ver
    assert (uninvoked_proc, "calls_helper", uninvoked_handler, "verified") not in edges_ver

    # Unresolved dynamic import records a scan note.
    assert any("dynamic import" in note.lower() for note in rep.scan_notes)

    # `import type` never emits runtime display edges.
    page_node = next(n for n in rep.nodes if n.subkind == "page" and n.label == "/[user]")
    type_only_node = next(n for n in rep.nodes if n.source_file.endswith("useTypeOnly.ts"))
    assert not any(e.source_id == page_node.id and e.target_id == type_only_node.id for e in rep.edges)

    # Verified 3-tier chain via Next.js page -> SlotPanel -> useSlots -> tRPC reserveSlot -> SelectedSlots.
    trpc_chains = [c for c in rep.chains if c.route_node_id == reserve_proc]
    assert any(
        c.verified
        and c.operation == "write"
        and c.http_method == "POST"
        and c.display_node_id == page_node.id
        and "t:selectedslots" in c.truth_table_ids
        and "t:unusedaudit" not in c.truth_table_ids
        for c in trpc_chains
    )

    # Existing Next.js REST route (/api/health) stays intact alongside tRPC.
    assert any(
        c.verified and c.http_method == "GET" and c.http_path == "/api/health" and "t:selectedslots" in c.truth_table_ids
        for c in rep.chains
    )

    # Unknown client tRPC procedure emits an unbacked call finding (DISP-004 or DISP-007).
    assert any(
        f.rule_code in ("DISP-004", "DISP-007") and "/api/trpc/viewer.slots.nonExistentProc" in f.detail
        for f in rep.findings
    )


def test_calcom_pinned_corpus_end_to_end(db_session: Session) -> None:
    """Verify real Cal.diy checkout if present locally."""
    cal_dir = Path("/private/tmp/wythe-corpus-20261113/cal.diy")
    if not cal_dir.is_dir():
        pytest.skip("Pinned Cal.diy corpus checkout not present locally.")

    det = detect_repository_stack(db_session, str(cal_dir))
    assert det.truth_adapter == "prisma-schema"
    assert det.manipulator_adapter == "typescript-node"
    assert det.display_adapter == "typescript-nextjs"
    assert det.recommended_profile_slug == "nextjs-prisma"

    rep = run_target_scan(
        db_session,
        _make_target(cal_dir, "cal-pinned", det.recommended_profile_slug, det.backend_subdir, det.frontend_subdir),
        strict_gate=False,
        persist_snapshot=False,
    )

    sql_tables = [n for n in rep.nodes if n.tier == "truth" and n.subkind == "table"]
    assert len(sql_tables) == 100
    assert not any(".test." in n.source_file for n in rep.nodes if n.tier == "manipulate")

    edges_ver = {(e.source_id, e.kind, e.target_id, e.verification) for e in rep.edges}
    reserve_proc = "m:route:packages.trpc.server.routers.viewer.slots._router:reserveSlot"
    reserve_handler = "m:service:packages.trpc.server.routers.viewer.slots.reserveSlot.handler"
    assert (reserve_proc, "calls_helper", reserve_handler, "verified") in edges_ver
    assert (reserve_handler, "writes_truth", "t:selectedslots", "verified") in edges_ver

    assert any(
        c.verified
        and c.route_node_id == reserve_proc
        and "t:selectedslots" in c.truth_table_ids
        and "d:hook:modules.bookings.hooks.useSlots" in c.via_node_ids
        for c in rep.chains
    )
