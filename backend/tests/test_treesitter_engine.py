"""Tests for the Tree-sitter CST grammar engine across TypeScript/TSX, Rust, and Go."""

from __future__ import annotations

from pathlib import Path

import pytest

from app.adapters.go_http import GoHttpAdapter
from app.adapters.prisma_truth import PrismaSchemaAdapter
from app.adapters.rust_inspect import extract_rust_routes, strip_rust_comments
from app.adapters.sql_ddl_truth import SqlDdlTruthAdapter
from app.adapters.treesitter_engine import has_treesitter
from app.adapters.typescript_nextjs import TypeScriptNextJsAdapter
from app.adapters.typescript_node import TypeScriptNodeAdapter


def test_treesitter_ts_generics_chained_hono_type_imports_and_urls(tmp_path: Path) -> None:
    assert has_treesitter() is True

    (tmp_path / "prisma").mkdir()
    (tmp_path / "prisma" / "schema.prisma").write_text(
        """
        datasource db { provider = "postgresql" url = env("DATABASE_URL") }
        model Order {
          id    Int    @id @default(autoincrement())
          total Int
          @@map("orders")
        }
        """,
        encoding="utf-8",
    )
    (tmp_path / "prisma" / "migrations" / "001").mkdir(parents=True)
    (tmp_path / "prisma" / "migrations" / "001" / "migration.sql").write_text(
        "CREATE TABLE orders (id SERIAL PRIMARY KEY, total INT NOT NULL);\n",
        encoding="utf-8",
    )

    be = tmp_path / "server"
    be.mkdir()
    (be / "dto.ts").write_text("export interface CreateOrderDto { total: number }\n", encoding="utf-8")
    (be / "orderService.ts").write_text(
        """
        export async function saveOrder(prisma: any, total: number) {
          const upstream = "https://payments.example.com/v1/charge"; // URL with // must not truncate!
          return prisma.order.create({ data: { total } });
        }
        """,
        encoding="utf-8",
    )
    (be / "routes.ts").write_text(
        """
        import type { CreateOrderDto } from './dto';
        import { saveOrder } from './orderService';

        const api = new Hono().basePath('/v1');
        api.post<CreateOrderDto, { id: number }>('/orders', async (c) => {
          return saveOrder(c.env.prisma, 100);
        });
        api.route('/orders/:id').get(async () => ({})).delete(async () => ({}));
        """,
        encoding="utf-8",
    )

    fe = tmp_path / "web" / "src"
    (fe / "api").mkdir(parents=True)
    (fe / "app").mkdir(parents=True)
    (fe / "api" / "orders.ts").write_text(
        """
        import type { paths } from './openapi';
        export async function createOrder(body: unknown) {
          return api.post<Record<string, { id: number }>>('/api/v1/orders', body);
        }
        export async function removeOrder(id: string) {
          return fetch(`/api/v1/orders/${id}`, {
            headers: {
              'X-Trace': 'https://trace.example.com//span',
              'Content-Type': 'application/json',
            },
            cache: 'no-store',
            credentials: 'include',
            method: 'DELETE',
          });
        }
        """,
        encoding="utf-8",
    )
    (fe / "app" / "page.tsx").write_text(
        """
        import { createOrder, removeOrder } from '../api/orders';
        export default function OrdersPage() {
          return <main><button type="button" onClick={() => { void createOrder({}); void removeOrder('1'); }}>Run</button></main>;
        }
        """,
        encoding="utf-8",
    )

    truth = PrismaSchemaAdapter().extract(tmp_path, "server")
    manip = TypeScriptNodeAdapter().extract(tmp_path, "server", truth)
    disp = TypeScriptNextJsAdapter().extract(tmp_path, "web")

    route_Set = {(r.http_method, r.full_path) for r in manip.routes}
    assert ("POST", "/v1/orders") in route_Set
    assert ("GET", "/v1/orders/{id}") in route_Set
    assert ("DELETE", "/v1/orders/{id}") in route_Set

    # `import type { CreateOrderDto } from './dto'` must NOT create a runtime calls_helper edge to dto.ts
    helper_targets = {e.target_id for e in manip.edges if e.kind == "calls_helper"}
    assert "m:service:orderService" in helper_targets
    assert not any("dto" in t for t in helper_targets)

    # URL string `"https://..."` inside orderService.ts must NOT truncate the subsequent prisma.order.create write
    write_edges = [e for e in manip.edges if e.kind == "writes_truth"]
    assert any(e.target_id == "t:orders" for e in write_edges)

    # Frontend generic `api.post<Record<...>>` and multi-line `fetch(..., { method: 'DELETE' })` extracted via TSX CST
    fe_calls = {(c.http_method, c.normalized_path) for c in disp.http_calls}
    assert ("POST", "/api/v1/orders") in fe_calls
    assert ("DELETE", "/api/v1/orders/{param}") in fe_calls


def test_treesitter_rust_multi_nest_and_stacked_attributes() -> None:
    rust_src = """
    const ENDPOINT: &str = "https://internal.example.com//health"; // must not strip string!

    #[tracing::instrument]
    #[allow(clippy::unused_async)]
    #[post("/invoices")]
    pub async fn create_invoice() {}

    #[tauri::command]
    #[allow(dead_code)]
    pub async fn sync_ledger() {}

    pub fn build_router() -> Router {
        Router::new()
            .nest("/users", Router::new().route("/:id", get(get_user)))
            .nest("/orders", Router::new().route("/", post(create_order)))
    }
    """
    cleaned = strip_rust_comments(rust_src)
    assert "https://internal.example.com//health" in cleaned
    routes = extract_rust_routes(cleaned)
    by_verb_path = {(v, p): syms for v, p, _, syms in routes}

    assert ("GET", "/users/{id}") in by_verb_path
    assert ("POST", "/orders") in by_verb_path
    assert ("POST", "/invoices") in by_verb_path
    assert "create_invoice" in by_verb_path[("POST", "/invoices")]
    assert ("POST", "/tauri/sync_ledger") in by_verb_path


def test_treesitter_go_nested_chi_closures_and_fallback_toggle(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    (tmp_path / "go.mod").write_text("module example.com/nested\n\ngo 1.22\n", encoding="utf-8")
    (tmp_path / "schema.sql").write_text(
        "CREATE TABLE shipments (id SERIAL PRIMARY KEY, code TEXT NOT NULL);\n",
        encoding="utf-8",
    )
    (tmp_path / "cmd" / "api").mkdir(parents=True)
    (tmp_path / "cmd" / "api" / "main.go").write_text(
        """
        package main
        func mount(r Router) {
            upstream := "https://carrier.example.com//track"
            _ = upstream
            r.Route("/v1", func(r Router) {
                r.Route("/shipments", func(r Router) {
                    r.Post("/:id/dispatch", handleDispatch)
                })
            })
        }
        func handleDispatch() {
            q := "INSERT INTO shipments (code) VALUES ('A')"
            _ = q
        }
        """,
        encoding="utf-8",
    )

    truth = SqlDdlTruthAdapter().extract(tmp_path, ".")
    manip = GoHttpAdapter().extract(tmp_path, ".", truth)
    assert ("POST", "/v1/shipments/{id}/dispatch") in {(r.http_method, r.full_path) for r in manip.routes}
    assert any(e.kind == "writes_truth" and e.target_id == "t:shipments" for e in manip.edges)

    # Verify deterministic fallback toggle when Tree-sitter is disabled
    monkeypatch.setenv("WYTHE_DISABLE_TREESITTER", "1")
    assert has_treesitter() is False
    fallback_manip = GoHttpAdapter().extract(tmp_path, ".", truth)
    assert any(r.http_method == "POST" for r in fallback_manip.routes)
