"""Pluggable adapter protocols for Database Truth, Backend Manipulation, and Frontend Display.

Each tier adapter inspects a repository slice and emits normalized nodes, raw symbol
metadata, intra-tier edges, and tier-specific candidate findings. Adding a new language
(e.g., Go, Rust, Swift, Prisma/Drizzle, SvelteKit) requires implementing the relevant
protocol and registering its adapter key here without changing the core lineage engine.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from pathlib import Path
from typing import Protocol

from app.schemas.atlas import AdapterSlotSchema, AtlasEdge, AtlasNode


@dataclass(frozen=True)
class RawCandidateFinding:
    """Adapter-emitted candidate violation prior to DB RulePolicy filtering."""

    rule_code: str
    node_id: str | None
    source_file: str
    line: int
    title: str
    detail: str
    remediation: str
    # Set on unbacked frontend calls so an optional live probe can re-check them.
    http_method: str | None = None
    http_path: str | None = None
    # Downstream store/table impacted when the finding attaches to an upstream writer.
    target_node_id: str | None = None
    # Explicit epistemic metadata when an adapter distinguishes evidence strength or candidacy.
    confidence: str | None = None
    evidence_strength: str | None = None


@dataclass(frozen=True)
class TruthExtractionResult:
    """Normalized output of a Database Truth adapter."""

    nodes: list[AtlasNode]
    table_symbol_map: dict[str, str]  # model class or table name -> node_id ("t:...")
    function_symbol_map: dict[str, str]  # sql function name -> node_id ("fn:...")
    findings: list[RawCandidateFinding] = field(default_factory=list)
    observation_source: str = "static_ast"
    # Plain-language notes about what the adapter could not check (shown in reports).
    notes: list[str] = field(default_factory=list)
    # ORM class name -> dotted modules that define it. When non-empty, manipulation adapters
    # resolve a class symbol to its table only if the consumer imports it from one of these
    # modules (a same-named schema/dataclass is not the table), and stop treating plain
    # identifiers that merely equal a table name as table access.
    class_modules: dict[str, set[str]] = field(default_factory=dict)
    # Dotted modules that hold ORM models or table objects (for `from <models> import some_table`).
    model_modules: set[str] = field(default_factory=set)
    # Database-side readers of a table: node id -> {reader node id: (evidence path, edge kind, note)}.
    # Filled from SQL function bodies (`fn:*` reads) and foreign keys (`t:*` references).
    db_readers: dict[str, dict[str, tuple[str, str, str]]] = field(default_factory=dict)


@dataclass(frozen=True)
class RouteDescriptor:
    """Normalized HTTP endpoint exposed by a Manipulation tier route handler."""

    node_id: str
    http_method: str
    full_path: str
    path_regex: str
    source_file: str
    line: int
    called_symbols: frozenset[str]
    imported_modules: frozenset[str]


@dataclass(frozen=True)
class ManipulatorExtractionResult:
    """Normalized output of a Backend Manipulation adapter."""

    nodes: list[AtlasNode]
    edges: list[AtlasEdge]  # manipulate->truth and manipulate->manipulate
    routes: list[RouteDescriptor]
    findings: list[RawCandidateFinding] = field(default_factory=list)
    notes: list[str] = field(default_factory=list)


@dataclass(frozen=True)
class FrontendHttpCall:
    """Normalized HTTP request issued from a Display tier module."""

    caller_node_id: str
    http_method: str
    raw_path: str
    normalized_path: str
    source_file: str
    line: int
    # Top-level symbol (function/const/class) that contains the call, when known.
    caller_symbol: str | None = None
    # True: an entry point (page/layout) reaches `caller_symbol`; False: nothing does;
    # None: the adapter cannot tell (treated as reachable).
    reachable: bool | None = None
    # Entry point -> ... -> caller, as `file#symbol` hops (empty when unknown).
    reach_trail: tuple[str, ...] = ()


@dataclass(frozen=True)
class DisplayExtractionResult:
    """Normalized output of a Frontend Display adapter."""

    nodes: list[AtlasNode]
    edges: list[AtlasEdge]  # page->hook, page->client, hook->client
    http_calls: list[FrontendHttpCall]
    findings: list[RawCandidateFinding] = field(default_factory=list)
    # Regexes for paths the frontend serves itself (e.g. Next.js `route.ts` handlers);
    # calls matching one are not backend calls.
    local_route_patterns: list[str] = field(default_factory=list)
    notes: list[str] = field(default_factory=list)


class TruthTierAdapter(Protocol):
    """Protocol for Tier 1 (Database Truth) language/ORM/schema adapters."""

    name: str

    def extract(
        self,
        repo_root: Path,
        backend_subdir: str,
        pg_dsn: str | None = None,
    ) -> TruthExtractionResult: ...


class ManipulatorTierAdapter(Protocol):
    """Protocol for Tier 2 (Backend Manipulation) language/framework adapters."""

    name: str

    def extract(
        self,
        repo_root: Path,
        backend_subdir: str,
        truth: TruthExtractionResult,
    ) -> ManipulatorExtractionResult: ...


class DisplayTierAdapter(Protocol):
    """Protocol for Tier 3 (Frontend Display) language/framework adapters."""

    name: str

    def extract(
        self,
        repo_root: Path,
        frontend_subdir: str,
    ) -> DisplayExtractionResult: ...


class AdapterRegistry:
    """Registry of active and planned adapters across Truth, Manipulate, and Display tiers."""

    def __init__(self) -> None:
        self._truth: dict[str, TruthTierAdapter] = {}
        self._manipulators: dict[str, ManipulatorTierAdapter] = {}
        self._displays: dict[str, DisplayTierAdapter] = {}

    def register_truth(self, adapter: TruthTierAdapter) -> None:
        self._truth[adapter.name] = adapter

    def register_manipulator(self, adapter: ManipulatorTierAdapter) -> None:
        self._manipulators[adapter.name] = adapter

    def register_display(self, adapter: DisplayTierAdapter) -> None:
        self._displays[adapter.name] = adapter

    def get_truth(self, name: str) -> TruthTierAdapter:
        if name not in self._truth:
            raise KeyError(f"Truth adapter '{name}' is not registered or not yet implemented")
        return self._truth[name]

    def get_manipulator(self, name: str) -> ManipulatorTierAdapter:
        if name not in self._manipulators:
            raise KeyError(f"Manipulator adapter '{name}' is not registered or not yet implemented")
        return self._manipulators[name]

    def get_display(self, name: str) -> DisplayTierAdapter:
        if name not in self._displays:
            raise KeyError(f"Display adapter '{name}' is not registered or not yet implemented")
        return self._displays[name]

    def list_slots(self) -> list[AdapterSlotSchema]:
        """Return implemented multi-language adapters alongside planned extension slots."""
        return [
            AdapterSlotSchema(
                name="python-services", tier="manipulate", language="Python / Shell / plist",
                frameworks=["Python scripts", "launchd"], implementation_status="experimental",
                capabilities=[
                    "Python import and package-initializer dependency declarations",
                    "Shell script references and launchd command declarations",
                    "Explicit coverage exclusions; no runtime or safe-removal inference",
                ],
            ),
            AdapterSlotSchema(
                name="no-display", tier="display", language="None", frameworks=[],
                implementation_status="experimental",
                capabilities=["Explicitly unobserved display tier for service-only profiles"],
            ),
            AdapterSlotSchema(
                name="postgres-sqlalchemy",
                tier="truth",
                language="SQL / Python",
                frameworks=["PostgreSQL", "MySQL", "SQLite", "SQLAlchemy 2.0", "Alembic", "schema.sql"],
                implementation_status="implemented",
                capabilities=[
                    "SQLAlchemy declarative __tablename__ & column extraction",
                    "schema.sql & Alembic CREATE TABLE / FUNCTION / TRIGGER parsing",
                    "ORM-to-SQL drift check + read-only PostgreSQL/MySQL/SQLite catalog probe",
                ],
            ),
            AdapterSlotSchema(
                name="prisma-schema",
                tier="truth",
                language="Prisma / SQL",
                frameworks=["PostgreSQL", "MySQL", "SQLite", "SQL Server", "Prisma ORM"],
                implementation_status="experimental",
                capabilities=[
                    "schema.prisma datasource, model, @@map, and @@schema extraction",
                    "prisma/migrations/*.sql DDL & stored guard verification",
                    "Prisma-to-migration & live read-only DB catalog drift check",
                ],
            ),
            AdapterSlotSchema(
                name="drizzle-orm",
                tier="truth",
                language="TypeScript / SQL",
                frameworks=["PostgreSQL", "MySQL", "SQLite", "Drizzle ORM", "drizzle-kit"],
                implementation_status="experimental",
                capabilities=[
                    "pgTable / mysqlTable / sqliteTable & custom schema extraction",
                    "Drizzle SQL migration parity & live read-only catalog probe",
                ],
            ),
            AdapterSlotSchema(
                name="django-orm",
                tier="truth",
                language="Python / SQL",
                frameworks=["PostgreSQL", "MySQL", "SQLite", "Django ORM", "Django Migrations"],
                implementation_status="experimental",
                capabilities=[
                    "Django models.Model AST (Meta.db_table, abstract/proxy exclusion)",
                    "CreateModel & RunSQL migration verification + live catalog probe",
                ],
            ),
            AdapterSlotSchema(
                name="sql-ddl",
                tier="truth",
                language="SQL",
                frameworks=["PostgreSQL", "MySQL", "SQLite", "sqlc", "golang-migrate", "goose", "Flyway", "sqlx"],
                implementation_status="experimental",
                capabilities=[
                    "Multi-dialect CREATE TABLE / FUNCTION / PROCEDURE / TRIGGER DDL parsing",
                    "sqlc `-- name:` query-to-table read/write symbol binding",
                    "Read-only live catalog drift verification",
                ],
            ),
            AdapterSlotSchema(
                name="rust-sql",
                tier="truth",
                language="Rust / SQL",
                frameworks=["PostgreSQL", "MySQL", "SQLite", "sqlx", "Diesel", "SeaORM"],
                implementation_status="experimental",
                capabilities=[
                    "sqlx migrations & query_file! SQL-to-table binding",
                    "Diesel table! schema.rs & SeaORM #[sea_orm(table_name)] entity extraction",
                    "ORM-to-SQL migration parity & read-only PG/MySQL/SQLite catalog probe",
                ],
            ),
            AdapterSlotSchema(
                name="python-fastapi",
                tier="manipulate",
                language="Python",
                frameworks=["FastAPI", "SQLAlchemy", "Pydantic v2", "Celery / CLI"],
                implementation_status="implemented",
                capabilities=[
                    "APIRouter prefix + decorator full HTTP path synthesis",
                    "Syntax-tree ORM & SQL read/write separation (excluding comments/types)",
                    "Policy-in-code, host-clock, direct-route-write, and inert-module detection",
                ],
            ),
            AdapterSlotSchema(
                name="typescript-node",
                tier="manipulate",
                language="TypeScript / Node.js",
                frameworks=["Next.js Route Handlers (route.ts)", "Express", "Hono", "Fastify", "NestJS"],
                implementation_status="experimental",
                capabilities=[
                    "App Router route.ts, Express/Hono mounts, and NestJS @Controller synthesis",
                    "Prisma, Drizzle, and raw SQL read vs. write extraction",
                    "Direct route mutation, policy literal, and host clock detection",
                ],
            ),
            AdapterSlotSchema(
                name="python-django",
                tier="manipulate",
                language="Python",
                frameworks=["Django", "Django REST Framework", "Django Ninja"],
                implementation_status="experimental",
                capabilities=[
                    "urls.py path/include, DRF ViewSet routers, and Ninja route synthesis",
                    "Model.objects read vs. write AST separation & view-write detection",
                ],
            ),
            AdapterSlotSchema(
                name="go-http",
                tier="manipulate",
                language="Go",
                frameworks=["net/http (Go 1.22+)", "chi", "gin", "echo", "sqlc", "pgx", "GORM"],
                implementation_status="experimental",
                capabilities=[
                    "Router group & ServeMux HTTP pattern synthesis",
                    "sqlc generated query & raw SQL read/write package lineage",
                    "Go policy constant, time.Now(), and handler-write boundary checks",
                ],
            ),
            AdapterSlotSchema(
                name="rust-http",
                tier="manipulate",
                language="Rust",
                frameworks=["axum", "actix-web", "rocket", "Tauri v2 (#[tauri::command])", "sqlx", "Diesel", "SeaORM"],
                implementation_status="experimental",
                capabilities=[
                    "axum Router/nest, actix-web/rocket macros, and #[tauri::command] IPC synthesis",
                    "sqlx query!/query_file!, Diesel, and SeaORM read-vs-write crate lineage",
                    "Rust const/static policy, Utc::now()/SystemTime::now(), and handler-write checks",
                ],
            ),
            AdapterSlotSchema(
                name="typescript-nextjs",
                tier="display",
                language="TypeScript / TSX",
                frameworks=["Next.js App Router & Pages Router", "React", "TanStack Query", "openapi-typescript"],
                implementation_status="implemented",
                capabilities=[
                    "App Router & Pages Router surface, hook, and API client graph",
                    "Template URL normalization, OpenAPI type check, and DISP-001..007",
                    "Symbol-level reachability from pages/layouts and route.ts handler awareness",
                ],
            ),
            AdapterSlotSchema(
                name="typescript-react",
                tier="display",
                language="TypeScript / TSX",
                frameworks=["React SPA", "Vite", "React Router", "TanStack Router", "Remix"],
                implementation_status="experimental",
                capabilities=[
                    "SPA pages/routes/views, hooks, and typed client lineage",
                    "Client policy shadow & browser clock/UTC-slicing detection",
                ],
            ),
            AdapterSlotSchema(
                name="vue-sfc",
                tier="display",
                language="Vue / TypeScript",
                frameworks=["Vue 3", "Nuxt 3", "Vue Router", "Pinia"],
                implementation_status="experimental",
                capabilities=[
                    "Line-accurate .vue <script setup> extraction & composable graph",
                    "$fetch / useFetch / axios / typed client lineage & DISP checks",
                ],
            ),
            AdapterSlotSchema(
                name="sveltekit",
                tier="display",
                language="Svelte / TypeScript",
                frameworks=["Svelte 5", "SvelteKit"],
                implementation_status="experimental",
                capabilities=[
                    "+page.svelte / +page.ts route & $lib store/client graph",
                    "Line-accurate .svelte script inspection & DISP boundary checks",
                ],
            ),
            AdapterSlotSchema(
                name="rust-wasm",
                tier="display",
                language="Rust (WASM)",
                frameworks=["Leptos", "Dioxus", "Yew", "gloo-net", "Tauri WASM"],
                implementation_status="experimental",
                capabilities=[
                    "Leptos/Dioxus/Yew route & component graph extraction",
                    "gloo-net / reqwest HTTP & Tauri invoke() lineage + WASM DISP-001..004 checks",
                ],
            ),
            AdapterSlotSchema(
                name="swift-vapor",
                tier="manipulate",
                language="Swift",
                frameworks=["Swift Server / Vapor", "gRPC / OpenAPI Swift"],
                implementation_status="planned",
                capabilities=["Typed Swift HTTP/gRPC route & write-lane receipt verification"],
            ),
        ]
