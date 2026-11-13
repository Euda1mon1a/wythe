"""Default adapter registry factory with multi-language 3-tier adapters."""

from __future__ import annotations

from app.adapters.base import AdapterRegistry
from app.adapters.django_truth import DjangoOrmAdapter
from app.adapters.drizzle_truth import DrizzleOrmAdapter
from app.adapters.go_http import GoHttpAdapter
from app.adapters.postgres_sqlalchemy import PostgresSqlAlchemyAdapter
from app.adapters.prisma_truth import PrismaSchemaAdapter
from app.adapters.python_django import PythonDjangoAdapter
from app.adapters.python_fastapi import PythonFastApiAdapter
from app.adapters.python_services import NoDisplayAdapter, PythonServicesAdapter
from app.adapters.rust_http import RustHttpAdapter
from app.adapters.rust_sql_truth import RustSqlTruthAdapter
from app.adapters.rust_wasm_display import RustWasmDisplayAdapter
from app.adapters.sql_ddl_truth import SqlDdlTruthAdapter
from app.adapters.sveltekit_display import SvelteKitDisplayAdapter
from app.adapters.typescript_nextjs import TypeScriptNextJsAdapter
from app.adapters.typescript_node import TypeScriptNodeAdapter
from app.adapters.typescript_react import TypeScriptReactSpaAdapter
from app.adapters.vue_sfc import VueSfcDisplayAdapter


def build_default_registry() -> AdapterRegistry:
    """Instantiate an AdapterRegistry populated with all implemented 3-tier adapters."""
    registry = AdapterRegistry()

    # Tier 1: Database & Schema/ORM Truth
    registry.register_truth(PostgresSqlAlchemyAdapter())
    registry.register_truth(PrismaSchemaAdapter())
    registry.register_truth(DrizzleOrmAdapter())
    registry.register_truth(DjangoOrmAdapter())
    registry.register_truth(SqlDdlTruthAdapter())
    registry.register_truth(RustSqlTruthAdapter())

    # Tier 2: Backend Manipulation
    registry.register_manipulator(PythonFastApiAdapter())
    registry.register_manipulator(PythonServicesAdapter())
    registry.register_manipulator(TypeScriptNodeAdapter())
    registry.register_manipulator(PythonDjangoAdapter())
    registry.register_manipulator(GoHttpAdapter())
    registry.register_manipulator(RustHttpAdapter())

    # Tier 3: Frontend Display
    registry.register_display(TypeScriptNextJsAdapter())
    registry.register_display(NoDisplayAdapter())
    registry.register_display(TypeScriptReactSpaAdapter())
    registry.register_display(VueSfcDisplayAdapter())
    registry.register_display(SvelteKitDisplayAdapter())
    registry.register_display(RustWasmDisplayAdapter())

    return registry
