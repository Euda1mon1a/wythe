"""Tier 1 Adapter: Prisma Schema (`schema.prisma`) + SQL Migrations + Live DB Catalog.

Supports PostgreSQL, MySQL, SQLite, SQL Server, and CockroachDB Prisma datasources.
"""

from __future__ import annotations

import re
from pathlib import Path

from app.adapters.base import RawCandidateFinding, TruthExtractionResult
from app.adapters.db_catalog_probe import (
    infer_table_role,
    is_migration_meta_table,
    parse_sql_ddl_objects,
    probe_live_catalog_tables,
)
from app.schemas.atlas import AtlasNode

_DATASOURCE_PROVIDER_RE = re.compile(
    r"""datasource\s+\w+\s*\{[\s\S]*?provider\s*=\s*['"](?P<provider>[a-zA-Z0-9_-]+)['"]""",
    re.MULTILINE,
)
_MODEL_BLOCK_RE = re.compile(
    r"""^\s*model\s+(?P<name>[A-Za-z_]\w*)\s*\{(?P<body>[\s\S]*?)^\s*\}""",
    re.MULTILINE,
)
_MAP_TABLE_RE = re.compile(r"""@@map\(\s*['"](?P<tbl>[^'"]+)['"]\s*\)""")
_SCHEMA_ATTR_RE = re.compile(r"""@@schema\(\s*['"](?P<sch>[^'"]+)['"]\s*\)""")
_SCALAR_OR_ENUM_FIELD_RE = re.compile(r"""^\s*(?P<field>[A-Za-z_]\w*)\s+(?P<ftype>[A-Za-z_]\w*(?:\[\]|\?)?)""")


def _lower_camel(name: str) -> str:
    return name[:1].lower() + name[1:] if name else name


def _iter_prisma_files(base_dir: Path, repo_root: Path) -> list[Path]:
    candidates: list[Path] = []
    for root in dict.fromkeys([base_dir, repo_root]):
        if not root.is_dir():
            continue
        for p in sorted(root.rglob("*.prisma")):
            if "node_modules" in p.parts or ".next" in p.parts:
                continue
            if p not in candidates:
                candidates.append(p)
    return candidates


class PrismaSchemaAdapter:
    """Extracts Prisma models, SQL migration DDL, and optional live DB catalog drift."""

    name = "prisma-schema"

    def extract(
        self,
        repo_root: Path,
        backend_subdir: str,
        pg_dsn: str | None = None,
    ) -> TruthExtractionResult:
        base_dir = (repo_root / backend_subdir).resolve() if backend_subdir not in ("", ".") else repo_root
        prisma_files = _iter_prisma_files(base_dir, repo_root)

        nodes: list[AtlasNode] = []
        table_symbol_map: dict[str, str] = {}
        function_symbol_map: dict[str, str] = {}
        findings: list[RawCandidateFinding] = []

        provider = "postgresql"
        # key -> (rel_file, lineno, cols, model_name)
        prisma_models: dict[str, tuple[str, int, list[str], str]] = {}

        for pfile in prisma_files:
            rel_file = pfile.relative_to(repo_root).as_posix()
            text = pfile.read_text(encoding="utf-8", errors="replace")
            prov_m = _DATASOURCE_PROVIDER_RE.search(text)
            if prov_m:
                provider = prov_m.group("provider").lower()

            for m in _MODEL_BLOCK_RE.finditer(text):
                model_name = m.group("name")
                body = m.group("body")
                lineno = text.count("\n", 0, m.start()) + 1
                mapped_m = _MAP_TABLE_RE.search(body)
                schema_m = _SCHEMA_ATTR_RE.search(body)
                raw_tbl = (mapped_m.group("tbl") if mapped_m else model_name).lower()
                sch = schema_m.group("sch").lower() if schema_m else "public"
                tbl_key = raw_tbl if sch in ("public", "main", "dbo") else f"{sch}.{raw_tbl}"

                cols: list[str] = []
                for line in body.splitlines():
                    stripped = line.strip()
                    if not stripped or stripped.startswith(("//", "@@")):
                        continue
                    fm = _SCALAR_OR_ENUM_FIELD_RE.match(stripped)
                    if fm and not fm.group("ftype").endswith("[]"):
                        cols.append(fm.group("field"))
                prisma_models[tbl_key] = (rel_file, lineno, cols[:40], model_name)

        sql_tables: dict[str, tuple[str, int, list[str]]] = {}
        sql_guards: dict[str, tuple[str, int]] = {}
        sql_search_roots = [
            base_dir / "prisma" / "migrations",
            repo_root / "prisma" / "migrations",
            base_dir,
        ]
        seen_sql: set[Path] = set()
        for sroot in sql_search_roots:
            if not sroot.is_dir():
                continue
            pattern = "*.sql" if sroot.name == "migrations" else "schema.sql"
            for sfile in sorted(sroot.rglob(pattern)):
                if sfile in seen_sql or "node_modules" in sfile.parts:
                    continue
                seen_sql.add(sfile)
                rel_s = sfile.relative_to(repo_root).as_posix()
                t_objs, g_objs = parse_sql_ddl_objects(sfile.read_text(encoding="utf-8", errors="replace"))
                for tk, (tline, tcols) in t_objs.items():
                    sql_tables[tk] = (rel_s, tline, tcols)
                for gk, gline in g_objs.items():
                    sql_guards[gk] = (rel_s, gline)

        has_migrations = bool(seen_sql)
        all_keys = sorted(set(prisma_models.keys()) | set(sql_tables.keys()))
        for tbl_key in all_keys:
            if is_migration_meta_table(tbl_key):
                continue
            node_id = f"t:{tbl_key}"
            if tbl_key in prisma_models:
                src_file, lineno, cols, model_name = prisma_models[tbl_key]
                camel = _lower_camel(model_name)
                table_symbol_map[model_name] = node_id
                table_symbol_map[camel] = node_id
                table_symbol_map[f"prisma.{camel}"] = node_id
                summary = f"Prisma `{provider}` model `{model_name}` -> table `{tbl_key}`."
            else:
                src_file, lineno, cols = sql_tables[tbl_key]
                summary = f"SQL migration table `{tbl_key}` ({provider})."

            table_symbol_map[tbl_key] = node_id
            if "." in tbl_key:
                table_symbol_map[tbl_key.split(".", 1)[1]] = node_id
            nodes.append(
                AtlasNode(
                    id=node_id,
                    tier="truth",
                    subkind="table",
                    label=tbl_key,
                    source_file=src_file,
                    line=lineno,
                    status="clean",
                    role=infer_table_role(tbl_key),
                    cluster=tbl_key.split("_", 1)[0] if "_" in tbl_key else "core",
                    summary=summary,
                    columns=cols,
                )
            )

        if has_migrations:
            for tbl_key, (src_file, lineno, _, model_name) in sorted(prisma_models.items()):
                if tbl_key not in sql_tables:
                    findings.append(
                        RawCandidateFinding(
                            rule_code="TRUTH-002",
                            node_id=f"t:{tbl_key}",
                            source_file=src_file,
                            line=lineno,
                            title=f"Prisma model `{model_name}` (`{tbl_key}`) missing from SQL migrations",
                            detail=f"`{src_file}` declares `{model_name}`, but no SQL migration creates `{tbl_key}`.",
                            remediation="Run `prisma migrate dev` to record deterministic SQL DDL for the model.",
                        )
                    )

        for gk, (gsrc, gline) in sorted(sql_guards.items()):
            fn_id = f"fn:{gk}"
            function_symbol_map[gk] = fn_id
            nodes.append(
                AtlasNode(
                    id=fn_id,
                    tier="truth",
                    subkind="sql_function",
                    label=f"{gk}()",
                    source_file=gsrc,
                    line=gline,
                    status="clean",
                    role="mechanism",
                    cluster="db_guard",
                    summary=f"Database guard/function `{gk}` ({provider}).",
                )
            )

        obs_source = "static_ast"
        if pg_dsn:
            live_tables, obs_source = probe_live_catalog_tables(pg_dsn)
            for tbl_key, (src_file, lineno, _, model_name) in sorted(prisma_models.items()):
                if tbl_key not in live_tables:
                    findings.append(
                        RawCandidateFinding(
                            rule_code="TRUTH-002",
                            node_id=f"t:{tbl_key}",
                            source_file=src_file,
                            line=lineno,
                            title=f"Prisma model `{model_name}` absent from live database catalog",
                            detail=f"Read-only catalog probe ({obs_source}) did not find `{tbl_key}`.",
                            remediation="Apply Prisma migrations on the target database.",
                        )
                    )

        return TruthExtractionResult(
            nodes=nodes,
            table_symbol_map=table_symbol_map,
            function_symbol_map=function_symbol_map,
            findings=findings,
            observation_source=obs_source,
        )
