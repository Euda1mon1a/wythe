"""Tier 1 Adapter: SQL DDL + Migrations (`sqlc`, `golang-migrate`, `goose`, `Flyway`, `sqlx`)."""

from __future__ import annotations

import re
from pathlib import Path

from app.adapters.base import RawCandidateFinding, TruthExtractionResult
from app.adapters.db_catalog_probe import (
    clean_sql_ident,
    infer_table_role,
    is_migration_meta_table,
    parse_sql_ddl_objects,
    probe_live_catalog_tables,
)
from app.schemas.atlas import AtlasNode

_SQLC_BLOCK_RE = re.compile(
    r"""--\s*name:\s*(?P<qname>[A-Za-z_]\w*)\s*:(?P<qkind>\w+)\s*\n(?P<sql>[\s\S]*?;)\s*(?=--\s*name:|\Z)"""
)
_SQL_READ_TBL_RE = re.compile(
    r"""\b(?:FROM|JOIN)\s+(?P<t>(?:["`\[][A-Za-z_]\w*["`\]]|[A-Za-z_]\w*)(?:\.(?:["`\[][A-Za-z_]\w*["`\]]|[A-Za-z_]\w*))?)""",
    re.IGNORECASE,
)
_SQL_WRITE_TBL_RE = re.compile(
    r"""\b(?:INSERT\s+INTO|UPDATE|DELETE\s+FROM)\s+(?P<t>(?:["`\[][A-Za-z_]\w*["`\]]|[A-Za-z_]\w*)(?:\.(?:["`\[][A-Za-z_]\w*["`\]]|[A-Za-z_]\w*))?)""",
    re.IGNORECASE,
)


def _norm_sql_ref(raw: str) -> str:
    if "." in raw:
        sch, tbl = raw.split(".", 1)
        sc = clean_sql_ident(sch)
        tc = clean_sql_ident(tbl)
        return tc if sc in ("public", "main", "dbo") else f"{sc}.{tc}"
    return clean_sql_ident(raw)


class SqlDdlTruthAdapter:
    """Extracts pure SQL DDL schemas/migrations, sqlc query bindings, and live DB catalog drift."""

    name = "sql-ddl"

    def extract(
        self,
        repo_root: Path,
        backend_subdir: str,
        pg_dsn: str | None = None,
    ) -> TruthExtractionResult:
        base_dir = (repo_root / backend_subdir).resolve() if backend_subdir not in ("", ".") else repo_root

        nodes: list[AtlasNode] = []
        table_symbol_map: dict[str, str] = {}
        function_symbol_map: dict[str, str] = {}
        findings: list[RawCandidateFinding] = []

        ddl_tables: dict[str, tuple[str, int, list[str]]] = {}
        sql_guards: dict[str, tuple[str, int]] = {}
        sql_files: list[Path] = []
        for root in dict.fromkeys([base_dir, repo_root]):
            if not root.is_dir():
                continue
            for sf in sorted(root.rglob("*.sql")):
                if any(p in sf.parts for p in ("node_modules", "vendor", ".venv", ".git")):
                    continue
                if sf.name.endswith(".down.sql"):
                    continue
                if sf not in sql_files:
                    sql_files.append(sf)

        for sf in sql_files:
            rel_s = sf.relative_to(repo_root).as_posix()
            text = sf.read_text(encoding="utf-8", errors="replace")
            t_objs, g_objs = parse_sql_ddl_objects(text)
            for tk, (tline, tcols) in t_objs.items():
                if tk not in ddl_tables or tcols:
                    ddl_tables[tk] = (rel_s, tline, tcols)
            for gk, gline in g_objs.items():
                sql_guards[gk] = (rel_s, gline)

        for tbl_key, (src_file, lineno, cols) in sorted(ddl_tables.items()):
            if is_migration_meta_table(tbl_key):
                continue
            node_id = f"t:{tbl_key}"
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
                    summary=f"SQL DDL table `{tbl_key}` ({src_file}).",
                    columns=cols,
                )
            )

        # Extract sqlc `-- name: QueryName :one|:many|:exec` bindings into table_symbol_map
        for sf in sql_files:
            text = sf.read_text(encoding="utf-8", errors="replace")
            if "-- name:" not in text:
                continue
            for m in _SQLC_BLOCK_RE.finditer(text):
                qname = m.group("qname")
                sql_body = m.group("sql")
                write_refs = [_norm_sql_ref(w.group("t")) for w in _SQL_WRITE_TBL_RE.finditer(sql_body)]
                read_refs = [_norm_sql_ref(r.group("t")) for r in _SQL_READ_TBL_RE.finditer(sql_body)]
                for wref in write_refs:
                    if wref in table_symbol_map:
                        table_symbol_map[f"sqlc:write:{qname}"] = table_symbol_map[wref]
                for rref in read_refs:
                    if rref not in write_refs and rref in table_symbol_map:
                        table_symbol_map[f"sqlc:read:{qname}"] = table_symbol_map[rref]

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
                    summary=f"SQL stored function / trigger `{gk}`.",
                )
            )

        obs_source = "static_ast"
        if pg_dsn:
            live_tables, obs_source = probe_live_catalog_tables(pg_dsn)
            for tbl_key, (src_file, lineno, _) in sorted(ddl_tables.items()):
                if is_migration_meta_table(tbl_key):
                    continue
                if tbl_key not in live_tables:
                    findings.append(
                        RawCandidateFinding(
                            rule_code="TRUTH-002",
                            node_id=f"t:{tbl_key}",
                            source_file=src_file,
                            line=lineno,
                            title=f"SQL DDL table `{tbl_key}` absent from live database catalog",
                            detail=f"Read-only catalog probe ({obs_source}) did not find `{tbl_key}`.",
                            remediation="Apply pending SQL migrations on the target database.",
                        )
                    )

        return TruthExtractionResult(
            nodes=nodes,
            table_symbol_map=table_symbol_map,
            function_symbol_map=function_symbol_map,
            findings=findings,
            observation_source=obs_source,
        )
