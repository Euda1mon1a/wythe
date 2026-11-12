"""Tier 1 Adapter: Drizzle ORM (`pgTable` / `mysqlTable` / `sqliteTable`) + SQL Migrations."""

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

_DRIZZLE_SCHEMA_VAR_RE = re.compile(
    r"""(?:export\s+)?const\s+(?P<var>[A-Za-z_]\w*)\s*=\s*(?:pgSchema|mysqlSchema)\(\s*['"](?P<sch>[^'"]+)['"]\s*\)"""
)
_DRIZZLE_TABLE_RE = re.compile(
    r"""(?:export\s+)?const\s+(?P<sym>[A-Za-z_]\w*)\s*=\s*(?P<fn>pgTable|mysqlTable|sqliteTable|[A-Za-z_]\w*\.table)\s*\(\s*['"](?P<tbl>[^'"]+)['"]\s*,\s*\{(?P<body>[\s\S]*?)\}""",
    re.MULTILINE,
)
_COL_PROP_RE = re.compile(r"""^\s*(?P<col>[A-Za-z_]\w*)\s*:""", re.MULTILINE)


class DrizzleOrmAdapter:
    """Inspects TypeScript Drizzle table definitions, SQL migrations, and optional live DB catalog."""

    name = "drizzle-orm"

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

        # tbl_key -> (rel_file, lineno, cols, dialect, ts_symbols)
        drizzle_tables: dict[str, tuple[str, int, list[str], str, list[str]]] = {}

        for ts_file in sorted(base_dir.rglob("*.ts")):
            if any(p in ts_file.parts for p in ("node_modules", ".next", "dist", "build")):
                continue
            try:
                text = ts_file.read_text(encoding="utf-8")
            except (OSError, UnicodeError):
                continue
            if "Table(" not in text and ".table(" not in text:
                continue
            rel_file = ts_file.relative_to(repo_root).as_posix()
            schema_vars = {
                m.group("var"): m.group("sch").lower()
                for m in _DRIZZLE_SCHEMA_VAR_RE.finditer(text)
            }
            for m in _DRIZZLE_TABLE_RE.finditer(text):
                sym = m.group("sym")
                fn = m.group("fn")
                raw_tbl = m.group("tbl").lower()
                lineno = text.count("\n", 0, m.start()) + 1
                sch = "public"
                if "." in fn:
                    svar = fn.split(".", 1)[0]
                    sch = schema_vars.get(svar, "public")
                dialect = (
                    "mysql"
                    if "mysql" in fn
                    else "sqlite"
                    if "sqlite" in fn
                    else "postgresql"
                )
                tbl_key = raw_tbl if sch == "public" else f"{sch}.{raw_tbl}"
                cols = [cm.group("col") for cm in _COL_PROP_RE.finditer(m.group("body"))][:40]
                if tbl_key not in drizzle_tables:
                    drizzle_tables[tbl_key] = (rel_file, lineno, cols, dialect, [sym])
                else:
                    drizzle_tables[tbl_key][4].append(sym)

        sql_tables: dict[str, tuple[str, int, list[str]]] = {}
        sql_guards: dict[str, tuple[str, int]] = {}
        sql_dirs = [base_dir / "drizzle", repo_root / "drizzle", base_dir / "migrations", base_dir]
        seen_sql: set[Path] = set()
        for sdir in sql_dirs:
            if not sdir.is_dir():
                continue
            pat = "*.sql" if sdir.name in ("drizzle", "migrations") else "schema.sql"
            for sfile in sorted(sdir.rglob(pat)):
                if sfile in seen_sql or "node_modules" in sfile.parts:
                    continue
                seen_sql.add(sfile)
                rel_s = sfile.relative_to(repo_root).as_posix()
                t_objs, g_objs = parse_sql_ddl_objects(sfile.read_text(encoding="utf-8", errors="replace"))
                for tk, (tline, tcols) in t_objs.items():
                    sql_tables[tk] = (rel_s, tline, tcols)
                for gk, gline in g_objs.items():
                    sql_guards[gk] = (rel_s, gline)

        for tbl_key in sorted(set(drizzle_tables.keys()) | set(sql_tables.keys())):
            if is_migration_meta_table(tbl_key):
                continue
            node_id = f"t:{tbl_key}"
            if tbl_key in drizzle_tables:
                src_file, lineno, cols, dialect, syms = drizzle_tables[tbl_key]
                for s in syms:
                    table_symbol_map[s] = node_id
                summary = f"Drizzle `{dialect}` table `{tbl_key}` (symbol `{syms[0]}`)."
            else:
                src_file, lineno, cols = sql_tables[tbl_key]
                summary = f"Drizzle SQL migration table `{tbl_key}`."
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

        if seen_sql:
            for tbl_key, (src_file, lineno, _, _, syms) in sorted(drizzle_tables.items()):
                if tbl_key not in sql_tables:
                    findings.append(
                        RawCandidateFinding(
                            rule_code="TRUTH-002",
                            node_id=f"t:{tbl_key}",
                            source_file=src_file,
                            line=lineno,
                            title=f"Drizzle table `{syms[0]}` (`{tbl_key}`) missing from SQL migrations",
                            detail=f"`{src_file}` defines `{tbl_key}`, but no generated SQL migration creates it.",
                            remediation="Run `drizzle-kit generate` to synchronize SQL migration artifacts.",
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
                    summary=f"Database stored function / trigger `{gk}`.",
                )
            )

        obs_source = "static_ast"
        if pg_dsn:
            live_tables, obs_source = probe_live_catalog_tables(pg_dsn)
            for tbl_key, (src_file, lineno, _, _, syms) in sorted(drizzle_tables.items()):
                if tbl_key not in live_tables:
                    findings.append(
                        RawCandidateFinding(
                            rule_code="TRUTH-002",
                            node_id=f"t:{tbl_key}",
                            source_file=src_file,
                            line=lineno,
                            title=f"Drizzle table `{syms[0]}` absent from live database catalog",
                            detail=f"Read-only catalog probe ({obs_source}) did not find `{tbl_key}`.",
                            remediation="Apply Drizzle migrations on the target database.",
                        )
                    )

        return TruthExtractionResult(
            nodes=nodes,
            table_symbol_map=table_symbol_map,
            function_symbol_map=function_symbol_map,
            findings=findings,
            observation_source=obs_source,
        )
