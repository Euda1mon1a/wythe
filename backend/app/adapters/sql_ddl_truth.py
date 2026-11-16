"""Tier 1 Adapter: SQL DDL + Inline SQLite/PostgreSQL/JSONL Stores + Declarative Registries."""

from __future__ import annotations

import re
from pathlib import Path, PurePosixPath

from app.adapters.base import RawCandidateFinding, TruthExtractionResult
from app.adapters.db_catalog_probe import (
    clean_sql_ident,
    is_migration_meta_table,
    parse_sql_ddl_objects,
    probe_live_catalog_tables,
)
from app.adapters.inline_store_truth import (
    InlineStoreObject,
    _sanitize_stem,
    infer_sql_file_engine,
    parse_inline_create_tables,
    reconcile_sql_and_inline_stores,
    scan_inline_stores,
)
from app.adapters.registry_sources import extract_registry_truth_nodes
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
    """Extracts SQL DDL schemas/migrations, inline SQLite/PG/JSONL stores, JSON registries, and catalog drift."""

    name = "sql-ddl"

    def extract(
        self,
        repo_root: Path,
        backend_subdir: str,
        pg_dsn: str | None = None,
    ) -> TruthExtractionResult:
        real_root = repo_root.resolve()
        function_symbol_map: dict[str, str] = {}
        findings: list[RawCandidateFinding] = []
        notes: list[str] = []

        scan_roots: list[Path] = []
        if backend_subdir not in ("", "."):
            raw_be = real_root / backend_subdir
            if raw_be.is_symlink() or not raw_be.resolve().is_relative_to(real_root) or not raw_be.resolve().is_dir():
                notes.append("SQL DDL backend root is absent, symlinked, or outside the repository; skipping backend_subdir.")
            else:
                scan_roots.append(raw_be.resolve())
        scan_roots.append(real_root)

        ddl_tables: dict[str, tuple[str, int, list[str], str]] = {}
        extra_sqlite_sql: list[InlineStoreObject] = []
        sql_guards: dict[str, tuple[str, int]] = {}
        sql_files: list[Path] = []
        for root in dict.fromkeys(scan_roots):
            if not root.is_dir():
                continue
            for sf in sorted(root.rglob("*.sql")):
                if any(p in sf.parts for p in ("node_modules", "vendor", ".venv", ".git")):
                    continue
                if sf.name.endswith(".down.sql") or sf.is_symlink():
                    continue
                sf_real = sf.resolve()
                if not sf_real.is_relative_to(real_root):
                    continue
                if sf_real not in sql_files:
                    sql_files.append(sf_real)

        for sf in sql_files:
            rel_s = sf.relative_to(real_root).as_posix()
            text = sf.read_text(encoding="utf-8", errors="replace")
            f_eng = infer_sql_file_engine(rel_s, text)
            t_objs, g_objs = parse_sql_ddl_objects(text)
            balanced = parse_inline_create_tables(text)
            for (raw_sch, b_tbl), (b_off, b_cols) in balanced.items():
                b_key = b_tbl if raw_sch in ("", "public", "main", "dbo") else f"{raw_sch}.{b_tbl}"
                if b_key not in t_objs or (b_cols and not t_objs[b_key][1]):
                    t_objs[b_key] = (b_off + 1, b_cols)

            for tk, (tline, tcols) in t_objs.items():
                if tk in ddl_tables and ddl_tables[tk][3] != f_eng and "sqlite" in {ddl_tables[tk][3], f_eng}:
                    if f_eng == "sqlite":
                        db_st = _sanitize_stem(PurePosixPath(rel_s).stem) or "main"
                        extra_sqlite_sql.append(
                            InlineStoreObject("sqlite", db_st, tk.split(".", 1)[-1], rel_s, tline, tcols)
                        )
                    else:
                        prev_src, prev_ln, prev_cols, _ = ddl_tables[tk]
                        db_st = _sanitize_stem(PurePosixPath(prev_src).stem) or "main"
                        extra_sqlite_sql.append(
                            InlineStoreObject("sqlite", db_st, tk.split(".", 1)[-1], prev_src, prev_ln, prev_cols)
                        )
                        ddl_tables[tk] = (rel_s, tline, tcols, f_eng)
                elif tk not in ddl_tables or tcols:
                    prev_cols = ddl_tables[tk][2] if tk in ddl_tables else []
                    merged_cols = list(dict.fromkeys([*prev_cols, *tcols]))[:40]
                    ddl_tables[tk] = (rel_s, tline, merged_cols, f_eng)
            for gk, gline in g_objs.items():
                sql_guards[gk] = (rel_s, gline)

        inline_stores = [*extra_sqlite_sql, *scan_inline_stores(real_root, backend_subdir)]
        nodes, table_symbol_map, ambiguous_bare, ddl_node_ids = reconcile_sql_and_inline_stores(
            ddl_tables, inline_stores
        )
        if ambiguous_bare:
            pairs_txt = ", ".join(f"`{k}` -> {v}" for k, v in sorted(ambiguous_bare.items()))
            notes.append(f"Disambiguated colliding bare store names across engines: {pairs_txt}.")

        reg_nodes, reg_sym_map = extract_registry_truth_nodes(real_root)
        existing_ids = {n.id for n in nodes}
        for rnode in reg_nodes:
            if rnode.id not in existing_ids:
                nodes.append(rnode)
                existing_ids.add(rnode.id)
        for rk, rv in reg_sym_map.items():
            table_symbol_map.setdefault(rk, rv)

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
            is_sqlite_dsn = pg_dsn.lower().startswith("sqlite:")
            for tbl_key, (src_file, lineno, _, sql_eng) in sorted(ddl_tables.items()):
                if is_migration_meta_table(tbl_key):
                    continue
                if is_sqlite_dsn and sql_eng == "postgres":
                    continue
                if not is_sqlite_dsn and sql_eng == "sqlite":
                    continue
                if tbl_key not in live_tables:
                    findings.append(
                        RawCandidateFinding(
                            rule_code="TRUTH-002",
                            node_id=ddl_node_ids.get(tbl_key, f"t:{tbl_key}"),
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
            notes=notes,
        )
