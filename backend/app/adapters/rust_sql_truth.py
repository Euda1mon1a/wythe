"""Tier 1 Adapter: Rust SQL & ORM Truth (`sqlx`, `Diesel`, `SeaORM`, and raw SQL migrations)."""

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

_DIESEL_TABLE_RE = re.compile(
    r"""\b(?:diesel::)?table!\s*\{\s*(?:(?P<sch>[A-Za-z_]\w*)\s*\.\s*)?(?P<tbl>[A-Za-z_]\w*)\s*\([^)]*\)\s*\{(?P<body>[\s\S]*?)\}\s*\}"""
)
_DIESEL_COL_RE = re.compile(r"^[ \t]*(?P<col>[A-Za-z_]\w*)\s*->", re.MULTILINE)
_SEAORM_TABLE_RE = re.compile(
    r"""#\[\s*sea_orm\s*\([^)]*?\btable_name\s*=\s*"(?P<tbl>[^"]+)"(?P<rest>[^)]*)\)"""
)
_SEAORM_SCHEMA_RE = re.compile(r"""\bschema_name\s*=\s*"(?P<sch>[^"]+)" """.strip())
_RUST_STRUCT_FIELD_RE = re.compile(r"^[ \t]*pub\s+(?P<col>[A-Za-z_]\w*)\s*:", re.MULTILINE)
_SQL_WRITE_REF_RE = re.compile(
    r"""\b(?:INSERT\s+INTO|UPDATE|DELETE\s+FROM)\s+["`]?([A-Za-z_]\w*(?:\.[A-Za-z_]\w*)?)["`]?""",
    re.IGNORECASE,
)
_SQL_READ_REF_RE = re.compile(
    r"""\b(?:FROM|JOIN)\s+["`]?([A-Za-z_]\w*(?:\.[A-Za-z_]\w*)?)["`]?""",
    re.IGNORECASE,
)


def _norm_tbl(raw: str) -> str:
    cleaned = raw.replace('"', "").replace("`", "").lower()
    if "." in cleaned:
        sch, t = cleaned.split(".", 1)
        return t if sch in ("public", "main", "dbo") else f"{sch}.{t}"
    return cleaned


class RustSqlTruthAdapter:
    """Extracts `sqlx` migrations/query files, `Diesel` `table!`, and `SeaORM` entities."""

    name = "rust-sql"

    def extract(
        self,
        repo_root: Path,
        backend_subdir: str,
        pg_dsn: str | None = None,
    ) -> TruthExtractionResult:
        base_dir = repo_root if backend_subdir in ("", ".") else repo_root / backend_subdir
        if backend_subdir in ("", ".") and (repo_root / "src-tauri" / "Cargo.toml").is_file():
            base_dir = repo_root / "src-tauri"

        nodes: list[AtlasNode] = []
        table_symbol_map: dict[str, str] = {}
        function_symbol_map: dict[str, str] = {}
        findings: list[RawCandidateFinding] = []

        ddl_tables: dict[str, tuple[str, int, list[str]]] = {}
        sql_guards: dict[str, tuple[str, int]] = {}
        orm_tables: dict[str, tuple[str, int, list[str], str, list[str]]] = {}
        query_sql_files: list[tuple[Path, str]] = []

        search_roots = [base_dir]
        if base_dir != repo_root:
            for extra in ("migrations", "db", "sql", "crates"):
                if (repo_root / extra).is_dir():
                    search_roots.append(repo_root / extra)

        seen_files: set[Path] = set()
        for root in search_roots:
            if not root.is_dir():
                continue
            for sf in sorted(root.rglob("*.sql")):
                if sf in seen_files or any(p in sf.parts for p in ("target", "node_modules", ".git")):
                    continue
                if sf.name == "down.sql" or sf.name.endswith(".down.sql"):
                    continue
                seen_files.add(sf)
                rel_s = sf.relative_to(repo_root).as_posix()
                text = sf.read_text(encoding="utf-8", errors="replace")
                t_objs, g_objs = parse_sql_ddl_objects(text)
                for tk, (tline, tcols) in t_objs.items():
                    if tk not in ddl_tables or tcols:
                        ddl_tables[tk] = (rel_s, tline, tcols)
                for gk, gline in g_objs.items():
                    sql_guards[gk] = (rel_s, gline)
                if not t_objs and not g_objs:
                    query_sql_files.append((sf, text))

        seen_rs_files: set[Path] = set()
        for root in search_roots:
            if not root.is_dir():
                continue
            for rs_file in sorted(root.rglob("*.rs")):
                if rs_file in seen_rs_files or any(p in rs_file.parts for p in ("target", "node_modules", ".git")):
                    continue
                seen_rs_files.add(rs_file)
                rel_rs = rs_file.relative_to(repo_root).as_posix()
                rs_text = rs_file.read_text(encoding="utf-8", errors="replace")

                for dm in _DIESEL_TABLE_RE.finditer(rs_text):
                    sch = (dm.group("sch") or "public").lower()
                    raw_t = dm.group("tbl").lower()
                    tbl_key = raw_t if sch == "public" else f"{sch}.{raw_t}"
                    lineno = rs_text.count("\n", 0, dm.start()) + 1
                    cols = [cm.group("col") for cm in _DIESEL_COL_RE.finditer(dm.group("body"))][:40]
                    orm_tables[tbl_key] = (
                        rel_rs,
                        lineno,
                        cols,
                        f"Diesel `table!` schema `{tbl_key}`.",
                        [raw_t, f"{raw_t}::table"],
                    )

                for sm in _SEAORM_TABLE_RE.finditer(rs_text):
                    raw_t = sm.group("tbl").lower()
                    sch_m = _SEAORM_SCHEMA_RE.search(sm.group("rest") or "")
                    sch = sch_m.group("sch").lower() if sch_m else "public"
                    tbl_key = raw_t if sch == "public" else f"{sch}.{raw_t}"
                    lineno = rs_text.count("\n", 0, sm.start()) + 1
                    tail_struct = rs_text[sm.end() : sm.end() + 800]
                    cols = [cm.group("col") for cm in _RUST_STRUCT_FIELD_RE.finditer(tail_struct)][:40]
                    mod_stem = rs_file.stem
                    orm_tables[tbl_key] = (
                        rel_rs,
                        lineno,
                        cols,
                        f"SeaORM entity `{mod_stem}` -> table `{tbl_key}`.",
                        [mod_stem, raw_t, f"{mod_stem}::Entity", f"{mod_stem}::ActiveModel"],
                    )

        all_keys = sorted(set(ddl_tables.keys()) | set(orm_tables.keys()))
        for tbl_key in all_keys:
            if is_migration_meta_table(tbl_key):
                continue
            node_id = f"t:{tbl_key}"
            if tbl_key in orm_tables:
                src_file, lineno, cols, summary, syms = orm_tables[tbl_key]
                if not cols and tbl_key in ddl_tables:
                    cols = ddl_tables[tbl_key][2]
                for s in syms:
                    table_symbol_map[s] = node_id
            else:
                src_file, lineno, cols = ddl_tables[tbl_key]
                summary = f"Rust/SQL migration table `{tbl_key}` ({src_file})."

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

        # Bind `sqlx::query_file!("...")` SQL files to target tables
        for qf, qtext in query_sql_files:
            rel_base = qf.relative_to(base_dir).as_posix() if qf.is_relative_to(base_dir) else qf.name
            w_refs = [_norm_tbl(m.group(1)) for m in _SQL_WRITE_REF_RE.finditer(qtext)]
            r_refs = [_norm_tbl(m.group(1)) for m in _SQL_READ_REF_RE.finditer(qtext)]
            for key_alias in {rel_base, qf.name}:
                for wr in w_refs:
                    if wr in table_symbol_map:
                        table_symbol_map[f"sqlx_file:write:{key_alias}"] = table_symbol_map[wr]
                for rr in r_refs:
                    if rr not in w_refs and rr in table_symbol_map:
                        table_symbol_map[f"sqlx_file:read:{key_alias}"] = table_symbol_map[rr]

        if ddl_tables and orm_tables:
            for tbl_key, (src_file, lineno, _, _, syms) in sorted(orm_tables.items()):
                if tbl_key not in ddl_tables:
                    findings.append(
                        RawCandidateFinding(
                            rule_code="TRUTH-002",
                            node_id=f"t:{tbl_key}",
                            source_file=src_file,
                            line=lineno,
                            title=f"Rust ORM entity `{syms[0]}` (`{tbl_key}`) missing from SQL migrations",
                            detail=f"`{src_file}` declares `{tbl_key}`, but no SQL migration creates it.",
                            remediation="Add a `migrations/*.sql` (`sqlx`/`diesel`) migration creating the table.",
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
            expected = {k: (v[0], v[1]) for k, v in ddl_tables.items()}
            for k, v in orm_tables.items():
                expected.setdefault(k, (v[0], v[1]))
            for tbl_key, (src_file, lineno) in sorted(expected.items()):
                if not is_migration_meta_table(tbl_key) and tbl_key not in live_tables:
                    findings.append(
                        RawCandidateFinding(
                            rule_code="TRUTH-002",
                            node_id=f"t:{tbl_key}",
                            source_file=src_file,
                            line=lineno,
                            title=f"Rust table `{tbl_key}` absent from live database catalog",
                            detail=f"Read-only catalog probe ({obs_source}) did not find `{tbl_key}`.",
                            remediation="Run `sqlx migrate run` or `diesel migration run` against the target DB.",
                        )
                    )

        return TruthExtractionResult(
            nodes=nodes,
            table_symbol_map=table_symbol_map,
            function_symbol_map=function_symbol_map,
            findings=findings,
            observation_source=obs_source,
        )
