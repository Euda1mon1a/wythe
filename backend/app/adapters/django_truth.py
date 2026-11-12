"""Tier 1 Adapter: Django ORM (`models.Model`) + Django Migrations + Live DB Catalog."""

from __future__ import annotations

import ast
from pathlib import Path

from app.adapters.base import RawCandidateFinding, TruthExtractionResult
from app.adapters.db_catalog_probe import (
    infer_table_role,
    is_migration_meta_table,
    parse_sql_ddl_objects,
    probe_live_catalog_tables,
)
from app.schemas.atlas import AtlasNode

_DJANGO_MODEL_BASES = frozenset({"Model", "AbstractUser", "AbstractBaseUser", "TimeStampedModel"})


def _infer_app_label(py_file: Path, base_dir: Path) -> str:
    rel_parts = py_file.relative_to(base_dir).parts
    if py_file.name == "models.py" and len(rel_parts) >= 2:
        return rel_parts[-2].lower()
    if "models" in rel_parts:
        idx = rel_parts.index("models")
        if idx >= 1:
            return rel_parts[idx - 1].lower()
    return base_dir.name.lower()


def _extract_django_models(
    py_file: Path, rel_path: str, app_label: str
) -> list[tuple[str, str, int, list[str], str]]:
    try:
        tree = ast.parse(py_file.read_text(encoding="utf-8"))
    except (OSError, UnicodeError, SyntaxError):
        return []

    found: list[tuple[str, str, int, list[str], str]] = []
    for node in tree.body:
        if not isinstance(node, ast.ClassDef):
            continue
        base_names = {
            b.id if isinstance(b, ast.Name) else b.attr if isinstance(b, ast.Attribute) else ""
            for b in node.bases
        }
        if not (base_names & _DJANGO_MODEL_BASES):
            continue

        is_abstract = False
        is_proxy = False
        explicit_table: str | None = None
        cols: list[str] = []

        for stmt in node.body:
            if isinstance(stmt, ast.ClassDef) and stmt.name == "Meta":
                for mstmt in stmt.body:
                    if isinstance(mstmt, ast.Assign):
                        for t in mstmt.targets:
                            if isinstance(t, ast.Name) and isinstance(mstmt.value, ast.Constant):
                                if t.id == "abstract" and mstmt.value.value is True:
                                    is_abstract = True
                                elif t.id == "proxy" and mstmt.value.value is True:
                                    is_proxy = True
                                elif t.id == "db_table" and isinstance(mstmt.value.value, str):
                                    explicit_table = mstmt.value.value.strip().lower()
            elif isinstance(stmt, ast.Assign) and isinstance(stmt.value, ast.Call):
                fn = stmt.value.func
                fn_name = fn.id if isinstance(fn, ast.Name) else fn.attr if isinstance(fn, ast.Attribute) else ""
                if fn_name.endswith(("Field", "Key")):
                    for t in stmt.targets:
                        if isinstance(t, ast.Name) and t.id != "objects":
                            cols.append(t.id)

        if is_abstract or is_proxy:
            continue
        tbl_key = explicit_table or f"{app_label}_{node.name.lower()}"
        doc = (ast.get_docstring(node) or "").strip().splitlines()
        summary = doc[0].strip() if doc else f"Django model `{node.name}` (`{tbl_key}`)."
        found.append((node.name, tbl_key, node.lineno, cols[:40], summary))
    return found


def _extract_django_migrations(
    mig_file: Path, app_label: str
) -> tuple[set[str], dict[str, int]]:
    tables: set[str] = set()
    guards: dict[str, int] = {}
    try:
        tree = ast.parse(mig_file.read_text(encoding="utf-8"))
    except (OSError, UnicodeError, SyntaxError):
        return tables, guards

    for sub in ast.walk(tree):
        if isinstance(sub, ast.Call):
            fn = sub.func
            fn_name = fn.id if isinstance(fn, ast.Name) else fn.attr if isinstance(fn, ast.Attribute) else ""
            if fn_name == "CreateModel":
                model_name = ""
                custom_tbl = ""
                for kw in sub.keywords:
                    if kw.arg == "name" and isinstance(kw.value, ast.Constant) and isinstance(kw.value.value, str):
                        model_name = kw.value.value
                    elif kw.arg == "options" and isinstance(kw.value, ast.Dict):
                        for k, v in zip(kw.value.keys, kw.value.values, strict=False):
                            if (
                                isinstance(k, ast.Constant)
                                and k.value == "db_table"
                                and isinstance(v, ast.Constant)
                                and isinstance(v.value, str)
                            ):
                                custom_tbl = v.value.lower()
                if model_name:
                    tables.add(custom_tbl or f"{app_label}_{model_name.lower()}")
            elif fn_name == "RunSQL" and sub.args and isinstance(sub.args[0], ast.Constant) and isinstance(sub.args[0].value, str):
                sql_t, sql_g = parse_sql_ddl_objects(sub.args[0].value)
                tables |= set(sql_t.keys())
                for gk in sql_g:
                    guards[gk] = sub.lineno
    return tables, guards


class DjangoOrmAdapter:
    """Extracts Django ORM models, Django migration operations, and optional live catalog checks."""

    name = "django-orm"

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

        orm_tables: dict[str, tuple[str, int, list[str], str, list[str]]] = {}
        mig_tables: set[str] = set()
        sql_guards: dict[str, tuple[str, int]] = {}
        has_migration_files = False

        for py_file in sorted(base_dir.rglob("*.py")):
            if any(p in py_file.parts for p in (".venv", "venv", "node_modules", "__pycache__")):
                continue
            rel_path = py_file.relative_to(repo_root).as_posix()
            if "migrations" in py_file.parts and py_file.name != "__init__.py":
                has_migration_files = True
                idx = py_file.parts.index("migrations")
                app_lbl = py_file.parts[idx - 1].lower() if idx >= 1 else "app"
                mtbls, mguards = _extract_django_migrations(py_file, app_lbl)
                mig_tables |= mtbls
                for gk, gline in mguards.items():
                    sql_guards[gk] = (rel_path, gline)
            elif py_file.name == "models.py" or "models" in py_file.parts:
                app_lbl = _infer_app_label(py_file, base_dir)
                for cls_name, tbl_key, lineno, cols, summary in _extract_django_models(py_file, rel_path, app_lbl):
                    if tbl_key not in orm_tables:
                        orm_tables[tbl_key] = (rel_path, lineno, cols, summary, [cls_name])
                    else:
                        orm_tables[tbl_key][4].append(cls_name)

        for tbl_key in sorted(set(orm_tables.keys()) | mig_tables):
            if is_migration_meta_table(tbl_key):
                continue
            node_id = f"t:{tbl_key}"
            if tbl_key in orm_tables:
                src_file, lineno, cols, summary, cls_names = orm_tables[tbl_key]
                for cname in cls_names:
                    table_symbol_map[cname] = node_id
            else:
                src_file, lineno, cols, summary = f"{backend_subdir}/migrations", 1, [], f"Django migration table `{tbl_key}`."
            table_symbol_map[tbl_key] = node_id
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

        if has_migration_files:
            for tbl_key, (src_file, lineno, _, _, cls_names) in sorted(orm_tables.items()):
                if tbl_key not in mig_tables:
                    findings.append(
                        RawCandidateFinding(
                            rule_code="TRUTH-002",
                            node_id=f"t:{tbl_key}",
                            source_file=src_file,
                            line=lineno,
                            title=f"Django model `{cls_names[0]}` (`{tbl_key}`) missing CreateModel migration",
                            detail=f"`{src_file}` declares `{cls_names[0]}`, but no Django migration creates `{tbl_key}`.",
                            remediation="Run `python manage.py makemigrations` and commit the migration.",
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
                    summary=f"Database function / trigger `{gk}`.",
                )
            )

        obs_source = "static_ast"
        if pg_dsn:
            live_tables, obs_source = probe_live_catalog_tables(pg_dsn)
            for tbl_key, (src_file, lineno, _, _, cls_names) in sorted(orm_tables.items()):
                if tbl_key not in live_tables:
                    findings.append(
                        RawCandidateFinding(
                            rule_code="TRUTH-002",
                            node_id=f"t:{tbl_key}",
                            source_file=src_file,
                            line=lineno,
                            title=f"Django model `{cls_names[0]}` absent from live database catalog",
                            detail=f"Read-only catalog probe ({obs_source}) did not find `{tbl_key}`.",
                            remediation="Run `python manage.py migrate` on the target database.",
                        )
                    )

        return TruthExtractionResult(
            nodes=nodes,
            table_symbol_map=table_symbol_map,
            function_symbol_map=function_symbol_map,
            findings=findings,
            observation_source=obs_source,
        )
