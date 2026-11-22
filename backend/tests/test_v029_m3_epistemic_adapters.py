"""Comprehensive M3 P0/P1 regression tests for epistemic & adapter soundness."""

from __future__ import annotations

import json
import os
import textwrap
from pathlib import Path

from app.adapters.base import TruthExtractionResult
from app.adapters.epistemic_display_checks import load_fabricated_allowlist
from app.adapters.frontend_common import resolve_frontend_import
from app.adapters.postgres_sqlalchemy import PostgresSqlAlchemyAdapter
from app.adapters.python_daemon_routes import _compile_daemon_route_regex
from app.adapters.python_policy_consumption import _strip_sql_literals_and_comments
from app.adapters.python_services import PythonServicesAdapter
from app.adapters.sql_ddl_truth import SqlDdlTruthAdapter
from app.adapters.treesitter_engine import (
    extract_go_routes_cst,
    extract_rust_routes_cst,
)
from app.adapters.typescript_nextjs import (
    TypeScriptNextJsAdapter,
    _collect_pattern_bound_names,
    _extract_ts_http_calls,
    _find_ts_loop_end,
    _skip_ts_quoted,
)
from app.adapters.typescript_react import TypeScriptReactSpaAdapter


def _w(root: Path, rel: str, text: str) -> Path:
    dest = root / rel
    dest.parent.mkdir(parents=True, exist_ok=True)
    dest.write_text(text, encoding="utf-8")
    return dest


def test_p0_3_load_fabricated_allowlist_hardening(tmp_path: Path) -> None:
    """A1/P0-3: strict ignores disk, symlink root & >2MB JSON & non-regular files fail closed."""
    gov = tmp_path / ".wythe" / "governance.json"
    gov.parent.mkdir(parents=True)
    gov.write_text(json.dumps({"fabricated_fallback_allowlist": ["demo-slice"]}), encoding="utf-8")

    assert load_fabricated_allowlist(tmp_path, strict=False) == {"demo-slice"}
    assert load_fabricated_allowlist(tmp_path, strict=True) == set()

    # Symlinked repo_root is rejected even when strict=False
    real_repo = tmp_path / "real_repo"
    (real_repo / ".wythe").mkdir(parents=True)
    (real_repo / ".wythe" / "governance.json").write_text(
        json.dumps({"fabricated_fallback_allowlist": ["sneaky"]}), encoding="utf-8"
    )
    link_repo = tmp_path / "link_repo"
    link_repo.symlink_to(real_repo)
    assert load_fabricated_allowlist(link_repo, strict=False) == set()

    # >2 MB governance.json fails closed
    big_repo = tmp_path / "big_repo"
    (big_repo / ".wythe").mkdir(parents=True)
    (big_repo / ".wythe" / "governance.json").write_text(
        json.dumps({"fabricated_fallback_allowlist": ["x"], "pad": "a" * (2 * 1024 * 1024 + 64)}),
        encoding="utf-8",
    )
    assert load_fabricated_allowlist(big_repo, strict=False) == set()

    # Non-regular FIFO governance.json does not hang or return entries
    fifo_repo = tmp_path / "fifo_repo"
    (fifo_repo / ".wythe").mkdir(parents=True)
    os.mkfifo(fifo_repo / ".wythe" / "governance.json")
    assert load_fabricated_allowlist(fifo_repo, strict=False) == set()


def test_p1_4_daemon_route_qualification_and_fetch_methods(tmp_path: Path) -> None:
    """P1-4: reject root prefix wildcard, require receiver qualification, detect HEAD/OPTIONS & same-line dyn."""
    root_rx = _compile_daemon_route_regex("/", is_prefix=True)
    assert root_rx == r"^(?:/api/v\d+)?//?$" and not root_rx.endswith(".*$")

    _w(
        tmp_path,
        "backend/app/daemon.py",
        textwrap.dedent(
            """\
            from http.server import BaseHTTPRequestHandler
            from fastapi import FastAPI

            class Cache:
                def delete(self, p): return lambda fn: fn
                def tool(self): return lambda fn: fn

            cache = Cache()
            app = FastAPI()

            @cache.delete("/not-a-route")
            def drop_cache():
                return True

            @cache.tool()
            def helper_tool():
                return True

            class Handler(BaseHTTPRequestHandler):
                def do_GET(self):
                    if not self.path.startswith("/"):
                        return
                    if self.path == "/healthz":
                        return
            """
        ),
    )
    _w(
        tmp_path,
        "backend/app/svc.py",
        textwrap.dedent(
            """\
            def fetch_stuff(client, runner):
                a = client.get("/api/users")
                b = runner.run("/api/jobs")
                return a, b
            """
        ),
    )
    truth = TruthExtractionResult(nodes=[], table_symbol_map={}, function_symbol_map={})
    res = PythonServicesAdapter().extract(tmp_path, "backend", truth)
    route_paths = {r.full_path for r in res.routes}
    assert "/not-a-route" not in route_paths
    assert not any("helper_tool" in r.node_id for r in res.routes)
    assert "/" not in route_paths
    assert "/healthz" in route_paths
    # Unqualified .get()/.run() must NOT produce verified e:route: edges
    assert not any("svc.py" in e.source_id and e.target_id.startswith("e:route:") for e in res.edges)

    # Next.js / TS fetch HEAD, OPTIONS, and same-line dynamic method taint isolation
    ts_src = (
        "fetch('/api/head-check', { method: 'HEAD' });\n"
        "fetch('/api/cors-check', { method: 'options' });\n"
        "Promise.all([fetch('/api/static-ok'), fetch('/api/dyn-call', { method: dyn })]);\n"
    )
    calls = _extract_ts_http_calls(ts_src)
    by_path = {path: method for method, path, _ln in calls}
    assert by_path["/api/head-check"] == "HEAD"
    assert by_path["/api/cors-check"] == "OPTIONS"
    assert by_path["/api/static-ok"] == "GET"
    assert by_path["/api/dyn-call"] == "DYNAMIC"


def test_p1_7_iterative_ts_and_cst_walkers_no_recursion_error() -> None:
    """P1-7: deeply nested parens, templates, destructuring, loops, Rust/Go CSTs avoid RecursionError."""
    deep_parens = "(" * 1100 + "1" + ")" * 1100
    assert _find_ts_loop_end(f"for {deep_parens} {{ x(); }}", 3) > 2200

    deep_tpl = "`" + "${" * 1100 + "1" + "}" * 1100 + "`"
    _quote, end_idx = _skip_ts_quoted(deep_tpl, 0)
    assert end_idx == len(deep_tpl)

    deep_pat = "{" * 600 + "a: leafName" + "}" * 600
    bound: set[str] = set()
    _collect_pattern_bound_names(deep_pat, bound, allow_type_colon=True)
    assert "leafName" in bound

    def _norm(*parts: str) -> str:
        return "/" + "/".join(p.strip("/") for p in parts if p and p.strip("/"))

    deep_rust = "fn r() -> Router {\n" + "".join(
        f'Router::new().nest("/r{i}", ' for i in range(600)
    ) + 'Router::new().route("/leaf", get(h))' + ")" * 600 + "\n}"
    rust_routes = extract_rust_routes_cst(deep_rust, _norm)
    assert isinstance(rust_routes, list)

    deep_go = "func r(r chi.Router) {\n" + "".join(
        f'r.Route("/g{i}", func(r chi.Router) {{\n' for i in range(600)
    ) + 'r.Get("/leaf", h)\n' + "})\n" * 600 + "}"
    go_routes = extract_go_routes_cst(deep_go, _norm)
    assert isinstance(go_routes, list)


def test_p1_8_path_containment_symlinks_and_coverage_complete(tmp_path: Path) -> None:
    """P1-8: reject traversal/symlinks with coverage_complete=False; allow macOS /tmp canonical containment."""
    (tmp_path / "frontend" / "src").mkdir(parents=True)
    cur = _w(tmp_path, "frontend/src/page.tsx", "export const x = 1;\n")
    assert resolve_frontend_import("../../../../../../../../etc/hosts", cur, tmp_path / "frontend" / "src", (".ts", ".tsx"), repo_root=tmp_path) is None

    # Symlinked frontend source file -> coverage_complete=False
    outside_ts = tmp_path / "secret.ts"
    outside_ts.write_text("fetch('/api/secret');\n", encoding="utf-8")
    (tmp_path / "frontend" / "src" / "bad_link.tsx").symlink_to(outside_ts)
    _w(tmp_path, "frontend/package.json", '{"dependencies":{"react":"18.0.0"}}')
    spa_res = TypeScriptReactSpaAdapter().extract(tmp_path, "frontend")
    assert spa_res.coverage_complete is False

    # Syntax error in TS/React file -> coverage_complete=False
    bad_syntax_repo = tmp_path / "bad_syntax"
    _w(bad_syntax_repo, "frontend/package.json", '{"dependencies":{"react":"18.0.0"}}')
    _w(bad_syntax_repo, "frontend/src/Broken.tsx", "export function Broken() { return (\n")
    bad_spa = TypeScriptReactSpaAdapter().extract(bad_syntax_repo, "frontend")
    assert bad_spa.coverage_complete is False

    # Next.js symlink rejection -> coverage_complete=False
    next_repo = tmp_path / "next_sym"
    _w(next_repo, "frontend/package.json", '{"dependencies":{"next":"14.0.0"}}')
    (next_repo / "frontend" / "app").mkdir(parents=True)
    (next_repo / "frontend" / "app" / "page.tsx").symlink_to(outside_ts)
    next_res = TypeScriptNextJsAdapter().extract(next_repo, "frontend")
    assert next_res.coverage_complete is False

    # macOS /tmp alias vs resolved /private/tmp containment still succeeds with coverage_complete=True
    if os.path.islink("/tmp"):
        import tempfile
        with tempfile.TemporaryDirectory(dir="/tmp", prefix="wythe_m3_") as td:
            unresolved_repo = Path("/tmp") / Path(td).name
            _w(unresolved_repo, "frontend/package.json", '{"dependencies":{"next":"14.0.0"}}')
            _w(unresolved_repo, "frontend/app/page.tsx", "export default function Page() { return fetch('/api/ok'); }\n")
            ok_res = TypeScriptNextJsAdapter().extract(unresolved_repo, "frontend")
            assert ok_res.coverage_complete is True
            assert any(c.normalized_path == "/api/ok" for c in ok_res.http_calls)


def test_p1_13_python_services_react_spa_and_sql_ddl_truth_coverage(tmp_path: Path) -> None:
    """P1-13: adapters/ no longer skipped for MANIP-001; SPA scans main/lib/api/non-barrel index; SQL DDL coverage_complete."""
    from app.core.policy_context import policy_tokens_scope

    # 1. python_services: adapters/ still emits MANIP-001 + corrupt py degrades coverage_complete
    _w(
        tmp_path,
        "backend/app/models/cap.py",
        textwrap.dedent(
            """\
            from sqlalchemy.orm import DeclarativeBase, Mapped, mapped_column
            class Base(DeclarativeBase): pass
            class CapRule(Base):
                __tablename__ = "cap_rules"
                id: Mapped[int] = mapped_column(primary_key=True)
                max_cap: Mapped[int]
            """
        ),
    )
    _w(
        tmp_path,
        "backend/app/adapters/cap_adapter.py",
        textwrap.dedent(
            """\
            HARDCODED_MAX_CAP = 75
            def load_cap(cursor):
                rows = cursor.execute("SELECT max_cap FROM cap_rules").fetchall()
                return HARDCODED_MAX_CAP if rows else HARDCODED_MAX_CAP
            """
        ),
    )
    _w(tmp_path, "backend/app/adapters/broken_mod.py", "def syntax_err(:\n")

    with policy_tokens_scope(("CAP", "POLICY", "HARDCODED", "DEFAULT")):
        truth = PostgresSqlAlchemyAdapter().extract(tmp_path, "backend")
        svc_res = PythonServicesAdapter().extract(tmp_path, "backend", truth)
    assert svc_res.coverage_complete is False
    assert any(f.rule_code == "MANIP-001" and "cap_adapter.py" in f.source_file for f in svc_res.findings)

    # 2. TypeScriptReactSpaAdapter scans main.tsx, lib/api.ts, non-barrel index.ts, skips pure barrel index.ts
    spa_repo = tmp_path / "spa"
    _w(spa_repo, "frontend/package.json", '{"dependencies":{"react":"18.0.0","vite":"5.0.0"}}')
    _w(spa_repo, "frontend/src/main.tsx", "fetch('/api/bootstrap');\n")
    _w(spa_repo, "frontend/src/lib/api.ts", "export function loadAll() { return fetch('/api/items'); }\n")
    _w(spa_repo, "frontend/src/features/index.ts", "fetch('/api/non-barrel');\n")
    _w(spa_repo, "frontend/src/barrel/index.ts", "export * from '../lib/api';\n")
    spa_res = TypeScriptReactSpaAdapter().extract(spa_repo, "frontend")
    called_targets = {c.normalized_path for c in spa_res.http_calls}
    assert {"/api/bootstrap", "/api/items", "/api/non-barrel"} <= called_targets

    # 3. SqlDdlTruthAdapter degrades coverage_complete=False on corrupt UTF-8 .py
    sql_repo = tmp_path / "sql_repo"
    _w(sql_repo, "backend/schema.sql", "CREATE TABLE items (id INT PRIMARY KEY);\n")
    bad_py = sql_repo / "backend" / "bad_bytes.py"
    bad_py.parent.mkdir(parents=True, exist_ok=True)
    bad_py.write_bytes(b"\xff\xfe\xfd invalid utf8")
    sql_truth = SqlDdlTruthAdapter().extract(sql_repo, "backend")
    assert sql_truth.coverage_complete is False


def test_p1_13_python_policy_consumption_precision_fixes(tmp_path: Path) -> None:
    """P1-13: ARRAY[']'], abs/round casts, self.get_logger(), __tablename__, sibling write_scopes, len(items) > 100."""
    from app.core.policy_context import policy_tokens_scope

    stripped = _strip_sql_literals_and_comments(
        "SELECT * FROM tbl WHERE a = '[' AND b = ']' AND note = 'secret_val'"
    )
    assert "secret_val" not in stripped and "AND b =" in stripped

    # End-to-end policy consumption check on 2-column table with structural guard, casts, telemetry, __tablename__, sibling write
    _w(
        tmp_path,
        "backend/app/models/pol.py",
        textwrap.dedent(
            """\
            from sqlalchemy.orm import DeclarativeBase, Mapped, mapped_column
            class Base(DeclarativeBase): pass
            class GuardRule(Base):
                __tablename__ = "guard_rules"
                id: Mapped[int] = mapped_column(primary_key=True)
                max_cap: Mapped[int]
            """
        ),
    )
    _w(
        tmp_path,
        "backend/app/services/consumer.py",
        textwrap.dedent(
            """\
            from app.models.pol import GuardRule

            class Writer:
                def save(self, cursor):
                    cursor.execute("UPDATE guard_rules SET max_cap = 1")

            class Reader:
                def get_logger(self):
                    return self
                def info(self, msg, **kw):
                    pass
                def read_only(self, cursor, items):
                    tname = GuardRule.__tablename__
                    if len(items) > 100:
                        self.get_logger().info("large_batch", table=tname)
                    rows = cursor.execute("SELECT id, max_cap FROM guard_rules").fetchall()
                    return [{"id": r[0], "t": abs(round(r[1]))} for r in rows]
            """
        ),
    )
    with policy_tokens_scope(("CAP", "POLICY", "HARDCODED", "DEFAULT")):
        truth = PostgresSqlAlchemyAdapter().extract(tmp_path, "backend")
        res = PythonServicesAdapter().extract(tmp_path, "backend", truth)
    assert res.coverage_complete is True
    # Must NOT emit bypassed MANIP-001 on read_only (abs/round used, len(items)>100 is non-policy, logger/tablename/sibling write ignored)
    assert not any(
        f.rule_code == "MANIP-001" and "read_only" in f.title for f in res.findings
    )


def test_p1_13_postgres_sqlalchemy_create_all_ddl_primary_group_schema(tmp_path: Path) -> None:
    """P1-13: create_all + op.add_column ordering, DDL-weighted primary_group, CREATE SCHEMA seen_schemas."""
    _w(
        tmp_path,
        "backend/alembic/versions/001_init.py",
        textwrap.dedent(
            """\
            from alembic import op
            import sqlalchemy as sa
            revision = "001"
            down_revision = None
            def upgrade():
                op.execute("CREATE SCHEMA IF NOT EXISTS analytics")
                Base.metadata.create_all(bind=op.get_bind())
                op.create_table("widgets", sa.Column("id", sa.Integer(), primary_key=True))
                op.add_column("widgets", sa.Column("extra_col", sa.Integer()))
            """
        ),
    )
    _w(
        tmp_path,
        "backend/app/models/all_models.py",
        textwrap.dedent(
            """\
            from sqlalchemy.orm import DeclarativeBase, Mapped, mapped_column
            class PrimaryBase(DeclarativeBase): pass
            class DraftBase(DeclarativeBase): pass

            class Widget(PrimaryBase):
                __tablename__ = "widgets"
                id: Mapped[int] = mapped_column(primary_key=True)

            class GhostDraftA(DraftBase):
                __tablename__ = "ghost_a"
                id: Mapped[int] = mapped_column(primary_key=True)

            class GhostDraftB(DraftBase):
                __tablename__ = "ghost_b"
                id: Mapped[int] = mapped_column(primary_key=True)

            class Metric(PrimaryBase):
                __tablename__ = "metrics"
                __table_args__ = {"schema": "analytics"}
                id: Mapped[int] = mapped_column(primary_key=True)

            class UnseenAudit(PrimaryBase):
                __tablename__ = "unseen_logs"
                __table_args__ = {"schema": "audit_hidden"}
                id: Mapped[int] = mapped_column(primary_key=True)
            """
        ),
    )
    truth = PostgresSqlAlchemyAdapter().extract(tmp_path, "backend")
    by_table = {n.label: n for n in truth.nodes if n.tier == "truth" and n.subkind == "table"}
    # PrimaryBase has DDL overlap (widgets), so it wins over larger non-DDL DraftBase
    assert "widgets" in by_table
    # Uncreated model in CREATE SCHEMA `analytics` MUST emit TRUTH-002 (saw_incremental_ddl_after_create_all=True & seen_schemas includes analytics)
    assert any(
        f.rule_code == "TRUTH-002" and "analytics.metrics" in f.title for f in truth.findings
    )
    # GhostDraftA has no DDL overlap and DraftBase is treated as separate base (not TRUTH-002)
    assert not any(
        f.rule_code == "TRUTH-002" and "ghost_a" in f.title for f in truth.findings
    )
    # Unseen non-public schema `audit_hidden` is omitted from TRUTH-002 with an explicit note
    assert not any(
        f.rule_code == "TRUTH-002" and "unseen_logs" in f.title for f in truth.findings
    )
    assert any("audit_hidden" in n for n in truth.notes)


def test_p0_1_postgres_sqlalchemy_safe_git_error_on_symlinked_git_dir(tmp_path: Path) -> None:
    """P0-1 / Contract #4: symlinked .git triggers SafeGitError cleanly handled without crash."""
    outside_git = tmp_path / "outside_git"
    outside_git.mkdir()
    repo = tmp_path / "repo"
    _w(
        repo,
        "backend/alembic/versions/001_init.py",
        "from alembic import op\n"
        "revision = '001'\n"
        "down_revision = None\n"
        "def upgrade():\n"
        "    op.create_table('other_tbl')\n",
    )
    _w(
        repo,
        "backend/app/models/m.py",
        "from sqlalchemy.orm import DeclarativeBase, Mapped, mapped_column\n"
        "class Base(DeclarativeBase): pass\n"
        "class Item(Base):\n"
        "    __tablename__ = 'items'\n"
        "    id: Mapped[int] = mapped_column(primary_key=True)\n",
    )
    (repo / ".git").symlink_to(outside_git)
    truth = PostgresSqlAlchemyAdapter().extract(repo, "backend")
    assert any(n.label == "items" for n in truth.nodes)


def test_p1_4_python_ast_inspect_head_and_options_routes(tmp_path: Path) -> None:
    """P1-4: python_ast_inspect & FastAPI/Services extract @app.head / @app.options without DISP-004."""
    from app.adapters.python_ast_inspect import parse_python_module
    from app.adapters.python_fastapi import PythonFastApiAdapter

    src = textwrap.dedent(
        """\
        from fastapi import FastAPI
        app = FastAPI()

        @app.head("/api/health")
        def head_health():
            return None

        @app.options("/api/health")
        def options_health():
            return {"allow": "GET,HEAD,OPTIONS"}
        """
    )
    pm = parse_python_module(src, "backend/app/main.py", "app.main")
    assert pm is not None
    assert {(h.http_method, h.subpath) for h in pm.route_handlers} == {
        ("HEAD", "/api/health"),
        ("OPTIONS", "/api/health"),
    }

    _w(tmp_path, "backend/app/main.py", src)
    truth = TruthExtractionResult(nodes=[], table_symbol_map={}, function_symbol_map={})
    fa_res = PythonFastApiAdapter().extract(tmp_path, "backend", truth)
    assert {(r.http_method, r.full_path) for r in fa_res.routes} == {
        ("HEAD", "/api/health"),
        ("OPTIONS", "/api/health"),
    }
    svc_res = PythonServicesAdapter().extract(tmp_path, "backend", truth)
    assert {("HEAD", "/api/health"), ("OPTIONS", "/api/health")} <= {
        (r.http_method, r.full_path) for r in svc_res.routes
    }


def test_c1_1_c1_2_c1_3_nextjs_and_react_containment_fifo_and_const_errors(tmp_path: Path) -> None:
    """C1-1/C1-2/C1-3: out-of-repo invalid UTF-8 symlink, FIFOs, and >4MB const_read_errors."""
    from app.adapters.ts_workspace import MAX_FRONTEND_FILE_BYTES

    # C1-1: Next.js out-of-repo symlink to invalid UTF-8 must not crash and must set coverage_complete=False
    outside = tmp_path / "outside_bad.ts"
    outside.write_bytes(b"\xff\xfe\xfd not utf8")
    next_sym = tmp_path / "next_sym"
    _w(next_sym, "frontend/package.json", '{"dependencies":{"next":"14.0.0"}}')
    _w(next_sym, "frontend/app/page.tsx", "export default function Page() { return <main />; }\n")
    (next_sym / "frontend" / "app" / "evil_link.ts").symlink_to(outside)
    res_sym = TypeScriptNextJsAdapter().extract(next_sym, "frontend")
    assert res_sym.coverage_complete is False

    # C1-2: FIFOs in React and Next.js must set coverage_complete=False
    react_fifo = tmp_path / "react_fifo"
    _w(react_fifo, "frontend/package.json", '{"dependencies":{"react":"18.0.0"}}')
    _w(react_fifo, "frontend/src/App.tsx", "export function App() { return <div />; }\n")
    os.mkfifo(react_fifo / "frontend" / "src" / "fifo.tsx")
    assert TypeScriptReactSpaAdapter().extract(react_fifo, "frontend").coverage_complete is False

    next_fifo = tmp_path / "next_fifo"
    _w(next_fifo, "frontend/package.json", '{"dependencies":{"next":"14.0.0"}}')
    _w(next_fifo, "frontend/app/page.tsx", "export default function Page() { return <main />; }\n")
    os.mkfifo(next_fifo / "frontend" / "app" / "pipe.ts")
    assert TypeScriptNextJsAdapter().extract(next_fifo, "frontend").coverage_complete is False

    # C1-3: Oversized (>4MB) shared const module imported via url_const_resolver sets coverage_complete=False
    big_const_body = "export const API_URL = '/api/big';\n// " + ("x" * (MAX_FRONTEND_FILE_BYTES + 128)) + "\n"
    react_big = tmp_path / "react_big"
    _w(react_big, "frontend/package.json", '{"dependencies":{"react":"18.0.0"}}')
    _w(react_big, "packages/shared/consts.ts", big_const_body)
    _w(
        react_big,
        "frontend/src/App.tsx",
        "import { API_URL } from '../../packages/shared/consts';\n"
        "export function App() { return fetch(API_URL); }\n",
    )
    assert TypeScriptReactSpaAdapter().extract(react_big, "frontend").coverage_complete is False

    next_big = tmp_path / "next_big"
    _w(next_big, "frontend/package.json", '{"dependencies":{"next":"14.0.0"}}')
    _w(next_big, "packages/shared/consts.ts", big_const_body)
    _w(
        next_big,
        "frontend/app/page.tsx",
        "import { API_URL } from '../../packages/shared/consts';\n"
        "export default function Page() { return fetch(API_URL); }\n",
    )
    assert TypeScriptNextJsAdapter().extract(next_big, "frontend").coverage_complete is False


def test_c1_4_c1_5_epistemic_display_lexical_shadowing_and_regex_comments(tmp_path: Path) -> None:
    """C1-4/C1-5: lexical shadowing stops module-level fetch leak; regex // keeps DISP-009 intact."""
    from app.adapters.base import DisplayExtractionResult
    from app.adapters.epistemic_display_checks import analyze_display_confabulation_and_reads

    _w(
        tmp_path,
        "frontend/views/shadow.js",
        textwrap.dedent(
            """\
            const res = await fetch('/api/x');
            const data = await res.json();

            export function helper() {
                const data = { v: 1 };
                return data.v ?? 999;
            }

            export function destruct() {
                const obj = { data: { v: 1 } };
                const { data } = obj;
                return data.v ?? 998;
            }

            export function inheritOuter(ok) {
                if (ok) {
                    return data.v ?? 997;
                }
            }

            export function regexSameLine() {
                const rx = /https?:\\/\\//; return data.v ?? 777;
            }
            """
        ),
    )
    _w(
        tmp_path,
        "frontend/views/typed.ts",
        textwrap.dedent(
            """\
            const res = await fetch('/api/y');
            const data = await res.json();

            export function tsShadowParam(data: { v?: number }) {
                return data.v ?? 555;
            }
            """
        ),
    )
    disp = DisplayExtractionResult(nodes=[], edges=[], http_calls=[])
    findings, _ = analyze_display_confabulation_and_reads(tmp_path, "frontend", disp, strict=True)
    titles = "\n".join(f"{f.source_file}:{f.line}:{f.title}" for f in findings if f.rule_code == "DISP-009")
    assert "999" not in titles
    assert "998" not in titles
    assert "555" not in titles
    assert "997" in titles
    assert "777" in titles


def test_c2_1_c2_2_c2_3_python_services_sql_ddl_symlinks_and_raw_sql_writer(tmp_path: Path) -> None:
    """C2-1/C2-2/C2-3: python_services & sql_ddl_truth symlink coverage_complete=False; raw SQL writer."""
    from app.core.policy_context import policy_tokens_scope

    outside_py = tmp_path / "outside.py"
    outside_py.write_text("X = 1\n", encoding="utf-8")
    truth_empty = TruthExtractionResult(nodes=[], table_symbol_map={}, function_symbol_map={})

    # C2-1: python_services symlinked .py -> coverage_complete=False
    repo_py = tmp_path / "repo_py"
    _w(repo_py, "ok.py", "def f(): return 1\n")
    (repo_py / "linked.py").symlink_to(outside_py)
    assert PythonServicesAdapter().extract(repo_py, ".", truth_empty).coverage_complete is False

    # C2-2: sql_ddl_truth symlinked .py inline store -> coverage_complete=False
    repo_sql = tmp_path / "repo_sql"
    repo_sql.mkdir()
    (repo_sql / "linked_store.py").symlink_to(outside_py)
    assert SqlDdlTruthAdapter().extract(repo_sql, ".").coverage_complete is False

    # C2-3: raw SQL UPDATE in ClassA.run vs ClassB.run reader
    repo_pol = tmp_path / "repo_pol"
    _w(
        repo_pol,
        "backend/app/models/pol.py",
        textwrap.dedent(
            """\
            from sqlalchemy.orm import DeclarativeBase, Mapped, mapped_column
            class Base(DeclarativeBase): pass
            class PolTbl(Base):
                __tablename__ = "pol_tbl"
                id: Mapped[int] = mapped_column(primary_key=True)
                max_cap: Mapped[int]
            """
        ),
    )
    _w(
        repo_pol,
        "backend/app/services/ops.py",
        textwrap.dedent(
            """\
            class ClassA:
                def run(self, conn):
                    row = conn.execute("SELECT id, max_cap FROM pol_tbl").fetchone()
                    conn.execute("UPDATE pol_tbl SET max_cap = 5 WHERE id = ?", (row[0],))

            class ClassB:
                def run(self, conn):
                    rows = conn.execute("SELECT id, max_cap FROM pol_tbl").fetchall()
                    return [{"id": r[0], "cap": r[1]} for r in rows]
            """
        ),
    )
    with policy_tokens_scope(("CAP", "POLICY", "HARDCODED", "DEFAULT")):
        pol_truth = PostgresSqlAlchemyAdapter().extract(repo_pol, "backend")
        pol_res = PythonServicesAdapter().extract(repo_pol, "backend", pol_truth)
    assert pol_res.coverage_complete is True
    assert not any(
        f.rule_code == "MANIP-001" and "ClassA.run" in f.title for f in pol_res.findings
    )


def test_c2_1_python_services_early_fail_closed_no_frozen_instance_error(tmp_path: Path) -> None:
    """C2-1 / P1-8: symlinked/unreadable repo_root and symlinked/missing/out-of-repo backend_subdir fail closed."""
    truth_empty = TruthExtractionResult(nodes=[], table_symbol_map={}, function_symbol_map={})
    outside = tmp_path / "outside"
    outside.mkdir()
    _w(outside, "svc.py", "def ok(): return 1\n")

    # a) Symlinked repo_root
    sym_repo = tmp_path / "sym_repo"
    sym_repo.symlink_to(outside)
    res_sym_repo = PythonServicesAdapter().extract(sym_repo, ".", truth_empty)
    assert res_sym_repo.coverage_complete is False
    assert any("symlink" in n.lower() for n in res_sym_repo.notes)

    # b) Symlinked backend_subdir
    repo_be = tmp_path / "repo_be"
    repo_be.mkdir()
    (repo_be / "api").symlink_to(outside)
    res_sym_be = PythonServicesAdapter().extract(repo_be, "api", truth_empty)
    assert res_sym_be.coverage_complete is False
    assert any("absent or outside" in n.lower() for n in res_sym_be.notes)

    # c) Missing and out-of-repo backend_subdir
    res_missing_be = PythonServicesAdapter().extract(repo_be, "missing_be", truth_empty)
    assert res_missing_be.coverage_complete is False
    assert any("absent or outside" in n.lower() for n in res_missing_be.notes)

    res_escape_be = PythonServicesAdapter().extract(repo_be, "../outside", truth_empty)
    assert res_escape_be.coverage_complete is False
    assert any("absent or outside" in n.lower() for n in res_escape_be.notes)

    # d) Unreadable / missing repo_root (OSError in resolve(strict=True))
    res_missing_repo = PythonServicesAdapter().extract(tmp_path / "does_not_exist", ".", truth_empty)
    assert res_missing_repo.coverage_complete is False
    assert any("unreadable" in n.lower() for n in res_missing_repo.notes)


def test_i4_sql_ddl_and_postgres_fail_closed_symlink_fifo_0o000(tmp_path: Path) -> None:
    """I4: SqlDdlTruthAdapter & PostgresSqlAlchemyAdapter fail closed on symlinks, FIFOs, and 0o000 dirs."""
    outside = tmp_path / "outside_pg"
    _w(
        outside,
        "app/models/secret.py",
        "from sqlalchemy.orm import DeclarativeBase, Mapped, mapped_column\n"
        "class Base(DeclarativeBase): pass\n"
        "class SecretTbl(Base):\n"
        "    __tablename__ = 'secret_leaked_table'\n"
        "    id: Mapped[int] = mapped_column(primary_key=True)\n",
    )
    _w(outside, "schema.sql", "CREATE TABLE outside_ddl (id INT PRIMARY KEY);\n")
    _w(
        outside,
        "alembic/versions/001_out.py",
        "from alembic import op\nimport sqlalchemy as sa\n"
        "revision = '001'\ndown_revision = None\n"
        "def upgrade():\n    op.create_table('outside_mig_tbl', sa.Column('id', sa.Integer))\n",
    )

    # 1. SqlDdlTruthAdapter missing & symlinked repo_root (no TypeError) + 0o000 dirs
    missing_res = SqlDdlTruthAdapter().extract(tmp_path / "nonexistent_sql_repo", "backend")
    assert missing_res.coverage_complete is False
    assert missing_res.nodes == []

    sym_sql_root = tmp_path / "sym_sql_root"
    sym_sql_root.symlink_to(outside)
    sym_sql_res = SqlDdlTruthAdapter().extract(sym_sql_root, ".")
    assert sym_sql_res.coverage_complete is False
    assert sym_sql_res.nodes == []

    locked_sql_repo = tmp_path / "locked_sql_repo"
    _w(locked_sql_repo, "backend/schema.sql", "CREATE TABLE ok_tbl (id INT PRIMARY KEY);\n")
    os.chmod(locked_sql_repo / "backend", 0o000)
    try:
        res_sub000 = SqlDdlTruthAdapter().extract(locked_sql_repo, "backend")
        assert res_sub000.coverage_complete is False
    finally:
        os.chmod(locked_sql_repo / "backend", 0o755)

    os.chmod(locked_sql_repo, 0o000)
    try:
        res_root000 = SqlDdlTruthAdapter().extract(locked_sql_repo, "backend")
        assert res_root000.coverage_complete is False
        assert res_root000.nodes == []
    finally:
        os.chmod(locked_sql_repo, 0o755)

    # 2. PostgresSqlAlchemyAdapter symlinked root / subdirs / schema.sql
    sym_pg_root = tmp_path / "sym_pg_root"
    sym_pg_root.symlink_to(outside)
    res_pg_sym_root = PostgresSqlAlchemyAdapter().extract(sym_pg_root, ".")
    assert res_pg_sym_root.coverage_complete is False
    assert res_pg_sym_root.nodes == []

    pg_sym_be = tmp_path / "pg_sym_be"
    pg_sym_be.mkdir()
    (pg_sym_be / "backend").symlink_to(outside)
    res_pg_sym_be = PostgresSqlAlchemyAdapter().extract(pg_sym_be, "backend")
    assert res_pg_sym_be.coverage_complete is False
    assert all("secret_leaked_table" not in n.id for n in res_pg_sym_be.nodes)

    pg_sym_parts = tmp_path / "pg_sym_parts"
    _w(pg_sym_parts, "backend/app/__init__.py", "")
    (pg_sym_parts / "backend/app/models").symlink_to(outside / "app/models")
    (pg_sym_parts / "backend/alembic").symlink_to(outside / "alembic")
    (pg_sym_parts / "backend/schema.sql").symlink_to(outside / "schema.sql")
    res_pg_sym_parts = PostgresSqlAlchemyAdapter().extract(pg_sym_parts, "backend")
    assert res_pg_sym_parts.coverage_complete is False
    part_ids = {n.id for n in res_pg_sym_parts.nodes}
    assert "t:secret_leaked_table" not in part_ids
    assert "t:outside_ddl" not in part_ids
    assert "t:outside_mig_tbl" not in part_ids

    # 3. PostgresSqlAlchemyAdapter FIFOs (no hang, coverage_complete=False)
    if hasattr(os, "mkfifo"):
        fifo_pg = tmp_path / "fifo_pg"
        _w(fifo_pg, "backend/app/__init__.py", "")
        (fifo_pg / "backend/app/models").mkdir(parents=True)
        (fifo_pg / "backend/alembic/versions").mkdir(parents=True)
        os.mkfifo(fifo_pg / "backend/app/fifo.py")
        os.mkfifo(fifo_pg / "backend/app/models/fifo.py")
        os.mkfifo(fifo_pg / "backend/schema.sql")
        os.mkfifo(fifo_pg / "backend/alembic/versions/001_fifo.py")
        os.mkfifo(fifo_pg / "backend/alembic.ini")
        res_fifo_pg = PostgresSqlAlchemyAdapter().extract(fifo_pg, "backend")
        assert res_fifo_pg.coverage_complete is False

        fifo_pkg = tmp_path / "fifo_pkg"
        _w(fifo_pkg, "backend/pkg/__init__.py", "")
        os.mkfifo(fifo_pkg / "backend/pkg/main.py")
        res_fifo_pkg = PostgresSqlAlchemyAdapter().extract(fifo_pkg, "backend")
        assert res_fifo_pkg.coverage_complete is False

    # 4. PostgresSqlAlchemyAdapter 0o000 repo_root / backend / alembic/versions
    locked_pg = tmp_path / "locked_pg"
    _w(locked_pg, "backend/app/__init__.py", "")
    _w(locked_pg, "backend/alembic/versions/001_init.py", "revision = '001'\ndown_revision = None\n")
    os.chmod(locked_pg / "backend/alembic/versions", 0o000)
    try:
        res_alembic000 = PostgresSqlAlchemyAdapter().extract(locked_pg, "backend")
        assert res_alembic000.coverage_complete is False
    finally:
        os.chmod(locked_pg / "backend/alembic/versions", 0o755)

    os.chmod(locked_pg / "backend", 0o000)
    try:
        res_be000 = PostgresSqlAlchemyAdapter().extract(locked_pg, "backend")
        assert res_be000.coverage_complete is False
    finally:
        os.chmod(locked_pg / "backend", 0o755)

    os.chmod(locked_pg, 0o000)
    try:
        res_pg000 = PostgresSqlAlchemyAdapter().extract(locked_pg, "backend")
        assert res_pg000.coverage_complete is False
    finally:
        os.chmod(locked_pg, 0o755)


def test_i4_epistemic_and_remaining_adapters_0o000_fifo_symlink(tmp_path: Path) -> None:
    """I4: epistemic modules & 6 FS-touching M3 adapters fail closed on 0o000 dirs, symlinks, and FIFOs."""
    from app.adapters.base import DisplayExtractionResult, ManipulatorExtractionResult
    from app.adapters.epistemic_confabulation import evaluate_epistemic_confabulation
    from app.adapters.frontend_common import extract_html_mount_info
    from app.adapters.python_daemon_routes import (
        _detect_python_daemon_context,
        _has_external_display_sources,
        _has_root_html_ui,
        add_daemon_routes_and_subprocesses,
    )
    from app.adapters.ts_workspace import load_tsconfig_paths
    from app.schemas.atlas import AtlasNode

    # 1. evaluate_epistemic_confabulation on 0o000 repo_root, subdirs, and disp.nodes
    ep_repo = tmp_path / "ep_repo"
    _w(ep_repo, "backend/sub/a.py", "def f():\n    return 1\n")
    _w(ep_repo, "frontend/sub/a.js", "export const x = 1;\n")
    disp_with_node = DisplayExtractionResult(
        nodes=[
            AtlasNode(
                id="d:page:frontend/sub/a.js",
                tier="display",
                subkind="page",
                label="a.js",
                source_file="frontend/sub/a.js",
                summary="Display test page",
            )
        ],
        edges=[],
        http_calls=[],
    )
    manip_empty = ManipulatorExtractionResult(nodes=[], edges=[], routes=[])

    os.chmod(ep_repo / "backend/sub", 0o000)
    os.chmod(ep_repo / "frontend/sub", 0o000)
    try:
        cov_nested: list[bool] = []
        _, notes_nested = evaluate_epistemic_confabulation(
            ep_repo,
            "backend",
            "frontend",
            manip_empty,
            disp_with_node,
            strict=True,
            coverage_out=cov_nested,
        )
        assert cov_nested == [False]
        assert any("epistemic_coverage_incomplete:" in n for n in notes_nested)
    finally:
        os.chmod(ep_repo / "backend/sub", 0o755)
        os.chmod(ep_repo / "frontend/sub", 0o755)

    os.chmod(ep_repo, 0o000)
    try:
        for be_sub, fe_sub in (("backend", "frontend"), (".", ".")):
            cov_r: list[bool] = []
            _, notes_r = evaluate_epistemic_confabulation(
                ep_repo,
                be_sub,
                fe_sub,
                manip_empty,
                disp_with_node,
                strict=True,
                coverage_out=cov_r,
            )
            assert cov_r == [False]
            assert any("epistemic_coverage_incomplete:" in n for n in notes_r)
        assert load_fabricated_allowlist(ep_repo, strict=False) == set()
    finally:
        os.chmod(ep_repo, 0o755)

    # 2. PythonServicesAdapter & python_daemon_routes on 0o000 dirs
    truth_empty = TruthExtractionResult(nodes=[], table_symbol_map={}, function_symbol_map={})
    py_repo = tmp_path / "py_000"
    _w(py_repo, "backend/ok.py", "def ok(): return 1\n")
    _w(py_repo, "backend/secret/hidden.py", "def h(): return 2\n")
    os.chmod(py_repo / "backend/secret", 0o000)
    try:
        assert PythonServicesAdapter().extract(py_repo, "backend", truth_empty).coverage_complete is False
    finally:
        os.chmod(py_repo / "backend/secret", 0o755)

    os.chmod(py_repo, 0o000)
    try:
        assert PythonServicesAdapter().extract(py_repo, ".", truth_empty).coverage_complete is False
        assert _has_root_html_ui(py_repo) is False
        assert _detect_python_daemon_context(py_repo, 10, py_count=None, has_daemon_html=None) == (False, False)
        assert _has_external_display_sources(py_repo) is False
        m_res = ManipulatorExtractionResult(nodes=[], edges=[], routes=[])
        add_daemon_routes_and_subprocesses(py_repo, {}, set(), set(), [], {}, m_res)
    finally:
        os.chmod(py_repo, 0o755)

    # 3. Next.js, React SPA, and WorkspaceResolver on 0o000 dirs, packages/pkg1 0o000, symlink->0o000
    fe_repo = tmp_path / "fe_000"
    _w(fe_repo, "frontend/package.json", '{"dependencies":{"next":"14.0.0","react":"18.0.0"}}')
    _w(fe_repo, "frontend/src/App.tsx", "export function App() { return null; }\n")
    _w(fe_repo, "frontend/src/secret/page.tsx", "export default function P() { return null; }\n")
    _w(fe_repo, "packages/pkg1/package.json", '{"name":"@acme/pkg1"}')
    locked_tgt = tmp_path / "locked_tgt"
    _w(locked_tgt, "sub/a.ts", "export const x = 1;\n")
    os.chmod(locked_tgt, 0o000)
    (fe_repo / "frontend/src/evil").symlink_to(locked_tgt / "sub")
    os.chmod(fe_repo / "frontend/src/secret", 0o000)
    os.chmod(fe_repo / "packages/pkg1", 0o000)
    try:
        assert TypeScriptNextJsAdapter().extract(fe_repo, "frontend").coverage_complete is False
        assert TypeScriptReactSpaAdapter().extract(fe_repo, "frontend").coverage_complete is False
    finally:
        os.chmod(locked_tgt, 0o755)
        os.chmod(fe_repo / "frontend/src/secret", 0o755)
        os.chmod(fe_repo / "packages/pkg1", 0o755)

    os.chmod(fe_repo, 0o000)
    try:
        assert TypeScriptNextJsAdapter().extract(fe_repo, ".").coverage_complete is False
        assert TypeScriptReactSpaAdapter().extract(fe_repo, ".").coverage_complete is False
    finally:
        os.chmod(fe_repo, 0o755)

    # 4. extract_html_mount_info FIFO + 0o000 dir & load_tsconfig_paths(..., repo_root=None) symlink escape
    if hasattr(os, "mkfifo"):
        html_fifo_dir = tmp_path / "html_fifo"
        html_fifo_dir.mkdir()
        os.mkfifo(html_fifo_dir / "index.html")
        errs_fifo: list[str] = []
        extract_html_mount_info(html_fifo_dir, errors_out=errs_fifo)
        assert errs_fifo

    ts_outside = tmp_path / "ts_outside"
    _w(ts_outside, "base.json", '{"compilerOptions":{"baseUrl":"."}}')
    ts_proj = tmp_path / "ts_proj"
    _w(ts_proj, "tsconfig.json", '{"extends":"../ts_outside/base.json","compilerOptions":{"paths":{"@/*":["src/*"]}}}')
    cfg_none = load_tsconfig_paths(ts_proj / "tsconfig.json", repo_root=None)
    assert cfg_none.base_url == (ts_proj).resolve()


def test_i5_gate4_symlink_containment_and_frozen_replace_regressions(tmp_path: Path) -> None:
    """I5: symlinked daemon repo_root, tsconfig parent symlink escapes, a11y uncontained caller, and frozen replace."""
    import ast
    import tempfile

    from app.adapters.base import DisplayExtractionResult, ManipulatorExtractionResult
    from app.adapters.epistemic_confabulation import evaluate_epistemic_confabulation
    from app.adapters.frontend_common import build_a11y_component_resolver
    from app.adapters.python_daemon_routes import (
        _detect_python_daemon_context,
        _has_external_display_sources,
        _has_root_html_ui,
        add_daemon_routes_and_subprocesses,
    )
    from app.adapters.ts_workspace import load_tsconfig_paths

    # 1. python_daemon_routes: symlinked repo_root fails closed across all 4 entry points
    outside = tmp_path / "outside_daemon"
    _w(outside, "index.html", "<!doctype html><html><body>Out</body></html>\n")
    _w(outside, "ui/p.html", "<html><body>UI</body></html>\n")
    _w(outside, "frontend/App.tsx", "export const App = () => null;\n")
    daemon_src = (
        "from http.server import BaseHTTPRequestHandler\n"
        "class H(BaseHTTPRequestHandler):\n"
        "    def do_GET(self):\n"
        "        self.send_header('Content-Type', 'text/html')\n"
        "        return b'<html></html>'\n"
    )
    _w(outside, "daemon.py", daemon_src)
    sym_repo = tmp_path / "sym_repo"
    sym_repo.symlink_to(outside)

    assert _has_root_html_ui(sym_repo) is False
    assert _has_external_display_sources(sym_repo) is False
    assert _detect_python_daemon_context(sym_repo, 10, py_count=None, has_daemon_html=None) == (False, False)
    assert _detect_python_daemon_context(sym_repo, 10, py_count=10, has_daemon_html=True) == (False, False)
    m_res = ManipulatorExtractionResult(nodes=[], edges=[], routes=[])
    r_keys = add_daemon_routes_and_subprocesses(
        sym_repo,
        {"daemon.py": ast.parse(daemon_src)},
        {"daemon.py"},
        {"daemon.py"},
        [[]],
        {},
        m_res,
    )
    assert r_keys == {}
    assert m_res.nodes == []
    assert m_res.edges == []
    assert m_res.routes == []

    # 2. ts_workspace.load_tsconfig_paths(..., repo_root=None): reject sym_repo, proj/sym_dir, proj/sym_dir/sub
    ts_out = tmp_path / "ts_out_escape"
    _w(ts_out, "tsconfig.json", '{"compilerOptions":{"baseUrl":"./out_base"}}')
    _w(ts_out, "sub/tsconfig.json", '{"compilerOptions":{"baseUrl":"./out_sub_base"}}')
    _w(ts_out, "out_base/mod.ts", "export const X = 1;\n")
    _w(ts_out, "out_sub_base/mod.ts", "export const Y = 2;\n")

    sym_ts_repo = tmp_path / "sym_ts_repo"
    sym_ts_repo.symlink_to(ts_out)
    cfg_sym_repo = load_tsconfig_paths(sym_ts_repo / "tsconfig.json", repo_root=None)
    assert "out_base" not in str(cfg_sym_repo.base_url)

    proj = tmp_path / "proj_parent_sym"
    proj.mkdir()
    (proj / "sym_dir").symlink_to(ts_out)
    cfg_sym_parent = load_tsconfig_paths(proj / "sym_dir/tsconfig.json", repo_root=None)
    assert "out_base" not in str(cfg_sym_parent.base_url)

    cfg_sym_anc = load_tsconfig_paths(proj / "sym_dir/sub/tsconfig.json", repo_root=None)
    assert "out_sub_base" not in str(cfg_sym_anc.base_url)

    # Valid /tmp TemporaryDirectory tsconfig still resolves normally (no macOS /tmp false positive)
    with tempfile.TemporaryDirectory(dir="/tmp") as tmp_dir:
        valid_proj = Path(tmp_dir) / "valid_proj"
        _w(valid_proj, "tsconfig.json", '{"compilerOptions":{"baseUrl":"./src","paths":{"@/*":["app/*"]}}}')
        _w(valid_proj, "src/app/index.ts", "export const ok = 1;\n")
        cfg_valid = load_tsconfig_paths(valid_proj / "tsconfig.json", repo_root=None)
        assert cfg_valid.base_url == (valid_proj / "src").resolve()
        assert "@/*" in cfg_valid.paths

    # 3. PythonServicesAdapter & evaluate_epistemic_confabulation preserve frozen dataclasses via replace
    py_inc = tmp_path / "py_incomplete"
    _w(py_inc, "backend/ok.py", "def ok():\n    return 1\n")
    (py_inc / "backend/link.py").symlink_to(outside / "daemon.py")
    truth_empty = TruthExtractionResult(nodes=[], table_symbol_map={}, function_symbol_map={})
    py_res = PythonServicesAdapter().extract(py_inc, "backend", truth_empty)
    assert py_res.coverage_complete is False
    assert any(n.source_file == "backend/ok.py" for n in py_res.nodes)

    _w(py_inc, "frontend/app.js", "export const z = 1;\n")
    (py_inc / "frontend/bad.js").symlink_to(outside / "frontend/App.tsx")
    manip_in = ManipulatorExtractionResult(nodes=[], edges=[], routes=[], notes=[])
    disp_in = DisplayExtractionResult(nodes=[], edges=[], http_calls=[], notes=[])
    cov_out: list[bool] = []
    _ef, ep_notes = evaluate_epistemic_confabulation(
        py_inc,
        "backend",
        "frontend",
        manip_in,
        disp_in,
        strict=True,
        coverage_out=cov_out,
    )
    assert cov_out == [False]
    assert manip_in.coverage_complete is True
    assert disp_in.coverage_complete is True
    assert any(n.startswith("epistemic_coverage_incomplete: ") for n in ep_notes)

    # 4. build_a11y_component_resolver fails closed for uncontained or symlinked caller_file
    a11y_repo = tmp_path / "a11y_repo"
    _w(a11y_repo, "src/Icon.tsx", "export function Icon() { return <span>Save</span>; }\n")
    _w(outside, "OutsideIcon.tsx", "export function OutsideIcon() { return <span>Out</span>; }\n")
    (a11y_repo / "src/LinkPage.tsx").symlink_to(outside / "OutsideIcon.tsx")
    comp_res = build_a11y_component_resolver(a11y_repo / "src", (".tsx", ".ts"), repo_root=a11y_repo)
    uncontained_fn = comp_res(
        outside / "Page.tsx",
        "import { Icon } from '../a11y_repo/src/Icon'; export function P() { return <button><Icon /></button>; }",
    )
    assert uncontained_fn("Icon", "", "omitted") == "opaque"
    symlink_fn = comp_res(
        a11y_repo / "src/LinkPage.tsx",
        "import { Icon } from './Icon'; export function P() { return <button><Icon /></button>; }",
    )
    assert symlink_fn("Icon", "", "omitted") == "opaque"





