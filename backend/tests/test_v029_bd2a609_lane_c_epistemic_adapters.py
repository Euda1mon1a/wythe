"""Lane C regression tests for post-bd2a609 P0-1, P1-5, P1-6.1/6.2, and P1-11 fixes."""

from __future__ import annotations

import json
import textwrap
import time
from pathlib import Path

import pytest

from app.adapters.base import (
    DisplayExtractionResult,
    ManipulatorExtractionResult,
    TruthExtractionResult,
)
from app.adapters.epistemic_confabulation import evaluate_epistemic_confabulation
from app.adapters.epistemic_display_checks import (
    _FN_HEAD_RE,
    _extract_js_decl_names,
    analyze_display_confabulation_and_reads,
)
from app.adapters.epistemic_freshness_manip import analyze_python_freshness_and_producers
from app.adapters.frontend_common import scan_display_module_semantics
from app.adapters.postgres_sqlalchemy import PostgresSqlAlchemyAdapter
from app.adapters.python_fastapi import PythonFastApiAdapter
from app.adapters.python_policy_consumption import (
    _scope_has_write_evidence,
    analyze_module_policy_table_read,
)
from app.adapters.python_services import PythonServicesAdapter
from app.adapters.sql_ddl_truth import SqlDdlTruthAdapter
from app.adapters.typescript_nextjs import TypeScriptNextJsAdapter, _extract_ts_http_calls
from app.adapters.typescript_react import TypeScriptReactSpaAdapter
from app.core.policy_context import policy_tokens_scope
from app.schemas.atlas import AtlasNode


def _w(root: Path, rel: str, text: str) -> Path:
    dest = root / rel
    dest.parent.mkdir(parents=True, exist_ok=True)
    dest.write_text(text, encoding="utf-8")
    return dest


def test_p0_1_fn_head_re_and_benign_32kb_html_under_25ms(tmp_path: Path) -> None:
    """P0-1: _FN_HEAD_RE and 32 KB benign HTML scan complete in < 25 ms without cubic backtracking."""
    t0 = time.perf_counter()
    assert _FN_HEAD_RE.search(" " * 8000 + "x") is None
    dt_regex_ms = (time.perf_counter() - t0) * 1000.0
    assert dt_regex_ms < 25.0, f"_FN_HEAD_RE took {dt_regex_ms:.2f} ms"

    html_body = "<div>" + ("hello world " * 2500) + "</div>"
    assert len(html_body) >= 30_000
    _w(tmp_path, "frontend/index.html", html_body)
    disp = DisplayExtractionResult(nodes=[], edges=[], http_calls=[])

    t1 = time.perf_counter()
    findings, reads = analyze_display_confabulation_and_reads(tmp_path, "frontend", disp, strict=True)
    dt_html_ms = (time.perf_counter() - t1) * 1000.0
    assert dt_html_ms < 25.0, f"32 KB HTML scan took {dt_html_ms:.2f} ms"
    assert findings == [] and reads == []

    # Also verify HTML with an inline <script> + 30 KB markup and arrow/method parameter shadowing
    _w(
        tmp_path,
        "frontend/with_script.html",
        "<script>\n"
        "const res = await fetch('/api/status');\n"
        "const data = await res.json();\n"
        "const arrowShadow = (data) => { return data.val ?? 42; };\n"
        "const asyncArrowShadow = async (data) => { return data.val ?? 43; };\n"
        "</script>\n" + html_body,
    )
    t2 = time.perf_counter()
    findings2, _ = analyze_display_confabulation_and_reads(tmp_path, "frontend", disp, strict=True)
    dt_script_ms = (time.perf_counter() - t2) * 1000.0
    assert dt_script_ms < 25.0, f"32 KB HTML+script scan took {dt_script_ms:.2f} ms"
    assert findings2 == []


def test_p1_5_1_extract_js_decl_names_iterative_depth_bound() -> None:
    """P1-5.1: Deeply nested destructuring finishes immediately without RecursionError."""
    deep_arr = "[" * 1200 + "a" + "]" * 1200
    deep_obj = "{" + "k: {" * 1200 + "leaf" + "}" * 1200 + "}"
    t0 = time.perf_counter()
    assert _extract_js_decl_names(deep_arr) == []
    assert _extract_js_decl_names(deep_obj) == []
    assert (time.perf_counter() - t0) * 1000.0 < 50.0

    normal = "{ alpha, nested: [beta, { gamma = 10 }], ...restItems }"
    assert _extract_js_decl_names(normal) == ["alpha", "beta", "gamma", "restItems"]


def test_p1_5_2_disp014_jsx_tags_and_code_mask_string_literal_soundness(tmp_path: Path) -> None:
    """P1-5.2: JSX < > tags do not bypass DISP-014; string/template/comment text never fires DISP-009..012."""
    _w(
        tmp_path,
        "backend/app/routes.py",
        textwrap.dedent(
            """\
            from fastapi import FastAPI
            app = FastAPI()

            @app.get("/api/v1/slices/health")
            def get_health():
                return {"ok": True, "valid_until": "2026-12-01T00:00:00Z"}
            """
        ),
    )
    _w(tmp_path, "frontend/src/demo.tsx", "export const demo = 1;\n")
    _w(
        tmp_path,
        "frontend/src/UncheckedJsx.tsx",
        textwrap.dedent(
            """\
            export async function UncheckedJsx(client: any) {
              const data = await client.fetchSlice('health');
              const msg = "check data.nonexistent_status || 'ok'";
              const fakeImp = "import './demo.tsx'";
              const fakeBranch = "if (!data.items.length) { cards.push({ id: 'x', title: 'y' }); }";
              // data.commented_count ?? 99
              return <span>{data.valid_until} {msg} {fakeImp} {fakeBranch}</span>;
            }
            """
        ),
    )
    _w(
        tmp_path,
        "frontend/src/CheckedJsxGt.tsx",
        textwrap.dedent(
            """\
            export async function CheckedJsxGt(client: any, now: Date) {
              const data = await client.fetchSlice('health');
              return <span>{new Date(data.valid_until) > now ? 'fresh' : 'stale'}</span>;
            }
            """
        ),
    )
    _w(
        tmp_path,
        "frontend/src/CheckedJsxLt.tsx",
        textwrap.dedent(
            """\
            export async function CheckedJsxLt(client: any, cutoff: string) {
              const data = await client.fetchSlice('health');
              return <span>{data.valid_until < cutoff ? 'stale' : 'fresh'}</span>;
            }
            """
        ),
    )

    truth = TruthExtractionResult(nodes=[], table_symbol_map={}, function_symbol_map={})
    manip = PythonFastApiAdapter().extract(tmp_path, "backend", truth)
    disp = DisplayExtractionResult(nodes=[], edges=[], http_calls=[])
    findings, _ = evaluate_epistemic_confabulation(
        tmp_path,
        "backend",
        "frontend",
        manip,
        disp,
        strict=False,
        trusted_allowlist={"frontend/src/demo.tsx"},
    )

    # UncheckedJsx MUST emit DISP-014 (JSX <span>...</span> must not satisfy compares_valid_until)
    assert any(
        f.rule_code == "DISP-014" and "UncheckedJsx.tsx" in f.source_file for f in findings
    )
    # CheckedJsxGt and CheckedJsxLt MUST NOT emit DISP-014
    assert not any(
        f.rule_code == "DISP-014" and "CheckedJsx" in f.source_file for f in findings
    )
    # String/comment text in UncheckedJsx MUST NOT emit DISP-009, DISP-010, DISP-011, or DISP-012
    fp_rules = [
        f
        for f in findings
        if f.rule_code in {"DISP-009", "DISP-010", "DISP-011", "DISP-012"}
        and "UncheckedJsx.tsx" in f.source_file
    ]
    assert fp_rules == []


def test_p1_5_3_dict_mutation_emit_paths_and_dynamic_partial_coverage(tmp_path: Path) -> None:
    """P1-5.3: Track out['k']=v, setdefault, update({...}) statically; downgrade dynamic mutations to partial."""
    _w(
        tmp_path,
        "backend/app/slices.py",
        textwrap.dedent(
            """\
            def build_mutated():
                out = {"ok": True}
                out["count"] = 5
                out.setdefault("ready", True)
                out.update({"health": "good"}, summary="nominal")
                return out

            def build_dyn_sub(dyn_key, val):
                out = {"ok": True}
                out[dyn_key] = val
                return out

            def build_dyn_update(extra_payload):
                out = {"ok": True}
                out.update(extra_payload)
                return out

            SLICE_BUILDERS = {
                "mutated": build_mutated,
                "dynsub": build_dyn_sub,
                "dynupd": build_dyn_update,
            }
            """
        ),
    )
    _w(
        tmp_path,
        "frontend/views/panel.js",
        textwrap.dedent(
            """\
            export async function renderPanels(client) {
              const m = await client.fetchSlice('mutated');
              const s = await client.fetchSlice('dynsub');
              const u = await client.fetchSlice('dynupd');
              return {
                a: m.count,
                b: m.ready,
                c: m.health,
                d: m.summary,
                missingCrit: m.unemitted_count,
                dynA: s.any_status_count,
                dynB: u.other_status_count,
              };
            }
            """
        ),
    )
    manip = ManipulatorExtractionResult(nodes=[], edges=[], routes=[])
    disp = DisplayExtractionResult(nodes=[], edges=[], http_calls=[])
    _, contracts = analyze_python_freshness_and_producers(tmp_path, "backend", manip)
    assert contracts["slice:mutated"].coverage == "complete"
    assert {"ok", "count", "ready", "health", "summary"} <= contracts["slice:mutated"].emit_paths
    assert contracts["slice:dynsub"].coverage == "partial"
    assert contracts["slice:dynupd"].coverage == "partial"

    findings, _ = evaluate_epistemic_confabulation(tmp_path, "backend", "frontend", manip, disp, strict=True)
    drift = [f for f in findings if f.rule_code in {"DISP-011", "DISP-012"}]
    drift_details = "\n".join(f.detail for f in drift)
    for valid_key in ("m.count", "m.ready", "m.health", "m.summary", "any_status_count", "other_status_count"):
        assert valid_key not in drift_details
    assert any(f.rule_code == "DISP-011" and "unemitted_count" in f.detail for f in drift)


def test_p1_6_1_and_p1_6_2_react_monorepo_script_and_sql_venv_skip(tmp_path: Path) -> None:
    """P1-6.1/6.2: React <script src='../shared/boot.js'> resolves cleanly; SQL DDL skips venv/cache/dot dirs."""
    spa_repo = tmp_path / "monorepo"
    _w(spa_repo, "frontend/package.json", json.dumps({"dependencies": {"react": "18.0.0"}}))
    _w(
        spa_repo,
        "frontend/index.html",
        '<!doctype html><html><body><script type="module" src="../shared/boot.js"></script></body></html>\n',
    )
    _w(spa_repo, "shared/boot.js", "export async function boot() { return fetch('/api/shared-boot'); }\n")
    _w(spa_repo, "frontend/src/App.tsx", "export function App() { return fetch('/api/app-home'); }\n")

    spa_res = TypeScriptReactSpaAdapter().extract(spa_repo, "frontend")
    assert spa_res.coverage_complete is True
    assert {"/api/shared-boot", "/api/app-home"} <= {c.normalized_path for c in spa_res.http_calls}

    sql_repo = tmp_path / "sql_venv_repo"
    _w(sql_repo, "backend/schema.sql", "CREATE TABLE widgets (id INTEGER PRIMARY KEY);\n")
    for skip_dir in (
        "venv",
        ".venv",
        "env",
        "site-packages",
        "__pycache__",
        "node_modules",
        "dist",
        "build",
        "target",
        "vendor",
        ".tox",
        ".nox",
        ".mypy_cache",
        ".pytest_cache",
        ".ruff_cache",
        ".hidden_dir",
    ):
        real_lib = sql_repo / skip_dir / "lib"
        real_lib.mkdir(parents=True, exist_ok=True)
        (sql_repo / skip_dir / "lib64").symlink_to(real_lib)
        _w(sql_repo, f"{skip_dir}/ignored.sql", "CREATE TABLE ignored_vendor_tbl (id INT);\n")

    # Custom-named virtualenv identified by pyvenv.cfg
    _w(sql_repo, "custom_py_env/pyvenv.cfg", "home = /usr/bin\n")
    (sql_repo / "custom_py_env" / "lib").mkdir(parents=True, exist_ok=True)
    (sql_repo / "custom_py_env" / "lib64").symlink_to(sql_repo / "custom_py_env" / "lib")

    sql_res = SqlDdlTruthAdapter().extract(sql_repo, "backend")
    assert sql_res.coverage_complete is True
    tbl_labels = {n.label for n in sql_res.nodes}
    assert "widgets" in tbl_labels and "ignored_vendor_tbl" not in tbl_labels


def test_p1_11_policy_write_evidence_vue_balanced_fetch_and_nextjs_dynamic_opts(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """P1-11.1/2/3: Non-DB mutations & len(cands)==1 enforced; Vue fetch balanced; fetch(url, opts/{...opts}) DYNAMIC."""
    import ast

    in_mem = ast.parse(
        "self._cache = 1\nseen.add('a')\nitems.append(2)\nitems.insert(0, 3)\nmeta.update({'k': 1})\n"
    ).body
    assert _scope_has_write_evidence(in_mem) is False
    orm_write = ast.parse("uow.session.add(row)\nuow.session.commit()\n").body
    assert _scope_has_write_evidence(orm_write) is True

    # len(cands) == 1: top-level `sync` writes, single class method `Reader.sync` does in-memory mutations + bypasses policy
    pol_src = textwrap.dedent(
        """\
        HARDCODED_MAX_CAP = 50

        def sync(conn):
            conn.execute("UPDATE active_policies SET max_cap = 10")

        class Reader:
            def sync(self, session, items):
                row = session.get(ActivePolicy, 1)
                self._cache = row.id
                seen = set()
                seen.add(row.id)
                items.append(row.id)
                return row.id

        class BadWriter:
            def apply(self, session):
                row = session.get(ActivePolicy, 1)
                session.add(AuditEntry(cap=HARDCODED_MAX_CAP, pid=row.id))
                session.commit()
                return HARDCODED_MAX_CAP
        """
    )
    with policy_tokens_scope(("CAP", "POLICY", "HARDCODED", "DEFAULT")):
        analyses = analyze_module_policy_table_read(
            pol_src,
            table_label="active_policies",
            table_columns=("id", "max_cap"),
            policy_columns=("max_cap",),
            active_scopes=("Reader.sync", "BadWriter.apply"),
            write_scopes={"sync", "apply"},
            func_calls={},
            model_symbols={"ActivePolicy"},
            sql_table_names={"active_policies"},
        )
    by_sc = {a.scope_name: a for a in analyses}
    assert by_sc["Reader.sync"].is_write_lookup is False
    assert by_sc["Reader.sync"].state == "bypassed"
    assert by_sc["BadWriter.apply"].state == "bypassed"
    assert "HARDCODED_MAX_CAP" in by_sc["BadWriter.apply"].substituted_constants

    # End-to-end MANIP-001 via PostgresSqlAlchemyAdapter + PythonServicesAdapter on sibling in-memory mutation
    e2e_pol = tmp_path / "e2e_pol"
    _w(
        e2e_pol,
        "backend/app/models/pol.py",
        "from sqlalchemy.orm import DeclarativeBase, Mapped, mapped_column\n"
        "class Base(DeclarativeBase): pass\n"
        "class ActivePolicy(Base):\n"
        "    __tablename__ = 'active_policies'\n"
        "    id: Mapped[int] = mapped_column(primary_key=True)\n"
        "    max_cap: Mapped[int]\n",
    )
    _w(e2e_pol, "backend/app/services/svc.py", pol_src)
    with policy_tokens_scope(("CAP", "POLICY", "HARDCODED", "DEFAULT")):
        pol_truth = PostgresSqlAlchemyAdapter().extract(e2e_pol, "backend")
        pol_svc = PythonServicesAdapter().extract(e2e_pol, "backend", pol_truth)
    assert any(f.rule_code == "MANIP-001" for f in pol_svc.findings)

    # P1-11.2: Vue balanced $fetch / useFetch scanning
    vue_node = AtlasNode(
        id="d:page:Orders",
        tier="display",
        subkind="page",
        label="/orders",
        source_file="frontend/pages/Orders.vue",
        summary="Orders Vue page",
    )
    long_hdr = "x" * 220
    vue_script = (
        "$fetch('/api/first'); $fetch('/api/second', { method: 'POST' });\n"
        "$fetch('/api/nested-body', { body: { method: 'POST' } });\n"
        f"useFetch('/api/long-opts', {{ headers: {{ 'X-Pad': '{long_hdr}' }}, method: 'DELETE' }});\n"
    )
    _, vue_calls, _ = scan_display_module_semantics(vue_node, vue_script, vue_node.source_file)
    vue_map = {(c.normalized_path, c.http_method) for c in vue_calls}
    assert ("/api/first", "GET") in vue_map
    assert ("/api/second", "POST") in vue_map
    assert ("/api/nested-body", "GET") in vue_map
    assert ("/api/nested-body", "POST") not in vue_map
    assert ("/api/long-opts", "DELETE") in vue_map

    # P1-11.3: Next.js fetch(url, opts) and fetch(url, { ...opts }) -> DYNAMIC (CST + adapter + fallback)
    ts_code = (
        "export default function DynOptsPage(opts: RequestInit) {\n"
        "  void fetch('/api/var-opts', opts);\n"
        "  void fetch('/api/spread-only', { ...opts });\n"
        "  void fetch('/api/spread-after', { method: 'POST', ...opts });\n"
        "  void fetch('/api/spread-overridden', { ...opts, method: 'POST' });\n"
        "  void fetch('/api/undef-opts', undefined);\n"
        "  return <main>ok</main>;\n"
        "}\n"
    )
    cst_res = {u: m for m, u, _ in _extract_ts_http_calls(ts_code)}
    assert cst_res["/api/var-opts"] == "DYNAMIC"
    assert cst_res["/api/spread-only"] == "DYNAMIC"
    assert cst_res["/api/spread-after"] == "DYNAMIC"
    assert cst_res["/api/spread-overridden"] == "POST"
    assert cst_res["/api/undef-opts"] == "GET"

    next_repo = tmp_path / "next_dyn_opts"
    _w(next_repo, "frontend/package.json", json.dumps({"dependencies": {"next": "14.0.0"}}))
    _w(next_repo, "frontend/app/page.tsx", ts_code)
    next_disp = TypeScriptNextJsAdapter().extract(next_repo, "frontend")
    next_calls = {c.normalized_path: c.http_method for c in next_disp.http_calls}
    assert next_calls["/api/var-opts"] == "DYNAMIC"
    assert next_calls["/api/spread-only"] == "DYNAMIC"

    import app.adapters.treesitter_engine as ts_eng

    monkeypatch.setattr(ts_eng, "has_treesitter", lambda: False)
    fb_res = {u: m for m, u, _ in _extract_ts_http_calls(ts_code)}
    assert fb_res == cst_res
