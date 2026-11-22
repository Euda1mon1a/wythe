"""Deterministic tests for #119 (DISP-009/010), #120 (DISP-011..013), & #121 (MANIP-007, DISP-014)."""

from __future__ import annotations

import json
from pathlib import Path

from sqlalchemy import create_engine
from sqlalchemy.orm import Session

from app.adapters.base import DisplayExtractionResult, ManipulatorExtractionResult
from app.adapters.epistemic_confabulation import evaluate_epistemic_confabulation
from app.adapters.epistemic_display_checks import (
    analyze_display_confabulation_and_reads,
    load_fabricated_allowlist,
)
from app.db.base import Base
from app.db.seed import seed_catalog_if_needed
from app.models import TargetProject
from app.services.scanner_service import run_target_scan


def _make_session() -> Session:
    engine = create_engine("sqlite:///:memory:")
    Base.metadata.create_all(engine)
    session = Session(engine)
    seed_catalog_if_needed(session)
    return session


def _scan_fixture(repo: Path, *, backend_subdir: str = "backend", frontend_subdir: str = "frontend"):
    session = _make_session()
    target = TargetProject(
        slug="ops-portal-fixture",
        name="Ops Portal Fixture",
        repo_path=str(repo),
        stack_profile_slug="fastapi-sqlalchemy-nextjs",
        backend_subdir=backend_subdir,
        frontend_subdir=frontend_subdir,
        is_active=True,
        created_by="pytest",
    )
    session.add(target)
    session.commit()
    session.refresh(target)
    return run_target_scan(session, target, strict_gate=True, persist_snapshot=False)


def test_119_fabricated_fallbacks_sentinels_synthesized_items_and_allowlist(tmp_path: Path) -> None:
    """#119: Flag non-sentinel payload fallbacks & empty-list item synthesis; allow sentinels & unreachable fixtures."""
    (tmp_path / "backend" / "app").mkdir(parents=True)
    (tmp_path / "backend" / "app" / "main.py").write_text(
        "from fastapi import FastAPI\napp = FastAPI()\n"
        "@app.get('/api/v1/slices/storage')\n"
        "def get_storage():\n"
        "    return {'disk_pct': 70.0, 'failed_count': 0, 'title': 'ok', 'items': [], 'pending_count': 0}\n",
        encoding="utf-8",
    )

    views = tmp_path / "frontend" / "views"
    views.mkdir(parents=True)
    (views / "storage-view.js").write_text(
        "export async function renderStorage(client) {\n"
        "  const data = await client.fetchSlice('storage');\n"
        "  const pct = data.disk_pct ?? 93.3;\n"
        "  const title = data.title || 'Some title';\n"
        "  const failed = data.failed_count ?? 0;\n"
        "  const safeDash = data.missing_note ?? '—';\n"
        "  const safeNull = data.missing_other ?? null;\n"
        "  const cards = [];\n"
        "  if (!data.items.length) {\n"
        "    cards.push({ id: 'fallback-1', title: 'Prune pending', href: '/decide/fallback-1' });\n"
        "  }\n"
        "  return { pct, title, failed, safeDash, safeNull, cards };\n"
        "}\n",
        encoding="utf-8",
    )
    (views / "demo-fixture.js").write_text(
        "export function renderDemo(data) {\n"
        "  return data.disk_pct ?? 88.8;\n"
        "}\n",
        encoding="utf-8",
    )
    (tmp_path / ".wythe").mkdir()
    (tmp_path / ".wythe" / "governance.json").write_text(
        json.dumps({"fabricated_fallback_allowlist": ["frontend/views/demo-fixture.js"]}),
        encoding="utf-8",
    )

    report = _scan_fixture(tmp_path)
    by_rule: dict[str, list] = {}
    for f in report.findings:
        by_rule.setdefault(f.rule_code, []).append(f)

    disp_009 = by_rule.get("DISP-009", [])
    disp_010 = by_rule.get("DISP-010", [])
    detail_009 = "\n".join(f.detail for f in disp_009)
    detail_010 = "\n".join(f.detail for f in disp_010)

    assert "93.3" in detail_009
    assert "'Some title'" in detail_009
    assert "failed_count" in detail_009
    # Sentinels (`'—'`, `null`) are NOT flagged; under strict_gate=True `.wythe/governance.json` is ignored
    assert "safeDash" not in detail_009 and "missing_note" not in detail_009
    assert "demo-fixture.js" in detail_009
    assert "demo-fixture.js" not in detail_010
    # Empty-list synthesized decision card is blocking DISP-010
    assert any("storage-view.js" in f.source_file and f.blocks_gate for f in disp_010)

    # Under strict_gate=True, importing a disk-allowlisted fixture does NOT inherit `.wythe/governance.json` DISP-010
    (views / "live-importer.js").write_text(
        "import { renderDemo } from './demo-fixture.js';\n"
        "export function mountLive(d) { return renderDemo(d); }\n",
        encoding="utf-8",
    )
    report_live_imp = _scan_fixture(tmp_path)
    assert not any(
        f.rule_code == "DISP-010" and "demo-fixture.js" in f.detail
        for f in report_live_imp.findings
    )

    # Contract #1: strict=False with explicit trusted_allowlist honors allowlist without reading disk;
    # strict=False with trusted_allowlist=None does NOT silently read `.wythe/governance.json`;
    # strict=True ignores even an explicit trusted_allowlist.
    empty_manip = ManipulatorExtractionResult(nodes=[], routes=[], edges=[])
    empty_disp = DisplayExtractionResult(nodes=[], edges=[], http_calls=[])

    f_nonstrict_none, _ = evaluate_epistemic_confabulation(
        tmp_path, "backend", "frontend", empty_manip, empty_disp, strict=False, trusted_allowlist=None
    )
    assert any(f.rule_code == "DISP-009" and "demo-fixture.js" in f.source_file for f in f_nonstrict_none)

    f_nonstrict_trusted, _ = evaluate_epistemic_confabulation(
        tmp_path,
        "backend",
        "frontend",
        empty_manip,
        empty_disp,
        strict=False,
        trusted_allowlist=frozenset({"frontend/views/demo-fixture.js"}),
    )
    assert not any(f.rule_code == "DISP-009" and "demo-fixture.js" in f.source_file for f in f_nonstrict_trusted)
    assert any(
        f.rule_code == "DISP-010" and "demo-fixture.js" in f.detail
        for f in f_nonstrict_trusted
    )

    f_strict_with_arg, _ = evaluate_epistemic_confabulation(
        tmp_path,
        "backend",
        "frontend",
        empty_manip,
        empty_disp,
        strict=True,
        trusted_allowlist=frozenset({"frontend/views/demo-fixture.js"}),
    )
    assert any(f.rule_code == "DISP-009" and "demo-fixture.js" in f.source_file for f in f_strict_with_arg)
    assert not any(f.rule_code == "DISP-010" and "demo-fixture.js" in f.detail for f in f_strict_with_arg)

    assert load_fabricated_allowlist(tmp_path, strict=True) == set()
    assert "frontend/views/demo-fixture.js" in load_fabricated_allowlist(tmp_path, strict=False)
    disp_f, _ = analyze_display_confabulation_and_reads(
        tmp_path,
        "frontend",
        empty_disp,
        strict=False,
        trusted_allowlist={"frontend/views/demo-fixture.js"},
    )
    assert any(f.rule_code == "DISP-010" and "demo-fixture.js" in f.detail for f in disp_f)


def test_120_producer_display_field_drift_and_dynamic_partial_coverage(tmp_path: Path) -> None:
    """#120: Flag missing display read paths with both locations; dynamic producer yields coverage=partial."""
    (tmp_path / "backend" / "app").mkdir(parents=True)
    (tmp_path / "backend" / "app" / "slices.py").write_text(
        "def _build_pulse():\n"
        "    return {\n"
        "        'health_sources': ['probe-a'],\n"
        "        'source_health': 'ok',\n"
        "        'attention_mirror': {'health_sources': ['probe-a']},\n"
        "    }\n\n"
        "def _build_dynamic(raw_map):\n"
        "    return {k: v for k, v in raw_map.items()}\n\n"
        "SLICE_BUILDERS = {'pulse': _build_pulse, 'dyn': _build_dynamic}\n",
        encoding="utf-8",
    )

    views = tmp_path / "frontend" / "views"
    views.mkdir(parents=True)
    (views / "pulse-view.js").write_text(
        "export async function loadPulse(client) {\n"
        "  const data = await client.fetchSlice('pulse');\n"
        "  const am = data.attention_mirror;\n"
        "  return {\n"
        "    src: data.sources,\n"
        "    nestedSrc: am.sources,\n"
        "    counts: data.service_counts,\n"
        "  };\n"
        "}\n",
        encoding="utf-8",
    )
    (views / "dyn-view.js").write_text(
        "export async function loadDyn(client) {\n"
        "  const data = await client.fetchSlice('dyn');\n"
        "  return data.arbitrary_field;\n"
        "}\n",
        encoding="utf-8",
    )

    report = _scan_fixture(tmp_path)
    drift_11 = [f for f in report.findings if f.rule_code == "DISP-011"]
    drift_12 = [f for f in report.findings if f.rule_code == "DISP-012"]
    drift_13 = [f for f in report.findings if f.rule_code == "DISP-013"]

    # `service_counts` is a count field -> blocking DISP-011 with both display & producer locations
    assert any(
        "service_counts" in f.detail
        and "frontend/views/pulse-view.js:" in f.detail
        and "backend/app/slices.py:" in f.detail
        and f.blocks_gate
        for f in drift_11
    )
    # `sources` and `attention_mirror.sources` -> warning DISP-012 with both locations
    assert any(
        "sources" in f.detail
        and "frontend/views/pulse-view.js:" in f.detail
        and "backend/app/slices.py:" in f.detail
        for f in drift_12
    )
    # `health_sources` / `source_health` emitted by producer and unread by display -> info DISP-013
    assert any(
        "health_sources" in f.detail and f.severity == "info" and not f.blocks_gate
        for f in drift_13
    )
    # Dynamic builder yields coverage=partial note and zero false positives on `dyn-view.js`
    assert any("coverage=partial" in n and "_build_dynamic" in n for n in report.scan_notes)
    assert not any("dyn-view.js" in f.source_file for f in (*drift_11, *drift_12))


def test_121_freshness_laundering_and_valid_propagation(tmp_path: Path) -> None:
    """#121: Flag observed_at=now(), stale=False, & unenforced valid_until; clean propagation passes."""
    (tmp_path / "backend" / "app").mkdir(parents=True)
    (tmp_path / "backend" / "app" / "builders.py").write_text(
        "import json\n"
        "from datetime import datetime, timezone\n\n"
        "def build_laundered(state_path):\n"
        "    src = json.loads(state_path.read_text())\n"
        "    return {\n"
        "        'observed_at': datetime.now(timezone.utc).isoformat(),\n"
        "        'valid_until': src.get('valid_until'),\n"
        "        'stale': False,\n"
        "        'evidence_state': 'measured',\n"
        "        'value': src.get('value'),\n"
        "    }\n\n"
        "def build_honest(state_path, ref_now):\n"
        "    src = json.loads(state_path.read_text())\n"
        "    obs = src.get('observed_at')\n"
        "    vu = src.get('valid_until')\n"
        "    return {\n"
        "        'observed_at': obs,\n"
        "        'valid_until': vu,\n"
        "        'stale': bool(vu and vu < ref_now),\n"
        "        'evidence_state': src.get('evidence_state', 'unknown'),\n"
        "    }\n\n"
        "SLICE_BUILDERS = {'bad': build_laundered, 'good': build_honest}\n",
        encoding="utf-8",
    )

    views = tmp_path / "frontend" / "views"
    views.mkdir(parents=True)
    (views / "bad-freshness.js").write_text(
        "export async function renderBad(client) {\n"
        "  const data = await client.fetchSlice('bad');\n"
        "  return { expiresLabel: data.valid_until, val: data.value };\n"
        "}\n",
        encoding="utf-8",
    )
    (views / "good-freshness.js").write_text(
        "export async function renderGood(client, nowMs) {\n"
        "  const data = await client.fetchSlice('good');\n"
        "  if (data.evidence_state === 'source_error' || data.evidence_state === 'could_not_measure') {\n"
        "    return { status: 'degraded' };\n"
        "  }\n"
        "  const isStale = data.valid_until ? Date.parse(data.valid_until) < nowMs : true;\n"
        "  return { status: isStale ? 'stale' : 'fresh' };\n"
        "}\n",
        encoding="utf-8",
    )

    report = _scan_fixture(tmp_path)
    manip_007 = [f for f in report.findings if f.rule_code == "MANIP-007"]
    disp_014 = [f for f in report.findings if f.rule_code == "DISP-014"]

    assert any("build_laundered" in f.title and "request clock" in f.title for f in manip_007)
    assert any("build_laundered" in f.title and "stale=False" in f.title for f in manip_007)
    assert not any("build_honest" in f.title for f in manip_007)

    assert any("bad-freshness.js" in f.source_file and "valid_until" in f.title for f in disp_014)
    assert any("bad-freshness.js" in f.source_file and "evidence_state" in f.title for f in disp_014)
    assert not any("good-freshness.js" in f.source_file for f in disp_014)


def test_epistemic_coverage_out_and_notes_on_symlink_or_syntax_error(tmp_path: Path) -> None:
    """Contract #1 + P1-8: coverage_out=[False] and epistemic_coverage_incomplete note on failures."""
    from app.adapters.base import DisplayExtractionResult, ManipulatorExtractionResult
    from app.adapters.epistemic_confabulation import evaluate_epistemic_confabulation

    (tmp_path / "backend" / "app").mkdir(parents=True)
    (tmp_path / "frontend" / "src").mkdir(parents=True)
    (tmp_path / "backend" / "app" / "broken.py").write_text("def broken(:\n", encoding="utf-8")
    outside = tmp_path / "outside.js"
    outside.write_text("export const x = 1;\n", encoding="utf-8")
    (tmp_path / "frontend" / "src" / "linked.js").symlink_to(outside)

    manip = ManipulatorExtractionResult(nodes=[], edges=[], routes=[], notes=[])
    disp = DisplayExtractionResult(nodes=[], edges=[], http_calls=[], notes=[])
    cov_out: list[bool] = []

    _findings, notes = evaluate_epistemic_confabulation(
        tmp_path,
        "backend",
        "frontend",
        manip,
        disp,
        strict=True,
        coverage_out=cov_out,
    )

    assert cov_out == [False]
    assert manip.coverage_complete is True
    assert disp.coverage_complete is True
    assert any(n.startswith("epistemic_coverage_incomplete: ") for n in notes)


def test_p1_10_word_boundaries_store_receivers_nested_scopes_and_lexical_js(tmp_path: Path) -> None:
    """P1-10: word-bound action props, store receivers, nested scopes, partial ret, JS lexical scoping."""
    import textwrap

    from app.adapters.base import (
        DisplayExtractionResult,
        FrontendHttpCall,
        ManipulatorExtractionResult,
        RouteDescriptor,
    )
    from app.adapters.epistemic_confabulation import evaluate_epistemic_confabulation
    from app.adapters.epistemic_display_checks import analyze_display_confabulation_and_reads
    from app.adapters.epistemic_freshness_manip import analyze_python_freshness_and_producers

    (tmp_path / "backend" / "app").mkdir(parents=True)
    (tmp_path / "frontend" / "src").mkdir(parents=True)

    py_src = textwrap.dedent(
        """\
        import json
        from datetime import datetime, timezone

        def create_app():
            def nested_status():
                return {"status": "ok", "generated_at": "2026-01-01"}
            return nested_status

        def helper_noise(items):
            seen = set()
            seen.add("x")
            ts = "2026-01-01T00:00:00".replace("T", " ")
            return ts

        def build_slice(state_path):
            src = json.loads(state_path.read_text())
            seen = set()
            seen.add("x")
            ts = datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")
            return {"observed_at": ts, "value": src.get("value")}

        def mixed_return(flag: bool):
            if flag:
                return {"items": [], "total": 0}
            return build_dynamic_payload()
        """
    )
    (tmp_path / "backend" / "app" / "routes.py").write_text(py_src, encoding="utf-8")

    js_src = textwrap.dedent(
        """\
        export async function loadTransactionAndHourly() {
            const payload = await fetch("/api/items").then((r) => r.json());
            return { transactionId: payload.transactionId, hourly: payload.hourly, curlCmd: payload.curl };
        }

        export async function fnOne() {
            const data = await fetch("/api/alpha").then((r) => r.json());
            return data.alpha_only;
        }

        export async function fnTwo() {
            const data = await fetch("/api/beta").then((r) => r.json());
            return data.beta_only;
        }
        """
    )
    (tmp_path / "frontend" / "src" / "multi.js").write_text(js_src, encoding="utf-8")

    manip = ManipulatorExtractionResult(
        nodes=[],
        edges=[],
        routes=[
            RouteDescriptor(
                node_id="r:GET:/api/items",
                http_method="GET",
                full_path="/api/items",
                path_regex=r"^/api/items$",
                source_file="backend/app/routes.py",
                line=py_src.splitlines().index("def mixed_return(flag: bool):") + 1,
                called_symbols=frozenset(),
                imported_modules=frozenset(),
            )
        ],
        notes=[],
    )
    mf, contracts = analyze_python_freshness_and_producers(tmp_path, "backend", manip)
    # seen.add and string.replace should NOT mark helper_noise as a store write/persist producer
    assert not any("helper_noise" in f.title for f in mf if f.rule_code == "MANIP-007")
    # build_slice reads upstream state and stamps request clock -> MUST trigger MANIP-007
    assert any("build_slice" in f.title and "request clock" in f.title for f in mf if f.rule_code == "MANIP-007")
    # mixed_return has a dynamic Call return, so coverage must degrade to partial
    mixed = [c for c in contracts.values() if c.func_name == "mixed_return"]
    assert mixed and mixed[0].coverage == "partial"

    disp = DisplayExtractionResult(
        nodes=[],
        edges=[],
        http_calls=[
            FrontendHttpCall(
                caller_node_id="d:multi.js",
                http_method="GET",
                raw_path="/api/items",
                normalized_path="/api/items",
                source_file="frontend/src/multi.js",
                line=2,
            ),
            FrontendHttpCall(
                caller_node_id="d:multi.js",
                http_method="GET",
                raw_path="/api/alpha",
                normalized_path="/api/alpha",
                source_file="frontend/src/multi.js",
                line=7,
            ),
            FrontendHttpCall(
                caller_node_id="d:multi.js",
                http_method="GET",
                raw_path="/api/beta",
                normalized_path="/api/beta",
                source_file="frontend/src/multi.js",
                line=12,
            ),
        ],
        notes=[],
    )
    disp_findings, reads = analyze_display_confabulation_and_reads(
        tmp_path, "frontend", disp, strict=True
    )
    # transaction / hourly / curl must NOT trigger DISP-010 action-claim false positives
    assert not any(f.rule_code == "DISP-010" for f in disp_findings)
    # Lexical scoping: /api/alpha reads alpha_only, /api/beta reads beta_only without cross-leak
    alpha_reads = [r for r in reads if "/api/alpha" in r.route_key]
    beta_reads = [r for r in reads if "/api/beta" in r.route_key]
    assert alpha_reads and "alpha_only" in alpha_reads[0].read_paths and "beta_only" not in alpha_reads[0].read_paths
    assert beta_reads and "beta_only" in beta_reads[0].read_paths and "alpha_only" not in beta_reads[0].read_paths
    _ef, _notes = evaluate_epistemic_confabulation(tmp_path, "backend", "frontend", manip, disp, strict=True)

