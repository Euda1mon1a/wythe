"""Regression tests for Python call-graph precision: relative imports, package re-exports,
caller-only infrastructure files, and coincidental name matches."""

from __future__ import annotations

from pathlib import Path

from app.adapters.base import ManipulatorExtractionResult, TruthExtractionResult
from app.adapters.python_fastapi import PythonFastApiAdapter

_EMPTY_TRUTH = TruthExtractionResult(
    nodes=[], table_symbol_map={}, function_symbol_map={}, findings=[], observation_source="static_ast"
)
_ROUTE = (
    "from fastapi import APIRouter\n"
    "{imports}\n\n"
    "router = APIRouter()\n\n"
    "@router.get('/api/v1/thing')\n"
    "def get_thing():\n"
    "    return {body}\n"
)


def _write(root: Path, files: dict[str, str]) -> None:
    for rel, text in files.items():
        path = root / "backend" / "app" / rel
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(text, encoding="utf-8")


def _extract(root: Path) -> ManipulatorExtractionResult:
    return PythonFastApiAdapter().extract(root, "backend", _EMPTY_TRUTH)


def _edge_pairs(res: ManipulatorExtractionResult) -> set[tuple[str, str]]:
    return {(e.source_id, e.target_id) for e in res.edges if e.kind == "calls_helper"}


def _inert(res: ManipulatorExtractionResult) -> set[str]:
    return {f.node_id for f in res.findings if f.rule_code == "MANIP-003"}


def test_relative_imports_reach_sibling_modules(tmp_path: Path) -> None:
    _write(
        tmp_path,
        {
            "billing/__init__.py": "",
            "billing/rates.py": "RATE_TABLE = {'std': 1}\n",
            "billing/fees.py": "FLAT_FEE = 2\n",
            "billing/engine.py": (
                "from .rates import RATE_TABLE\n"
                "from . import fees\n\n"
                "def price(kind):\n"
                "    return RATE_TABLE[kind] + fees.FLAT_FEE\n"
            ),
            "api/routes/thing.py": _ROUTE.format(imports="from app.billing.engine import price", body="price('std')"),
        },
    )
    res = _extract(tmp_path)
    pairs = _edge_pairs(res)
    assert ("m:service:billing.engine", "m:service:billing.rates") in pairs
    assert ("m:service:billing.engine", "m:service:billing.fees") in pairs
    assert not {"m:service:billing.rates", "m:service:billing.fees"} & _inert(res)


def test_package_reexports_lazy_tables_and_initializer_use(tmp_path: Path) -> None:
    _write(
        tmp_path,
        {
            # Plain re-export, plus one re-exported name that nobody consumes.
            "notify/__init__.py": "from .codes import CHANNEL_CODES\nfrom .spare import SpareChannel\n",
            "notify/codes.py": "CHANNEL_CODES = ('email', 'sms')\n",
            "notify/spare.py": "class SpareChannel:\n    pass\n",
            # PEP 562 lazy table; a second class of the same name elsewhere defeats name matching.
            "plugins/__init__.py": (
                "from importlib import import_module\n\n"
                "_EXPORTS = {'Renderer': ('app.plugins.render', 'Renderer')}\n\n"
                "def __getattr__(name):\n"
                "    module_name, attr = _EXPORTS[name]\n"
                "    return getattr(import_module(module_name), attr)\n"
            ),
            "plugins/render.py": "class Renderer:\n    def draw(self):\n        return 1\n",
            "legacy/render.py": "class Renderer:\n    pass\n",
            # Code that lives in the package initializer itself, built on a submodule.
            "toolkit/__init__.py": (
                "from .scrub import scrub_text\n"
                "from .report import render_report\n\n"
                "def clean(value):\n    return scrub_text(value)\n\n"
                "def summary():\n    return render_report()\n"
            ),
            "toolkit/scrub.py": "def scrub_text(value):\n    return value.strip()\n",
            "toolkit/report.py": "def render_report():\n    return ''\n",
            # A same-named module file that the package shadows: `app.toolkit` never imports it.
            "toolkit.py": "def clean(value):\n    return value\n",
            "services/alerts.py": (
                "from app.notify import CHANNEL_CODES\n"
                "from app.plugins import Renderer\n"
                "from app.toolkit import clean\n\n"
                "def channels():\n"
                "    return [clean(c) for c in CHANNEL_CODES], Renderer()\n"
            ),
            "api/routes/thing.py": _ROUTE.format(imports="from app.services.alerts import channels", body="channels()"),
        },
    )
    res = _extract(tmp_path)
    pairs = _edge_pairs(res)
    assert ("m:service:services.alerts", "m:service:notify.codes") in pairs
    assert ("m:service:services.alerts", "m:service:plugins.render") in pairs
    assert ("m:service:services.alerts", "m:service:toolkit.scrub") in pairs
    assert ("m:service:services.alerts", "m:service:legacy.render") not in pairs
    assert ("m:service:services.alerts", "m:service:toolkit") not in pairs
    # Only what the imported initializer name (`clean`) itself uses is credited.
    assert ("m:service:services.alerts", "m:service:toolkit.report") not in pairs
    inert = _inert(res)
    assert not {"m:service:notify.codes", "m:service:plugins.render", "m:service:toolkit.scrub"} & inert
    # A re-export alone is not a caller.
    assert {"m:service:notify.spare", "m:service:toolkit", "m:service:toolkit.report"} <= inert


def test_infrastructure_and_model_files_count_as_callers_but_tests_do_not(tmp_path: Path) -> None:
    _write(
        tmp_path,
        {
            "db/base.py": "from app.db import guards  # noqa: F401  (registers listeners on import)\n",
            "db/guards.py": "def check_row(row):\n    return row\n",
            "models/thing.py": "from app.services.slugs import make_slug\n\nclass Thing:\n    slug = make_slug('x')\n",
            "services/slugs.py": "def make_slug(text):\n    return text.lower()\n",
            "services/lonely.py": "def lonely():\n    return 1\n",
            "tests/test_lonely.py": "from app.services.lonely import lonely\n\ndef test_it():\n    assert lonely() == 1\n",
        },
    )
    inert = _inert(_extract(tmp_path))
    assert "m:service:db.guards" not in inert
    assert "m:service:services.slugs" not in inert
    assert "m:service:services.lonely" in inert


def test_coincidental_name_matches_do_not_forge_call_edges(tmp_path: Path) -> None:
    _write(
        tmp_path,
        {
            "services/audit_sink.py": "class AuditSink:\n    def error(self, message):\n        return message\n",
            "services/builders.py": "class QueryBuilder:\n    def type(self, kind):\n        return kind\n",
            "graph/shapes.py": "class Widget:\n    pass\n",
            "models/widget.py": "class Widget:\n    pass\n",
            "services/catalog.py": "class SlotCatalog:\n    def list_slots(self):\n        return []\n",
            "services/billing.py": (
                "import logging\n"
                "from app.models.widget import Widget\n\n"
                "logger = logging.getLogger(__name__)\n\n"
                "def charge(item, registry):\n"
                "    logger.error('declined')\n"
                "    return type(item), Widget(), registry.list_slots()\n"
            ),
            "api/routes/thing.py": _ROUTE.format(imports="from app.services.billing import charge", body="charge(1, None)"),
        },
    )
    res = _extract(tmp_path)
    pairs = _edge_pairs(res)
    billing = "m:service:services.billing"
    assert (billing, "m:service:services.audit_sink") not in pairs  # logger.error()
    assert (billing, "m:service:services.builders") not in pairs  # builtin type()
    assert (billing, "m:service:graph.shapes") not in pairs  # Widget() is the imported model
    assert (billing, "m:service:services.catalog") in pairs  # duck-typed call on an injected parameter
    assert {"m:service:services.audit_sink", "m:service:services.builders", "m:service:graph.shapes"} <= _inert(res)
