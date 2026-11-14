"""Regression checks for frontend npm dependency safety and lockfile hygiene."""

from __future__ import annotations

import json
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[2]


def _parse_semver(raw: str) -> tuple[int, int, int]:
    core = raw.split("-", 1)[0].lstrip("^~>=<")
    parts = [int(part) for part in core.split(".")[:3]]
    while len(parts) < 3:
        parts.append(0)
    return (parts[0], parts[1], parts[2])


def test_frontend_lockfile_has_no_vulnerable_nested_postcss() -> None:
    """Ensure Next.js uses patched PostCSS (>= 8.5.32) with no nested 8.4.x copy."""
    pkg_json = json.loads((REPO_ROOT / "frontend" / "package.json").read_text(encoding="utf-8"))
    assert pkg_json.get("overrides", {}).get("next", {}).get("postcss")

    lock = json.loads((REPO_ROOT / "frontend" / "package-lock.json").read_text(encoding="utf-8"))
    postcss_entries = [
        (key, meta)
        for key, meta in lock.get("packages", {}).items()
        if key == "node_modules/postcss" or key.endswith("/node_modules/postcss")
    ]
    assert postcss_entries, "expected hoisted postcss entry in frontend/package-lock.json"
    for key, meta in postcss_entries:
        version = str(meta.get("version", "0.0.0"))
        assert _parse_semver(version) >= (8, 5, 32), f"{key} resolved vulnerable postcss {version}"
