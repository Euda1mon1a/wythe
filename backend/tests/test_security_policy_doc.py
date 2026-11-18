"""Regression checks for SECURITY.md policy posture and documentation pointers."""

from __future__ import annotations

from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[2]


def _normalized_text(path: Path) -> str:
    return " ".join(path.read_text(encoding="utf-8").split())


def test_security_policy_exists_and_covers_posture_blue_team_and_boundaries() -> None:
    security_doc = REPO_ROOT / "SECURITY.md"
    assert security_doc.is_file(), "SECURITY.md must exist at repository root"

    raw = security_doc.read_text(encoding="utf-8")
    normalized = " ".join(raw.split())

    required_terms = (
        "SUPPORT.md",
        "MIT License",
        "wythe==0.2.6",
        "Euda1mon1a/wythe@v0.2.6",
        "Private Vulnerability Reporting",
        "Security Advisories",
        "wythe security ownership",
        'invariant_result: "unknown"',
        "target_code_executed: false",
        "target_database_contacted: false",
        "1 MiB",
        "wythe gate",
        "wythe security ownership-demo",
        "wythe_examples",
        "backend/wythe_examples/ownership_lab.py",
        "network_requests_sent: false",
        "wythe security companion",
        "automated_security_audit: false",
        "wythe.plugins",
        "--allow-local-plugins",
        "docs/architecture/record-ownership.md",
        "docs/architecture/containers-security-and-plugins.md",
        "127.0.0.1",
        "0.0.0.0",
        "/api/v1/targets",
        "/api/v1/scans",
        "/api/v1/scans/{slug}/source",
        "/api/v1/scans/{slug}/openlineage",
        "/api/v1/adapters/plugins",
        "--dsn",
        "pg_catalog",
        "information_schema",
        "read-only",
        "wythe context",
        "wythe llms",
        "wythe mcp",
        "What's This?",
    )
    missing = [term for term in required_terms if term not in normalized]
    assert not missing, f"SECURITY.md is missing required terms: {missing}"


def test_security_policy_pointer_links_in_readme_and_user_guide() -> None:
    readme = _normalized_text(REPO_ROOT / "README.md")
    support = _normalized_text(REPO_ROOT / "SUPPORT.md")
    user_guide = _normalized_text(REPO_ROOT / "docs" / "user-guide.md")

    assert "### Record ownership (experimental)" in readme
    assert "[SECURITY.md](SECURITY.md)" in readme
    assert "Euda1mon1a/wythe@v0.2.6" in readme
    assert "wythe==0.2.6" in support
    assert "[SECURITY.md](../SECURITY.md)" in user_guide
