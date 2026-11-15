"""Opt-in security evidence and separately selected, fixed in-process demonstration."""

from __future__ import annotations

import argparse
import sys
from pathlib import Path

from app.services.ownership_service import inspect_record_ownership


def add_security_parser(subparsers) -> None:
    parser = subparsers.add_parser("security", help="Experimental security evidence; no live target testing")
    actions = parser.add_subparsers(dest="security_action", required=True)
    source = actions.add_parser("ownership", help="Source-only evidence for one record-ownership hypothesis")
    source.add_argument("target", help="Repository root directory (no slug lookup or database access)")
    source.add_argument("--handler", required=True, help="Root-relative file.py:function_name")
    source.add_argument("--record", required=True, help="Handler variable holding the record")
    source.add_argument("--principal", required=True, help="Caller identity expression, e.g. user.id")
    source.add_argument("--owner-field", default="owner_id", help="Ownership attribute on the record")
    source.add_argument("--json", dest="json_out", help="Write a new JSON file; existing files are refused")
    demo = actions.add_parser("ownership-demo", help="Execute only the shipped synthetic before/after examples")
    demo.add_argument("--json", dest="json_out", help="Write a new JSON file; existing files are refused")
    companion = actions.add_parser(
        "companion",
        help="Correlate static blueprint findings with optional Syft SBOM & Trivy reports (non-certifying)",
    )
    companion.add_argument("target", help="Registered target slug or repository path")
    companion.add_argument("--profile", default="auto", help="Stack profile slug or 'auto' (default)")
    companion.add_argument("--trivy-report", default=None, help="Optional read-only Trivy JSON or SARIF report")
    companion.add_argument("--syft-sbom", default=None, help="Optional read-only Syft CycloneDX/SPDX JSON SBOM")
    companion.add_argument("--json", dest="json_out", help="Write JSON handoff receipt to file")


def run_security_command(args: argparse.Namespace) -> int:
    try:
        if args.security_action == "companion":
            import json

            from app.cli import _resolve_cli_target, _write_json_file
            from app.db.session import get_session_factory
            from app.main import initialize_database
            from app.services.companion_export_service import summarize_companion_security_artifacts
            from app.services.scanner_service import run_target_scan

            initialize_database()
            factory = get_session_factory()
            with factory() as session:
                target, _ = _resolve_cli_target(session, args.target, args.profile, ensure_persisted=False)
                scan_report = run_target_scan(session, target, strict_gate=True, persist_snapshot=False)
            summary = summarize_companion_security_artifacts(
                scan_report,
                trivy_path=args.trivy_report,
                syft_path=args.syft_sbom,
            )
            payload = json.dumps(summary, indent=2)
            if args.json_out:
                _write_json_file(args.json_out, payload)
            print(payload)
            return 0
        if args.security_action == "ownership":
            report = inspect_record_ownership(
                Path(args.target), handler=args.handler, record=args.record,
                principal=args.principal, owner_field=args.owner_field,
            )
            code = 0  # Completed evidence collection, never a passing security verdict.
        else:
            from wythe_examples.ownership_lab import run_ownership_demo

            report = run_ownership_demo()
            code = 0 if report.regression_passed else 1
        payload = report.model_dump_json(indent=2)
        if args.json_out:
            path = Path(args.json_out).expanduser()
            with path.open("x", encoding="utf-8") as output:
                output.write(payload + "\n")
        print(payload)
        return code
    except Exception as exc:  # noqa: BLE001 - evidence errors must not appear successful
        print(f"wythe security error: {exc}", file=sys.stderr)
        return 2
