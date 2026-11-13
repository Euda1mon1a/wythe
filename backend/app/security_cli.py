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


def run_security_command(args: argparse.Namespace) -> int:
    try:
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
