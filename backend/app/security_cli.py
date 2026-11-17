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
    companion.add_argument("--cp-model-proto", default=None, help="Optional read-only CpModelProto (.pb/.pbtxt/JSON)")
    companion.add_argument("--cp-solver-response", default=None, help="Optional read-only CpSolverResponse (.pb/.pbtxt/JSON)")
    companion.add_argument(
        "--allow-local-plugins",
        action="store_true",
        help="Explicit opt-in permitting --plugin local modules/files",
    )
    companion.add_argument(
        "--plugin",
        dest="local_plugins",
        action="append",
        default=None,
        help="Explicit local plugin module or .py file (requires --allow-local-plugins)",
    )
    companion.add_argument(
        "--index-store",
        dest="index_store",
        action="append",
        default=None,
        help="Optional read-only IndexStoreDB / clangd USR index artifact path",
    )
    companion.add_argument(
        "--sil",
        dest="sil",
        action="append",
        default=None,
        help="Optional read-only Swift SIL (.sil) artifact path",
    )
    companion.add_argument(
        "--llvm-ir",
        dest="llvm_ir",
        action="append",
        default=None,
        help="Optional read-only LLVM IR (.ll / .bc dump) artifact path",
    )
    companion.add_argument(
        "--metallib",
        dest="metallib",
        action="append",
        default=None,
        help="Optional read-only compiled Metal AIR (.metallib / metal-objdump) artifact path",
    )
    companion.add_argument(
        "--proto-descriptor",
        dest="proto_descriptor",
        action="append",
        default=None,
        help="Optional read-only protoc FileDescriptorSet (.pb / JSON) artifact path",
    )
    companion.add_argument(
        "--compile-commands",
        dest="compile_commands",
        action="append",
        default=None,
        help="Optional read-only compile_commands.json artifact path",
    )
    companion.add_argument(
        "--binary",
        dest="binary",
        action="append",
        default=None,
        help="Optional read-only Mach-O / ELF binary or bundle path (repeatable; never executed)",
    )
    companion.add_argument(
        "--otel-traces",
        dest="otel_traces",
        action="append",
        default=None,
        help="Optional read-only OpenTelemetry OTLP JSON/NDJSON trace capture file",
    )
    companion.add_argument(
        "--ebpf-flows",
        dest="ebpf_flows",
        action="append",
        default=None,
        help="Optional read-only passive eBPF socket/flow JSON/NDJSON capture file",
    )
    companion.add_argument(
        "--memgraph",
        dest="memgraph",
        action="append",
        default=None,
        help="Optional read-only macOS leaks/memgraph JSON or text capture file",
    )
    companion.add_argument(
        "--vmmap",
        dest="vmmap",
        action="append",
        default=None,
        help="Optional read-only macOS vmmap summary text/JSON capture file",
    )
    companion.add_argument(
        "--port-listeners",
        dest="port_listeners",
        action="append",
        default=None,
        help="Optional read-only recorded lsof/ss/JSON listener table capture file",
    )
    companion.add_argument(
        "--probe-local-ports",
        dest="probe_local_ports",
        action="store_true",
        help="Opt-in: read-only snapshot of local host TCP/UDP listeners",
    )
    companion.add_argument("--json", dest="json_out", help="Write JSON handoff receipt to file")


def run_security_command(args: argparse.Namespace) -> int:
    try:
        if args.security_action == "companion":
            import json

            from app.cli import (
                _artifact_scope_from_args,
                _build_combined_companion_summary,
                _resolve_cli_target,
                _validate_active_cli_artifact_plugins,
                _write_json_file,
            )
            from app.db.session import get_session_factory
            from app.main import initialize_database
            from app.services.scanner_service import run_target_scan

            allow_local = bool(getattr(args, "allow_local_plugins", False))
            local_mods = getattr(args, "local_plugins", None)
            initialize_database()
            factory = get_session_factory()
            with factory() as session, _artifact_scope_from_args(args):
                _validate_active_cli_artifact_plugins(
                    allow_local_plugins=allow_local,
                    local_plugin_modules=local_mods,
                )
                target, _ = _resolve_cli_target(
                    session,
                    args.target,
                    args.profile,
                    ensure_persisted=False,
                    allow_local_plugins=allow_local,
                    local_plugin_modules=local_mods,
                )
                scan_report = run_target_scan(
                    session,
                    target,
                    strict_gate=True,
                    persist_snapshot=False,
                    allow_local_plugins=allow_local,
                    local_plugin_modules=local_mods,
                )
                summary = _build_combined_companion_summary(
                    scan_report,
                    trivy_path=args.trivy_report,
                    syft_path=args.syft_sbom,
                    cp_model_proto_path=getattr(args, "cp_model_proto", None),
                    cp_solver_response_path=getattr(args, "cp_solver_response", None),
                    binary_paths=getattr(args, "binary", None),
                    proto_descriptor_path=getattr(args, "proto_descriptor", None),
                    compile_commands_path=getattr(args, "compile_commands", None),
                    otel_traces_path=getattr(args, "otel_traces", None),
                    ebpf_flows_path=getattr(args, "ebpf_flows", None),
                    memgraph_path=getattr(args, "memgraph", None),
                    vmmap_path=getattr(args, "vmmap", None),
                    port_listeners_path=getattr(args, "port_listeners", None),
                    probe_local_ports=bool(getattr(args, "probe_local_ports", False)),
                    allow_local_plugins=allow_local,
                    local_plugin_modules=local_mods,
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
