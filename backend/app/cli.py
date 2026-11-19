"""Wythe CLI: scan, fail-closed gate, PR diff/blast-radius, SARIF, portable sync, & server."""

from __future__ import annotations

import argparse
import json
import os
import re
import sys
import urllib.parse
import urllib.request
from collections.abc import Sequence
from pathlib import Path

import httpx
import uvicorn

from app.adapters.autodetect import detect_repository_stack
from app.adapters.plugin_registry import (
    ENTRY_POINT_GROUP,
    _normalize_artifact_tuple,
    discover_plugins,
    dispatch_plugin_cli_subcommand,
    get_active_stratum_artifacts,
    list_registered_plugins,
    run_plugin_companion_handlers,
    stratum_artifacts_scope,
)
from app.core.config import load_settings
from app.db.session import get_session_factory
from app.main import create_app, initialize_database
from app.models import TargetProject
from app.schemas.atlas import TargetProjectCreate
from app.security_cli import add_security_parser, run_security_command
from app.services.companion_export_service import (
    build_openlineage_static_bundle,
    summarize_companion_security_artifacts,
)
from app.services.diff_and_sarif_service import (
    build_sarif_log,
    run_target_diff,
)
from app.services.governance_service import get_target_by_slug, register_target
from app.services.llm_context_service import (
    DEFAULT_BRIEF_TOKENS,
    DEFAULT_CONE_NODES,
    build_lineage_cone_slice,
    build_llms_txt_brief,
)
from app.services.mcp_service import run_mcp_stdio_server
from app.services.portable_config_service import (
    export_portable_bundle_to_disk,
    resolve_existing_bundle_path,
    sync_portable_bundle_from_disk,
)
from app.services.scanner_service import run_target_scan
from app.services.ui_focus_service import explain_ui_focus
from app.services.viewport_service import (
    DEFAULT_VIEWPORT_ORIGIN,
    _validate_viewport_server_url,
)


def _run_reply_cli(args: argparse.Namespace) -> int:
    """Pipe frontier/terminal markdown into the live Ask Wythe drawer + optional 3D viewport steering."""
    if args.message is not None:
        raw_md = str(args.message)
    elif args.file is not None:
        raw_md = Path(args.file).expanduser().read_text(encoding="utf-8")
    else:
        is_tty = bool(getattr(sys.stdin, "isatty", lambda: False)())
        if is_tty or sys.stdin is None:
            print(
                "wythe reply error: provide markdown via stdin pipe, --message, or --file.",
                file=sys.stderr,
            )
            return 2
        raw_md = sys.stdin.read()

    markdown_body = raw_md.strip()
    if not markdown_body:
        print("wythe reply error: empty markdown reply body.", file=sys.stderr)
        return 2

    server_raw = (
        args.server
        or os.getenv("WYTHE_SERVER_URL")
        or DEFAULT_VIEWPORT_ORIGIN
    )
    vp_cmd_url = _validate_viewport_server_url(
        server_raw,
        allow_remote=bool(args.allow_remote_viewport),
    )
    api_base = vp_cmd_url.removesuffix("/viewport/command")

    focus_ids: list[str] = []
    for raw_item in args.focus or []:
        for tok in str(raw_item).split(","):
            cleaned_tok = tok.strip()
            if cleaned_tok and cleaned_tok not in focus_ids:
                focus_ids.append(cleaned_tok)

    resolved_slug = (args.target or "").strip() or None
    resolved_sid = (args.session or "").strip() or None
    question_text = (args.question or "External frontier CLI analysis").strip()

    with httpx.Client(trust_env=False, follow_redirects=False, timeout=10.0) as client:
        if not resolved_slug or not resolved_sid:
            q_parts: list[str] = []
            if resolved_slug:
                q_parts.append(f"target={urllib.parse.quote(resolved_slug)}")
            if resolved_sid:
                q_parts.append(f"session_id={urllib.parse.quote(resolved_sid)}")
            qs = f"?{'&'.join(q_parts)}" if q_parts else ""
            focus_resp = client.get(f"{api_base}/ui-focus{qs}")
            if 200 <= focus_resp.status_code < 300:
                focus_json = focus_resp.json()
                if not resolved_slug and isinstance(focus_json.get("active_slug"), str):
                    resolved_slug = focus_json["active_slug"].strip() or None
                if not resolved_sid and isinstance(focus_json.get("session_id"), str):
                    resolved_sid = focus_json["session_id"].strip() or None

        if not resolved_slug:
            targets_resp = client.get(f"{api_base}/targets")
            if 200 <= targets_resp.status_code < 300:
                targets_list = targets_resp.json()
                if isinstance(targets_list, list) and targets_list:
                    resolved_slug = str(targets_list[0].get("slug") or "").strip() or None
        if not resolved_slug:
            print("wythe reply error: could not resolve an active target slug.", file=sys.stderr)
            return 2

        if not resolved_sid:
            inv_list_resp = client.get(
                f"{api_base}/investigations?target_slug={urllib.parse.quote(resolved_slug)}"
            )
            if 200 <= inv_list_resp.status_code < 300:
                sessions = inv_list_resp.json().get("sessions") or []
                if sessions:
                    resolved_sid = str(sessions[0].get("session_id") or "").strip() or None
            if not resolved_sid:
                create_resp = client.post(
                    f"{api_base}/investigations",
                    json={"target_slug": resolved_slug, "client_id": "wythe-reply-cli"},
                )
                if create_resp.status_code < 200 or create_resp.status_code >= 300:
                    print(
                        f"wythe reply error: failed to create session (HTTP {create_resp.status_code}): "
                        f"{create_resp.text[:240]}",
                        file=sys.stderr,
                    )
                    return 2
                resolved_sid = str(create_resp.json()["session_id"])

        turn_payload = {
            "client_id": "wythe-reply-cli",
            "actor": "agent",
            "question": question_text,
            "answer_markdown": markdown_body,
            "engine": str(args.engine or "frontier"),
            "model_id": str(args.model or "frontier-cli"),
            "authored_by": "model",
            "selected_node_id": focus_ids[0] if focus_ids else None,
            "referenced_ids": focus_ids,
        }
        turn_resp = client.post(
            f"{api_base}/investigations/{urllib.parse.quote(resolved_sid, safe='')}/turns",
            json=turn_payload,
        )
        if turn_resp.status_code == 404:
            reopen_resp = client.post(
                f"{api_base}/investigations",
                json={
                    "target_slug": resolved_slug,
                    "session_id": resolved_sid,
                    "client_id": "wythe-reply-cli",
                },
            )
            if 200 <= reopen_resp.status_code < 300:
                turn_resp = client.post(
                    f"{api_base}/investigations/{urllib.parse.quote(resolved_sid, safe='')}/turns",
                    json=turn_payload,
                )
        if turn_resp.status_code < 200 or turn_resp.status_code >= 300:
            print(
                f"wythe reply error: turn rejected (HTTP {turn_resp.status_code}): {turn_resp.text[:240]}",
                file=sys.stderr,
            )
            return 2
        turn_json = turn_resp.json()

        has_explicit_vp = bool(
            focus_ids
            or args.lens
            or args.layout_mode
            or args.tier_filter
            or args.only_flagged
            or args.isolate_cone
            or args.reset_filters
        )
        vp_seq: int | None = None
        if has_explicit_vp:
            vp_body = {
                "target_slug": resolved_slug,
                "session_id": resolved_sid,
                "refresh_session_id": resolved_sid,
                "open_drawer": True,
                "focus_node_ids": focus_ids,
                "selected_node_id": focus_ids[0] if focus_ids else None,
                "lens": args.lens,
                "layout_mode": args.layout_mode,
                "tier_filter": args.tier_filter,
                "only_flagged": True if args.only_flagged else None,
                "isolate_cone": True if args.isolate_cone else None,
                "reset_filters": bool(args.reset_filters),
            }
            vp_resp = client.post(vp_cmd_url, json=vp_body)
            if vp_resp.status_code < 200 or vp_resp.status_code >= 300:
                print(
                    f"wythe reply error: viewport command rejected (HTTP {vp_resp.status_code}): "
                    f"{vp_resp.text[:240]}",
                    file=sys.stderr,
                )
                return 2
            vp_seq = int(vp_resp.json().get("seq") or 0) or None

    val_refs = turn_json.get("validated_references") or []
    val_count = sum(
        1 for item in val_refs if isinstance(item, dict) and item.get("validation_state") == "validated"
    )
    receipt = {
        "ok": True,
        "target_slug": resolved_slug,
        "session_id": turn_json["session_id"],
        "turn_id": turn_json["turn_id"],
        "validated_ref_count": val_count,
        "viewport_command_seq": vp_seq,
    }
    print(json.dumps(receipt, indent=2))
    return 0


def _resolve_cli_target(
    session,
    target_or_path: str,
    profile: str,
    *,
    ensure_persisted: bool = False,
    allow_local_plugins: bool = False,
    local_plugin_modules: list[str] | None = None,
) -> tuple[TargetProject, bool]:
    looks_like_path = (
        target_or_path in (".", "..")
        or "/" in target_or_path
        or "\\" in target_or_path
        or target_or_path.startswith("~")
    )
    if not looks_like_path:
        existing = get_target_by_slug(session, target_or_path)
        if existing is not None:
            return existing, True

    candidate = Path(target_or_path).expanduser().resolve()
    if not candidate.is_dir():
        raise FileNotFoundError(
            f"Target '{target_or_path}' is neither a registered slug nor a directory"
        )

    detected = detect_repository_stack(
        session,
        str(candidate),
        allow_local_plugins=allow_local_plugins,
        local_plugin_modules=local_plugin_modules,
    )
    chosen_profile = detected.recommended_profile_slug if profile == "auto" else profile
    legacy_snap = "backend/app/data/truth_atlas_snapshot.json"
    has_legacy = (candidate / legacy_snap).is_file()
    clean_slug = re.sub(r"[^a-z0-9-_]", "-", candidate.name.lower()).strip("-") or "cli-target"
    bundle_candidate = resolve_existing_bundle_path(candidate)
    if bundle_candidate.is_file():
        try:
            raw_b = json.loads(bundle_candidate.read_text(encoding="utf-8"))
            if isinstance(raw_b.get("target_slug"), str) and raw_b["target_slug"].strip():
                clean_slug = raw_b["target_slug"].strip()
        except (OSError, ValueError):
            pass
    if len(clean_slug) < 2:
        clean_slug = f"{clean_slug}-repo"

    if ensure_persisted:
        by_slug = get_target_by_slug(session, clean_slug)
        if by_slug is not None and Path(by_slug.repo_path).resolve() == candidate:
            return by_slug, True
        register_target(
            session,
            TargetProjectCreate(
                slug=clean_slug,
                name=candidate.name,
                repo_path=str(candidate),
                stack_profile_slug=chosen_profile,
                backend_subdir=detected.backend_subdir,
                frontend_subdir=detected.frontend_subdir,
                legacy_snapshot_relpath=legacy_snap if has_legacy else None,
                description="Registered via CLI config sync",
                created_by="cli",
            ),
        )
        persisted = get_target_by_slug(session, clean_slug)
        if persisted is not None:
            return persisted, True

    ephemeral = TargetProject(
        id=0,
        slug=clean_slug,
        name=candidate.name,
        repo_path=str(candidate),
        stack_profile_slug=chosen_profile,
        backend_subdir=detected.backend_subdir,
        frontend_subdir=detected.frontend_subdir,
        legacy_snapshot_relpath=legacy_snap if has_legacy else None,
        description="Ad-hoc CLI target",
        is_active=True,
    )
    return ephemeral, False


def _print_report_summary(report) -> None:
    s = report.summary
    ephemeral_note = (
        f", {s.ephemeral_stores} Redis ephemeral store(s)" if s.ephemeral_stores > 0 else ""
    )
    maturity_tag = (
        f" [{report.stack_profile_status}]"
        if getattr(report, "stack_profile_status", "implemented") != "implemented"
        else ""
    )
    print(f"Wythe :: {report.target_name} ({report.target_slug})")
    print(
        f"  Profile : {report.stack_profile}{maturity_tag} | Commit: {_commit_label(report)} | Source: {report.observation_source}"
    )
    if getattr(report, "stack_profile_status", "implemented") == "experimental":
        print(
            "  Maturity: Experimental profile — prefer 'wythe diff' or ratchets over '--strict' until tuned for your repo."
        )
    print(f"  Digest  : {report.content_digest[:16]}...")
    print(
        f"  Tier 1 (DB Truth)        : {s.truth_tables} tables, {s.sql_functions} SQL functions{ephemeral_note}"
    )
    print(
        f"  Tier 2 (Manipulate)      : {s.manipulator_routes} route modules, {s.manipulator_services} service/solver modules"
    )
    print(
        f"  Tier 3 (Display)         : {s.display_pages} pages, {s.display_hooks_and_clients} hooks/clients/components"
    )
    print(
        f"  Lineage                  : {s.verified_edges} verified edges, "
        f"{sum(e.verification == 'declared' for e in report.edges)} declared edges, "
        f"{s.end_to_end_chains} end-to-end 3-tier chains"
    )
    if report.legacy_bridge.present:
        lb = report.legacy_bridge
        print(
            f"  Legacy Bridge            : {lb.receipts_verified}/{lb.receipts_checked} receipts verified "
            f"({lb.receipts_changed} changed, {lb.cutover_reclassified_count} completed cutover(s) normalized to clean)"
        )
    print(
        f"  Gate Verdict             : {report.gate.verdict} (mode={report.gate.mode}, "
        f"blocking={s.blocking_findings}, warnings={s.warning_findings})"
    )
    for row in report.gate.rule_counts:
        if row.observed_count > 0 or row.baseline_max is not None:
            ceil_str = f" / max {row.baseline_max}" if row.baseline_max is not None else ""
            print(
                f"    - {row.rule_code} [{row.tier:<10}] {row.observed_count}{ceil_str} ({row.status}) :: {row.title}"
            )
    for note in getattr(report, "scan_notes", []) or []:
        print(f"  Note                     : {note}")


def _commit_label(report) -> str:
    """`abc123def456`, or `abc123def456 + 12 uncommitted paths` when the scanned tree is dirty."""
    label = report.source_commit[:12]
    count = getattr(report, "dirty_path_count", None)
    if count:
        label += f" + {count} uncommitted path{'s' if count != 1 else ''}"
    return label


def _add_probe_args(p: argparse.ArgumentParser) -> None:
    p.add_argument(
        "--probe-url",
        default=None,
        help=(
            "Opt-in: base URL of a running backend (what frontend API paths are relative to). "
            "Sends one unauthenticated GET per unbacked call to confirm (404/405) or clear it."
        ),
    )
    p.add_argument(
        "--probe-allow-remote",
        action="store_true",
        help="Allow --probe-url to target a host that is not loopback/private",
    )


def _add_plugin_optin_args(p: argparse.ArgumentParser) -> None:
    p.add_argument(
        "--allow-local-plugins",
        action="store_true",
        help="Explicit opt-in permitting --plugin local modules/files",
    )
    p.add_argument(
        "--plugin",
        dest="local_plugins",
        action="append",
        default=None,
        help="Explicit local plugin module or .py file (requires --allow-local-plugins)",
    )


def _add_stratum_artifact_args(p: argparse.ArgumentParser) -> None:
    p.add_argument(
        "--index-store",
        dest="index_store",
        action="append",
        default=None,
        help="Optional read-only IndexStoreDB / clangd USR index artifact path",
    )
    p.add_argument(
        "--sil",
        dest="sil",
        action="append",
        default=None,
        help="Optional read-only Swift SIL (.sil) artifact path",
    )
    p.add_argument(
        "--llvm-ir",
        dest="llvm_ir",
        action="append",
        default=None,
        help="Optional read-only LLVM IR (.ll / .bc dump) artifact path",
    )
    p.add_argument(
        "--metallib",
        dest="metallib",
        action="append",
        default=None,
        help="Optional read-only compiled Metal AIR (.metallib / metal-objdump) artifact path",
    )
    p.add_argument(
        "--proto-descriptor",
        dest="proto_descriptor",
        action="append",
        default=None,
        help="Optional read-only protoc FileDescriptorSet (.pb / JSON) artifact path",
    )
    p.add_argument(
        "--compile-commands",
        dest="compile_commands",
        action="append",
        default=None,
        help="Optional read-only compile_commands.json artifact path",
    )
    p.add_argument(
        "--binary",
        dest="binary",
        action="append",
        default=None,
        help="Optional read-only Mach-O / ELF binary or bundle path (repeatable; never executed)",
    )
    p.add_argument(
        "--otel-traces",
        dest="otel_traces",
        action="append",
        default=None,
        help="Optional read-only OpenTelemetry OTLP JSON/NDJSON trace capture file",
    )
    p.add_argument(
        "--ebpf-flows",
        dest="ebpf_flows",
        action="append",
        default=None,
        help="Optional read-only passive eBPF socket/flow JSON/NDJSON capture file",
    )
    p.add_argument(
        "--memgraph",
        dest="memgraph",
        action="append",
        default=None,
        help="Optional read-only macOS leaks/memgraph JSON or text capture file",
    )
    p.add_argument(
        "--vmmap",
        dest="vmmap",
        action="append",
        default=None,
        help="Optional read-only macOS vmmap summary text/JSON capture file",
    )
    p.add_argument(
        "--port-listeners",
        dest="port_listeners",
        action="append",
        default=None,
        help="Optional read-only recorded lsof/ss/JSON listener table capture file",
    )
    p.add_argument(
        "--probe-local-ports",
        dest="probe_local_ports",
        action="store_true",
        help="Opt-in: read-only snapshot of local host TCP/UDP listeners for PORT-001/PORT-002 correlation",
    )


def _artifact_scope_from_args(args: argparse.Namespace):
    return stratum_artifacts_scope(
        index_store=getattr(args, "index_store", None),
        sil=getattr(args, "sil", None),
        llvm_ir=getattr(args, "llvm_ir", None),
        metallib=getattr(args, "metallib", None),
        proto_descriptor=getattr(args, "proto_descriptor", None),
        compile_commands=getattr(args, "compile_commands", None),
        binary=getattr(args, "binary", None),
        otel_traces=getattr(args, "otel_traces", None),
        ebpf_flows=getattr(args, "ebpf_flows", None),
        memgraph=getattr(args, "memgraph", None),
        vmmap=getattr(args, "vmmap", None),
        port_listeners=getattr(args, "port_listeners", None),
        probe_local_ports="true" if getattr(args, "probe_local_ports", False) else None,
    )


def _validate_active_cli_artifact_plugins(
    *,
    allow_local_plugins: bool = False,
    local_plugin_modules: Sequence[str] | None = None,
) -> None:
    """Fail closed when explicit CLI artifact flags lack their required optional plugin."""
    active = get_active_stratum_artifacts()
    if not active:
        return

    specs = [
        s
        for s in discover_plugins(
            allow_local_plugins=allow_local_plugins,
            local_plugin_modules=local_plugin_modules,
            strict_plugins=True,
        )
        if s.enabled_by_default
    ]
    has_compiler_ir = any(
        s.name in ("compiler-ir", "wythe-plugin-compiler-ir")
        or (s.origin == "local_opt_in" and 2 in (s.supported_zooms or (2, 3)))
        for s in specs
    )
    has_solver_internals = any(
        s.name in ("solver-internals", "wythe-plugin-solver-internals")
        or "solver_internals" in s.companion_handlers
        for s in specs
    )
    has_binary = any(
        s.name in ("binary", "wythe-plugin-binary")
        or "binary" in s.companion_handlers
        or (s.origin == "local_opt_in" and 3 in (s.supported_zooms or (2, 3)))
        for s in specs
    )
    has_wiretap = any(
        s.name in ("wiretap", "wythe-plugin-wiretap")
        or "wiretap" in s.companion_handlers
        for s in specs
    )

    if any(k in active for k in ("sil", "llvm_ir", "metallib")) and not has_compiler_ir:
        raise RuntimeError(
            "Flags --sil / --llvm-ir / --metallib require optional plugin 'wythe-plugin-compiler-ir' "
            "(install 'wythe-plugin-compiler-ir' or pass --allow-local-plugins --plugin ...)."
        )
    if (
        any(k in active for k in ("proto_descriptor", "compile_commands"))
        and not has_solver_internals
    ):
        raise RuntimeError(
            "Flags --proto-descriptor / --compile-commands require optional plugin "
            "'wythe-plugin-solver-internals' (install 'wythe-plugin-solver-internals' or pass "
            "--allow-local-plugins --plugin ...)."
        )
    if "index_store" in active and not (has_compiler_ir or has_solver_internals):
        raise RuntimeError(
            "Flag --index-store requires optional plugin 'wythe-plugin-compiler-ir' or "
            "'wythe-plugin-solver-internals' (install one of those plugins or pass "
            "--allow-local-plugins --plugin ...)."
        )
    if "binary" in active and not has_binary:
        raise RuntimeError(
            "Flag --binary requires optional plugin 'wythe-plugin-binary' "
            "(install 'wythe-plugin-binary' or pass --allow-local-plugins --plugin ...)."
        )
    if (
        any(
            k in active
            for k in (
                "otel_traces",
                "ebpf_flows",
                "memgraph",
                "vmmap",
                "port_listeners",
                "probe_local_ports",
            )
        )
        and not has_wiretap
    ):
        raise RuntimeError(
            "Flags --otel-traces / --ebpf-flows / --memgraph / --vmmap / --port-listeners / "
            "--probe-local-ports require optional plugin 'wythe-plugin-wiretap' "
            "(install 'wythe-plugin-wiretap' or pass --allow-local-plugins --plugin ...)."
        )


def _build_combined_companion_summary(
    report,
    *,
    trivy_path: str | None = None,
    syft_path: str | None = None,
    cp_model_proto_path: str | None = None,
    cp_solver_response_path: str | None = None,
    binary_paths: Sequence[str] | str | None = None,
    proto_descriptor_path: Sequence[str] | str | None = None,
    compile_commands_path: Sequence[str] | str | None = None,
    otel_traces_path: Sequence[str] | str | None = None,
    ebpf_flows_path: Sequence[str] | str | None = None,
    memgraph_path: Sequence[str] | str | None = None,
    vmmap_path: Sequence[str] | str | None = None,
    port_listeners_path: Sequence[str] | str | None = None,
    probe_local_ports: bool = False,
    allow_local_plugins: bool = False,
    local_plugin_modules: list[str] | None = None,
) -> dict[str, object]:
    comp = summarize_companion_security_artifacts(
        report,
        trivy_path=trivy_path,
        syft_path=syft_path,
    )
    comp["content_digest"] = report.content_digest
    if isinstance(comp.get("blueprint_stage"), dict):
        comp["blueprint_stage"]["content_digest"] = report.content_digest  # type: ignore[index]

    norm_binaries = _normalize_artifact_tuple(binary_paths)
    norm_proto_desc = _normalize_artifact_tuple(proto_descriptor_path)
    norm_comp_cmds = _normalize_artifact_tuple(compile_commands_path)
    norm_otel = _normalize_artifact_tuple(otel_traces_path)
    norm_ebpf = _normalize_artifact_tuple(ebpf_flows_path)
    norm_memgraph = _normalize_artifact_tuple(memgraph_path)
    norm_vmmap = _normalize_artifact_tuple(vmmap_path)
    norm_port_listeners = _normalize_artifact_tuple(port_listeners_path)
    has_wiretap_req = bool(
        norm_otel
        or norm_ebpf
        or norm_memgraph
        or norm_vmmap
        or norm_port_listeners
        or probe_local_ports
    )
    repo_root = Path(report.repo_path).resolve()

    with stratum_artifacts_scope(
        binary=norm_binaries or None,
        proto_descriptor=norm_proto_desc or None,
        compile_commands=norm_comp_cmds or None,
        otel_traces=norm_otel or None,
        ebpf_flows=norm_ebpf or None,
        memgraph=norm_memgraph or None,
        vmmap=norm_vmmap or None,
        port_listeners=norm_port_listeners or None,
        probe_local_ports="true" if probe_local_ports else None,
    ):
        if cp_model_proto_path or cp_solver_response_path:
            plugin_out = run_plugin_companion_handlers(
                repo_root,
                report,
                handler_key="cpsat",
                cp_model_proto_path=cp_model_proto_path,
                cp_solver_response_path=cp_solver_response_path,
                allow_local_plugins=allow_local_plugins,
                local_plugin_modules=local_plugin_modules,
                strict_plugins=True,
            )
            if "cpsat" not in plugin_out:
                raise RuntimeError(
                    "Companion flags --cp-model-proto / --cp-solver-response require optional "
                    "plugin 'wythe-plugin-cpsat' (install 'wythe-plugin-cpsat' or pass "
                    "--allow-local-plugins --plugin ...)."
                )
            plugin_map = comp.setdefault("plugin_companions", {})
            if isinstance(plugin_map, dict):
                plugin_map.update(plugin_out)
            comp["cpsat_companion"] = plugin_out["cpsat"]

        if norm_binaries:
            bin_out = run_plugin_companion_handlers(
                repo_root,
                report,
                handler_key="binary",
                binary_paths=list(norm_binaries),
                allow_local_plugins=allow_local_plugins,
                local_plugin_modules=local_plugin_modules,
                strict_plugins=True,
            )
            if "binary" not in bin_out:
                raise RuntimeError(
                    "Companion flag --binary requires optional plugin 'wythe-plugin-binary' "
                    "(install 'wythe-plugin-binary' or pass --allow-local-plugins --plugin ...)."
                )
            plugin_map = comp.setdefault("plugin_companions", {})
            if isinstance(plugin_map, dict):
                plugin_map.update(bin_out)
            comp["binary_companion"] = bin_out["binary"]

        if norm_proto_desc or norm_comp_cmds:
            si_out = run_plugin_companion_handlers(
                repo_root,
                report,
                handler_key="solver_internals",
                proto_descriptor_paths=list(norm_proto_desc),
                compile_commands_paths=list(norm_comp_cmds),
                proto_descriptor=list(norm_proto_desc) or None,
                compile_commands=list(norm_comp_cmds) or None,
                allow_local_plugins=allow_local_plugins,
                local_plugin_modules=local_plugin_modules,
                strict_plugins=True,
            )
            if "solver_internals" not in si_out:
                raise RuntimeError(
                    "Companion flags --proto-descriptor / --compile-commands require optional "
                    "plugin 'wythe-plugin-solver-internals' (install 'wythe-plugin-solver-internals' "
                    "or pass --allow-local-plugins --plugin ...)."
                )
            plugin_map = comp.setdefault("plugin_companions", {})
            if isinstance(plugin_map, dict):
                plugin_map.update(si_out)
            comp["solver_internals_companion"] = si_out["solver_internals"]

        if has_wiretap_req:
            wt_out = run_plugin_companion_handlers(
                repo_root,
                report,
                handler_key="wiretap",
                otel_traces_path=list(norm_otel) or None,
                ebpf_flows_path=list(norm_ebpf) or None,
                memgraph_path=list(norm_memgraph) or None,
                vmmap_path=list(norm_vmmap) or None,
                port_listeners_path=list(norm_port_listeners) or None,
                probe_local_ports=bool(probe_local_ports),
                allow_local_plugins=allow_local_plugins,
                local_plugin_modules=local_plugin_modules,
                strict_plugins=True,
            )
            if "wiretap" not in wt_out:
                raise RuntimeError(
                    "Companion flags --otel-traces / --ebpf-flows / --memgraph / --vmmap / "
                    "--port-listeners / --probe-local-ports require optional plugin "
                    "'wythe-plugin-wiretap' (install 'wythe-plugin-wiretap' or pass "
                    "--allow-local-plugins --plugin ...)."
                )
            plugin_map = comp.setdefault("plugin_companions", {})
            if isinstance(plugin_map, dict):
                plugin_map.update(wt_out)
            comp["wiretap_companion"] = wt_out["wiretap"]

    comp["target_code_executed"] = False
    comp["automated_security_audit"] = False
    return comp


def _write_json_file(dest: str, payload_str: str) -> Path:
    out_p = Path(dest).expanduser().resolve()
    out_p.parent.mkdir(parents=True, exist_ok=True)
    out_p.write_text(payload_str + "\n", encoding="utf-8")
    return out_p


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(prog="wythe", description="Wythe — 3-Tier Architecture & Lineage Verifier")
    sub = parser.add_subparsers(dest="cmd", required=True)
    add_security_parser(sub)

    p_scan = sub.add_parser("scan", help="Scan a target slug or repository path")
    p_scan.add_argument("target", help="Registered target slug or filesystem path")
    p_scan.add_argument("--profile", default="auto", help="Stack profile slug or 'auto' (default)")
    p_scan.add_argument("--dsn", default=None, help="Optional read-only SQL DB DSN")
    p_scan.add_argument("--redis-dsn", default=None, help="Optional read-only Redis DSN (keyspace metadata only)")
    p_scan.add_argument("--strict", action="store_true", help="Ignore ratchet baselines")
    p_scan.add_argument("--json", dest="json_out", default=None, help="Write full JSON report to file")
    p_scan.add_argument("--sarif", dest="sarif_out", default=None, help="Write SARIF 2.1.0 report to file")
    p_scan.add_argument("--trivy-report", default=None, help="Optional read-only Trivy JSON/SARIF report")
    p_scan.add_argument("--syft-sbom", default=None, help="Optional read-only Syft CycloneDX/SPDX JSON SBOM")
    p_scan.add_argument("--cp-model-proto", default=None, help="Optional read-only CpModelProto companion file")
    p_scan.add_argument("--cp-solver-response", default=None, help="Optional read-only CpSolverResponse companion file")
    p_scan.add_argument(
        "--companion-out",
        default=None,
        help="Write combined blueprint + crate security handoff JSON (non-certifying)",
    )
    _add_probe_args(p_scan)
    _add_plugin_optin_args(p_scan)
    _add_stratum_artifact_args(p_scan)

    p_plugins = sub.add_parser(
        "plugins",
        help="List built-in and installed wythe.plugins entry points (never imports target repo code)",
    )
    p_plugins.add_argument("--json", dest="as_json", action="store_true", help="Emit JSON metadata")
    _add_plugin_optin_args(p_plugins)

    p_companion = sub.add_parser(
        "companion",
        help="Correlate static Z=0 blueprint with optional Z=1/Z=2 companion artifacts (Syft, Trivy, CpModelProto, CpSolverResponse)",
    )
    p_companion.add_argument("target", help="Registered target slug or filesystem path")
    p_companion.add_argument("--profile", default="auto", help="Stack profile slug or 'auto' (default)")
    p_companion.add_argument("--trivy-report", default=None, help="Optional read-only Trivy JSON or SARIF report")
    p_companion.add_argument("--syft-sbom", default=None, help="Optional read-only Syft CycloneDX/SPDX JSON SBOM")
    p_companion.add_argument("--cp-model-proto", default=None, help="Optional read-only CpModelProto (.pb/.pbtxt/JSON)")
    p_companion.add_argument("--cp-solver-response", default=None, help="Optional read-only CpSolverResponse (.pb/.pbtxt/JSON)")
    p_companion.add_argument("--json", "--out", dest="json_out", default=None, help="Write companion handoff JSON to file")
    _add_plugin_optin_args(p_companion)
    _add_stratum_artifact_args(p_companion)

    p_watch = sub.add_parser(
        "watch-solver",
        add_help=False,
        help="Live tail or replay solver logs into a 3-tier ChronicleFrame[] timeline (requires wythe-plugin-solver-chronicle)",
    )
    _add_plugin_optin_args(p_watch)

    p_ol = sub.add_parser(
        "export-openlineage",
        help="Export deterministic OpenLineage Static Lineage JSON (datasets + jobs)",
    )
    p_ol.add_argument("target", help="Registered target slug or filesystem path")
    p_ol.add_argument("--profile", default="auto", help="Stack profile slug or 'auto' (default)")
    p_ol.add_argument("--dsn", default=None, help="Optional read-only SQL DB DSN")
    p_ol.add_argument("--redis-dsn", default=None, help="Optional read-only Redis DSN")
    p_ol.add_argument("--out", default=None, help="Optional output file path (e.g. openlineage.json)")
    _add_plugin_optin_args(p_ol)

    p_gate = sub.add_parser("gate", help="Fail-closed 3-tier boundary check (exit 0 pass, 1 violation, 2 incomplete or error)")
    p_gate.add_argument("target", help="Registered target slug or filesystem path")
    p_gate.add_argument("--profile", default="auto", help="Stack profile slug or 'auto' (default)")
    p_gate.add_argument("--dsn", default=None, help="Optional read-only SQL DB DSN")
    p_gate.add_argument("--redis-dsn", default=None, help="Optional read-only Redis DSN")
    p_gate.add_argument("--strict", action="store_true", help="Require zero blocking violations (ignore ratchet)")
    p_gate.add_argument("--sync-config", action="store_true", help="Hydrate DB from .wythe/governance.json first")
    p_gate.add_argument("--sarif", dest="sarif_out", default=None, help="Write SARIF 2.1.0 report to file")
    _add_probe_args(p_gate)
    _add_plugin_optin_args(p_gate)
    _add_stratum_artifact_args(p_gate)

    p_diff = sub.add_parser("diff", help="PR diff gate & 3-tier blast-radius analyzer (exit 0 pass, 1 new blocking)")
    p_diff.add_argument("target", help="Registered target slug or filesystem path")
    p_diff.add_argument("--profile", default="auto", help="Stack profile slug or 'auto' (default)")
    p_diff.add_argument("--base", default="HEAD~1", help="Git base ref to diff against (or WORKING)")
    p_diff.add_argument("--dsn", default=None, help="Optional read-only SQL DB DSN")
    p_diff.add_argument("--redis-dsn", default=None, help="Optional read-only Redis DSN")
    p_diff.add_argument("--json", dest="json_out", default=None, help="Write DiffBlastRadiusReport JSON")
    p_diff.add_argument("--sarif", dest="sarif_out", default=None, help="Write diff-scoped SARIF 2.1.0 report")
    _add_probe_args(p_diff)
    _add_plugin_optin_args(p_diff)
    _add_stratum_artifact_args(p_diff)

    p_exp = sub.add_parser("export-config", help="Export DB governance into .wythe/governance.json")
    p_exp.add_argument("target", help="Registered target slug or filesystem path")
    p_exp.add_argument("--profile", default="auto")
    p_exp.add_argument("--out", default=None, help="Custom output bundle path")

    p_sync = sub.add_parser("sync-config", help="Hydrate DB governance from .wythe/governance.json")
    p_sync.add_argument("target", help="Registered target slug or filesystem path")
    p_sync.add_argument("--profile", default="auto")
    p_sync.add_argument("--in", dest="in_file", default=None, help="Custom input bundle path")

    p_openapi = sub.add_parser("export-openapi", help="Export deterministic OpenAPI JSON schema")
    p_openapi.add_argument("--out", required=True, help="Output file path")

    p_llms = sub.add_parser(
        "llms",
        help="Emit token-budgeted `llms.txt` 3-tier pointer map for LLMs/coding agents",
    )
    p_llms.add_argument("target", help="Registered target slug or filesystem path")
    p_llms.add_argument("--profile", default="auto")
    p_llms.add_argument("--max-tokens", type=int, default=DEFAULT_BRIEF_TOKENS)
    p_llms.add_argument("--out", default=None, help="Optional output file path (e.g. llms.txt)")
    _add_plugin_optin_args(p_llms)

    p_ctx = sub.add_parser(
        "context",
        help="Slice surgical 3-tier Lineage Cone around a table, file, route, queue, or node ID",
    )
    p_ctx.add_argument("target", help="Registered target slug or filesystem path")
    p_ctx.add_argument("query", help="Table name, file path, HTTP route, queue lane, or node ID")
    p_ctx.add_argument("--profile", default="auto")
    p_ctx.add_argument("--max-nodes", type=int, default=DEFAULT_CONE_NODES)
    p_ctx.add_argument(
        "--full",
        action="store_true",
        help="Disable cone node/edge/finding caps and emit the complete reachable slice",
    )
    p_ctx.add_argument(
        "--zoom",
        type=int,
        choices=(1, 2, 3),
        default=1,
        help="Progressive LOD stratum: 1 (3-wythe default), 2 (compiler IR / Metal AIR), or 3 (binary / heap)",
    )
    p_ctx.add_argument(
        "--unfiltered-ir",
        dest="unfiltered_ir",
        action="store_true",
        help="Disable stdlib/ARC/witness thunk compaction at --zoom 2 or 3",
    )
    p_ctx.add_argument("--json", dest="as_json", action="store_true", help="Emit JSON instead of Markdown")
    _add_plugin_optin_args(p_ctx)
    _add_stratum_artifact_args(p_ctx)

    p_mcp = sub.add_parser("mcp", help="Run read-only Model Context Protocol (MCP) server over stdio")
    p_mcp.add_argument(
        "--slice",
        dest="slice_mode",
        choices=("full", "slm"),
        default="full",
        help="MCP tool surface slice: 'full' (all 8 tools, default) or 'slm' (compact <=2KB 4-tool slice)",
    )
    p_mcp.add_argument(
        "--server-url",
        dest="server_url",
        default=None,
        help="Optional running Wythe HTTP server base URL (or set WYTHE_SERVER_URL) for viewport delivery",
    )
    p_mcp.add_argument(
        "--allow-remote-viewport",
        dest="allow_remote_viewport",
        action="store_true",
        help="Allow --server-url / WYTHE_SERVER_URL to target a non-loopback/non-private host",
    )

    p_focus = sub.add_parser(
        "focus",
        help="Read live 3D GUI focus X-Ray ('what is this?') without copy-pasting",
    )
    p_focus.add_argument("--target", default=None, help="Optional target slug override")
    p_focus.add_argument("--session-id", default=None, help="Optional browser/investigation session ID")
    p_focus.add_argument(
        "--remote",
        default=None,
        help="Optional remote Wythe base URL (e.g. http://100.64.0.10:8780 over private LAN/Tailnet)",
    )
    p_focus.add_argument("--json", dest="as_json", action="store_true", help="Emit JSON instead of Markdown")

    p_reply = sub.add_parser(
        "reply",
        help="Pipe frontier/terminal markdown directly into the live Ask Wythe pop-out drawer over SSE",
    )
    p_reply.add_argument(
        "--server",
        "--server-url",
        dest="server",
        default=None,
        help="Running Wythe server base URL (defaults to WYTHE_SERVER_URL or http://127.0.0.1:8780)",
    )
    p_reply.add_argument(
        "--allow-remote-viewport",
        dest="allow_remote_viewport",
        action="store_true",
        help="Allow --server to target a non-loopback/non-private host",
    )
    p_reply.add_argument("--target", default=None, help="Optional target slug (defaults to active UI focus)")
    p_reply.add_argument(
        "--session",
        "--session-id",
        dest="session",
        default=None,
        help="Optional shared investigation session ID (defaults to active UI focus session)",
    )
    p_reply.add_argument("--question", default="External frontier CLI analysis", help="Prompt/heading for the turn")
    p_reply.add_argument("--model", default="frontier-cli", help="Model badge recorded on the turn")
    p_reply.add_argument("--engine", default="frontier", help="Engine badge recorded on the turn")
    p_reply.add_argument("-m", "--message", default=None, help="Inline markdown message (defaults to stdin)")
    p_reply.add_argument("-f", "--file", default=None, help="Read markdown reply from file path")
    p_reply.add_argument(
        "--focus",
        action="append",
        default=None,
        help="Optional semantic Atlas node ID(s) to frame in 3D (repeatable or comma-separated)",
    )
    p_reply.add_argument(
        "--lens",
        choices=("status", "contention", "gravity", "subkind", "cluster", "containers"),
        default=None,
        help="Optional 3D lens to activate alongside the reply",
    )
    p_reply.add_argument(
        "--layout",
        "--layout-mode",
        dest="layout_mode",
        choices=("cluster", "grid", "subkind", "connected", "lifecycle_z", "temporal_z"),
        default=None,
        help="Optional 3D spatial layout mode",
    )
    p_reply.add_argument(
        "--tier",
        "--tier-filter",
        dest="tier_filter",
        choices=("all", "truth", "manipulate", "display"),
        default=None,
        help="Optional stratum tier filter",
    )
    p_reply.add_argument(
        "--only-flagged",
        "--flagged-only",
        dest="only_flagged",
        action="store_true",
        help="Enable Flagged-Only filter in the 3D viewport",
    )
    p_reply.add_argument(
        "--isolate-cone",
        dest="isolate_cone",
        action="store_true",
        help="Isolate the 3-tier lineage cone in the 3D viewport",
    )
    p_reply.add_argument(
        "--reset-filters",
        dest="reset_filters",
        action="store_true",
        help="Reset all 3D viewport filters to overview defaults",
    )

    p_und = sub.add_parser(
        "understand",
        help="Evaluate Six-Link Outcome, Authority, Provenance & Preservation Understanding Chain",
    )
    p_und.add_argument(
        "target_or_example",
        nargs="?",
        default=None,
        help="Example slug, understanding bundle .json path, target slug, or repository path",
    )
    p_und.add_argument("--list-examples", action="store_true", help="List shipped synthetic example investigations")
    p_und.add_argument("--example", dest="example_slug", default=None, help="Explicit shipped example slug")
    p_und.add_argument("--bundle", dest="bundle_path", default=None, help="Optional understanding bundle .json file")
    p_und.add_argument("--session-id", default=None, help="Optional shared investigation session ID")
    p_und.add_argument("--subject-id", default=None, help="Optional subject / node / finding / edge ID")
    p_und.add_argument("--question", default=None, help="Optional concrete investigation question")
    p_und.add_argument("--observed-at", default=None, help="Optional ISO-8601 evaluation timestamp")
    p_und.add_argument("--prior-revision", default=None, help="Optional prior explanation evidence revision")
    p_und.add_argument("--profile", default="auto", help="Stack profile slug when scanning a repo path")
    p_und.add_argument("--json", dest="as_json", action="store_true", help="Emit JSON instead of Markdown")
    p_und.add_argument("--out", dest="json_out", default=None, help="Write JSON output to file")

    p_serve = sub.add_parser(
        "serve",
        help="Run loopback Wythe API & bundled 3D WebGL UI server",
    )
    p_serve.add_argument(
        "target",
        nargs="?",
        default=None,
        help="Optional repository path or slug to auto-register on startup",
    )
    p_serve.add_argument(
        "--profile",
        default="auto",
        help="Stack profile slug when auto-registering target (default: auto)",
    )
    p_serve.add_argument("--host", default=None)
    p_serve.add_argument("--port", type=int, default=None)

    raw_argv = list(sys.argv[1:] if argv is None else argv)
    if raw_argv and raw_argv[0] == "watch-solver":
        watch_ns, forward_args = p_watch.parse_known_args(raw_argv[1:])
        try:
            rc = dispatch_plugin_cli_subcommand(
                "watch-solver",
                forward_args,
                allow_local_plugins=bool(watch_ns.allow_local_plugins),
                local_plugin_modules=watch_ns.local_plugins,
                strict_plugins=True,
            )
        except Exception as exc:  # noqa: BLE001
            print(f"wythe watch-solver error: {exc}", file=sys.stderr)
            return 2
        if rc is None:
            print(
                "wythe watch-solver: optional plugin 'wythe-plugin-solver-chronicle' is not "
                "installed. Install 'wythe-plugin-solver-chronicle' (or pass "
                "--allow-local-plugins --plugin ...) to watch or replay solver chronicles.",
                file=sys.stderr,
            )
            return 2
        return rc

    args = parser.parse_args(argv)

    if args.cmd == "security":
        return run_security_command(args)

    if args.cmd == "plugins":
        try:
            items = list_registered_plugins(
                allow_local_plugins=bool(args.allow_local_plugins),
                local_plugin_modules=args.local_plugins,
            )
        except Exception as exc:  # noqa: BLE001
            print(f"wythe plugins error: {exc}", file=sys.stderr)
            return 2
        if args.as_json:
            print(
                json.dumps(
                    {
                        "entry_point_group": ENTRY_POINT_GROUP,
                        "allow_local_plugins": bool(args.allow_local_plugins),
                        "count": len(items),
                        "plugins": items,
                    },
                    indent=2,
                )
            )
            return 0
        print(f"Wythe Registered Plugins (group={ENTRY_POINT_GROUP}, count={len(items)})")
        for item in items:
            default_state = "on" if item.get("enabled_by_default") else "off"
            zooms = item.get("supported_zooms")
            stratum_tag = (
                f", StratumPlugin zooms={','.join(str(z) for z in zooms)}"
                if item.get("kind") == "stratum_inspector" and isinstance(zooms, list) and zooms
                else (", StratumPlugin" if item.get("kind") == "stratum_inspector" else "")
            )
            print(
                f"  - {item['name']} [{item['origin']}, {item['kind']}{stratum_tag}, "
                f"v{item['version']}, default={default_state}] :: {item['description']}"
            )
        return 0

    if args.cmd == "export-openapi":
        application = create_app()
        out_p = _write_json_file(args.out, json.dumps(application.openapi(), indent=2))
        print(f"Wrote OpenAPI schema to {out_p}")
        return 0

    if args.cmd == "mcp":
        return run_mcp_stdio_server(
            slice_mode=args.slice_mode,
            server_url=args.server_url,
            allow_remote_viewport=bool(args.allow_remote_viewport),
        )

    if args.cmd == "reply":
        try:
            return _run_reply_cli(args)
        except Exception as exc:  # noqa: BLE001
            print(f"wythe reply error: {exc}", file=sys.stderr)
            return 2

    if args.cmd == "focus":
        if args.remote:
            base = args.remote.strip().rstrip("/")
            if not base.endswith("/api/v1"):
                base = f"{base}/api/v1"
            q_parts: list[str] = []
            if args.target:
                q_parts.append(f"target={urllib.parse.quote(args.target)}")
            if args.session_id:
                q_parts.append(f"session_id={urllib.parse.quote(args.session_id)}")
            qs = f"?{'&'.join(q_parts)}" if q_parts else ""
            opener = urllib.request.build_opener(urllib.request.ProxyHandler({}))
            with opener.open(f"{base}/ui-focus{qs}", timeout=10.0) as resp:
                raw_json = resp.read().decode("utf-8", errors="replace")
            parsed = json.loads(raw_json)
            if args.as_json:
                print(json.dumps(parsed, indent=2))
            else:
                print(str(parsed.get("markdown_brief") or ""))
            return 0
        initialize_database()
        factory = get_session_factory()
        with factory() as session:
            explain = explain_ui_focus(
                session,
                target_override=args.target,
                session_id=args.session_id,
            )
            if args.as_json:
                print(explain.model_dump_json(indent=2))
            else:
                print(explain.markdown_brief)
        return 0

    if args.cmd == "understand":
        from app.services.understanding_service import (
            UnderstandingAnalyzeRequest,
            analyze_understanding_bundle,
            list_understanding_examples,
        )

        try:
            examples = list_understanding_examples()
            example_slugs = {e.slug for e in examples}
            if args.list_examples:
                if args.as_json:
                    print(json.dumps([e.model_dump(mode="json") for e in examples], indent=2))
                else:
                    print(f"Wythe Understanding Examples (count={len(examples)})")
                    for ex in examples:
                        print(f"  - {ex.slug} :: {ex.title} — {ex.question}")
                return 0

            initialize_database()
            factory = get_session_factory()
            with factory() as session:
                raw_pos = (args.target_or_example or "").strip()
                ex_slug = args.example_slug
                b_path = args.bundle_path
                t_slug: str | None = None
                if raw_pos:
                    if not ex_slug and raw_pos in example_slugs:
                        ex_slug = raw_pos
                    elif not b_path and raw_pos.lower().endswith(".json") and Path(raw_pos).expanduser().is_file():
                        b_path = raw_pos
                    elif Path(raw_pos).expanduser().is_dir():
                        resolved_t, _ = _resolve_cli_target(
                            session, raw_pos, args.profile, ensure_persisted=True
                        )
                        t_slug = resolved_t.slug
                    else:
                        t_slug = raw_pos

                req = UnderstandingAnalyzeRequest(
                    target_slug=t_slug,
                    example_slug=ex_slug,
                    session_id=args.session_id,
                    subject_id=args.subject_id,
                    question=args.question,
                    observed_at=args.observed_at,
                    prior_explanation_revision=args.prior_revision,
                    bundle_path=b_path,
                )
                chain = analyze_understanding_bundle(req, db=session)
                json_text = chain.model_dump_json(indent=2)
                if args.json_out:
                    _write_json_file(args.json_out, json_text)
                if args.as_json:
                    print(json_text)
                else:
                    print(f"# Wythe Understanding Chain :: {chain.example_slug or chain.target_slug or 'bundle'}")
                    print(f"> Question: {chain.question}")
                    print(f"> Headline: {chain.consequence_headline}")
                    print(f"> Last Supported Cause: {chain.last_supported_cause}")
                    for lk in chain.links:
                        print(f"  [{lk.link_key}] ({lk.state}) :: {lk.consequence_summary}")
                    if chain.overall_missing_joins:
                        print(f"  Missing Joins: {', '.join(chain.overall_missing_joins)}")
                    print(f"  Coverage: {chain.coverage_statement}")
                return 0
        except Exception as exc:  # noqa: BLE001
            print(f"wythe understand error: {exc}", file=sys.stderr)
            return 2

    if args.cmd == "serve":
        settings = load_settings()
        initialize_database()
        serve_target = args.target or ("." if (Path.cwd() / ".git").exists() else None)
        if serve_target:
            factory = get_session_factory()
            with factory() as session:
                resolved_target, _ = _resolve_cli_target(
                    session, serve_target, args.profile, ensure_persisted=True
                )
                cfg_file = resolve_existing_bundle_path(Path(resolved_target.repo_path).resolve())
                if cfg_file.is_file():
                    sync_portable_bundle_from_disk(session, resolved_target, in_path=cfg_file)
                print(
                    f"Registered target '{resolved_target.slug}' "
                    f"({resolved_target.stack_profile_slug}) -> {resolved_target.repo_path}"
                )
        bind_host = args.host or settings.api_host
        bind_port = args.port or settings.api_port
        print(f"Wythe serving on http://{bind_host}:{bind_port}")
        uvicorn.run(
            "app.main:app",
            host=bind_host,
            port=bind_port,
            reload=False,
        )
        return 0

    try:
        initialize_database()
        factory = get_session_factory()
        allow_local = bool(getattr(args, "allow_local_plugins", False))
        local_mods = getattr(args, "local_plugins", None)
        with factory() as session, _artifact_scope_from_args(args):
            _validate_active_cli_artifact_plugins(
                allow_local_plugins=allow_local,
                local_plugin_modules=local_mods,
            )
            need_persist = args.cmd == "sync-config" or getattr(args, "sync_config", False)
            target, is_persisted = _resolve_cli_target(
                session,
                args.target,
                args.profile,
                ensure_persisted=need_persist,
                allow_local_plugins=allow_local,
                local_plugin_modules=local_mods,
            )

            if args.cmd == "export-config":
                out_custom = Path(args.out).expanduser() if args.out else None
                receipt = export_portable_bundle_to_disk(session, target, out_path=out_custom)
                print(
                    f"Exported governance bundle -> {receipt.bundle_path} "
                    f"(rules={receipt.rules_synced}, vocabs={receipt.vocabularies_synced}, "
                    f"baselines={receipt.baselines_synced}, rulings={receipt.rulings_synced})"
                )
                return 0

            if args.cmd == "sync-config":
                in_custom = Path(args.in_file).expanduser() if args.in_file else None
                receipt = sync_portable_bundle_from_disk(session, target, in_path=in_custom)
                print(
                    f"Synced governance bundle <- {receipt.bundle_path} "
                    f"(rules={receipt.rules_synced}, vocabs={receipt.vocabularies_synced}, "
                    f"baselines={receipt.baselines_synced}, rulings={receipt.rulings_synced})"
                )
                return 0

            if args.cmd == "export-openlineage":
                rep = run_target_scan(
                    session,
                    target,
                    pg_dsn=args.dsn,
                    redis_dsn=args.redis_dsn,
                    strict_gate=True,
                    persist_snapshot=False,
                    allow_local_plugins=allow_local,
                    local_plugin_modules=local_mods,
                )
                bundle = build_openlineage_static_bundle(rep)
                payload = json.dumps(bundle, indent=2)
                if args.out:
                    out_p = _write_json_file(args.out, payload)
                    ds_n = len(bundle.get("datasets") or [])  # type: ignore[arg-type]
                    job_n = len(bundle.get("jobs") or [])  # type: ignore[arg-type]
                    print(
                        f"Wrote OpenLineage static lineage bundle "
                        f"(datasets={ds_n}, jobs={job_n}) -> {out_p}"
                    )
                else:
                    print(payload)
                return 0

            if args.cmd == "llms":
                rep = run_target_scan(
                    session,
                    target,
                    strict_gate=True,
                    persist_snapshot=False,
                    allow_local_plugins=allow_local,
                    local_plugin_modules=local_mods,
                )
                brief = build_llms_txt_brief(rep, max_tokens=args.max_tokens)
                if args.out:
                    out_p = _write_json_file(args.out, brief.markdown)
                    print(f"Wrote llms.txt brief (~{brief.approx_tokens} tokens) -> {out_p}")
                else:
                    print(brief.markdown)
                return 0

            if args.cmd == "companion":
                rep = run_target_scan(
                    session,
                    target,
                    strict_gate=True,
                    persist_snapshot=False,
                    allow_local_plugins=allow_local,
                    local_plugin_modules=local_mods,
                )
                comp = _build_combined_companion_summary(
                    rep,
                    trivy_path=args.trivy_report,
                    syft_path=args.syft_sbom,
                    cp_model_proto_path=args.cp_model_proto,
                    cp_solver_response_path=args.cp_solver_response,
                    binary_paths=args.binary,
                    proto_descriptor_path=args.proto_descriptor,
                    compile_commands_path=args.compile_commands,
                    otel_traces_path=args.otel_traces,
                    ebpf_flows_path=args.ebpf_flows,
                    memgraph_path=args.memgraph,
                    vmmap_path=args.vmmap,
                    port_listeners_path=args.port_listeners,
                    probe_local_ports=bool(args.probe_local_ports),
                    allow_local_plugins=allow_local,
                    local_plugin_modules=local_mods,
                )
                payload = json.dumps(comp, indent=2)
                if args.json_out:
                    _write_json_file(args.json_out, payload)
                print(payload)
                return 0

            if args.cmd == "context":
                rep = run_target_scan(
                    session,
                    target,
                    strict_gate=True,
                    persist_snapshot=False,
                    allow_local_plugins=allow_local,
                    local_plugin_modules=local_mods,
                )
                cone = build_lineage_cone_slice(
                    rep,
                    args.query,
                    max_nodes=args.max_nodes,
                    full=bool(getattr(args, "full", False)),
                    zoom=args.zoom,
                    unfiltered_ir=bool(getattr(args, "unfiltered_ir", False)),
                    allow_local_plugins=allow_local,
                    local_plugin_modules=local_mods,
                )
                if args.as_json:
                    print(cone.model_dump_json(indent=2))
                else:
                    print(cone.markdown)
                return 0 if cone.matched_seed_ids else 1

            if getattr(args, "sync_config", False):
                cfg_file = resolve_existing_bundle_path(Path(target.repo_path).resolve())
                if cfg_file.is_file():
                    sync_portable_bundle_from_disk(session, target, in_path=cfg_file)

            if args.cmd == "diff":
                report = run_target_scan(
                    session,
                    target,
                    pg_dsn=args.dsn,
                    redis_dsn=args.redis_dsn,
                    strict_gate=True,
                    persist_snapshot=False,
                    probe_url=args.probe_url,
                    probe_allow_remote=args.probe_allow_remote,
                    allow_local_plugins=allow_local,
                    local_plugin_modules=local_mods,
                )
                diff_rep = run_target_diff(session, target, report, args.base)
                print(
                    f"Wythe Diff :: {diff_rep.target_slug} (base={diff_rep.base_ref} -> {_commit_label(report)})"
                )
                print(
                    f"  Changed Files  : {len(diff_rep.changed_files)} | Touched Nodes: {len(diff_rep.touched_node_ids)} | Commits: {len(diff_rep.commits_in_range)}"
                )
                print(
                    f"  Blast Radius   : {len(diff_rep.impacted_truth_nodes)} truth, "
                    f"{len(diff_rep.impacted_manipulator_nodes)} manipulate, "
                    f"{len(diff_rep.impacted_display_nodes)} display, "
                    f"{len(diff_rep.impacted_chains)} E2E chain(s)"
                )
                print(
                    f"  Diff Verdict   : {diff_rep.diff_verdict} "
                    f"(new findings={len(diff_rep.new_findings)}, blocking={diff_rep.blocking_new_findings})"
                )
                print(f"  Base Graph     : {diff_rep.base_graph_status} ({diff_rep.base_commit[:12]})")
                for note in diff_rep.analysis_notes:
                    print(f"  Note           : {note}")
                if args.json_out:
                    _write_json_file(args.json_out, diff_rep.model_dump_json(indent=2))
                if args.sarif_out:
                    sarif = build_sarif_log(report, findings_override=diff_rep.new_findings, diff=diff_rep)
                    _write_json_file(args.sarif_out, json.dumps(sarif, indent=2))
                return {"PASS": 0, "FAIL": 1, "INCOMPLETE": 2}[diff_rep.diff_verdict]

            report = run_target_scan(
                session,
                target,
                pg_dsn=args.dsn,
                redis_dsn=args.redis_dsn,
                strict_gate=args.strict,
                persist_snapshot=is_persisted,
                probe_url=args.probe_url,
                probe_allow_remote=args.probe_allow_remote,
                allow_local_plugins=allow_local,
                local_plugin_modules=local_mods,
            )
            _print_report_summary(report)
            if args.cmd == "scan" and args.json_out:
                out_p = _write_json_file(args.json_out, report.model_dump_json(indent=2))
                print(f"  JSON written             : {out_p}")
            if args.cmd == "scan" and (
                args.trivy_report
                or args.syft_sbom
                or args.cp_model_proto
                or args.cp_solver_response
                or args.binary
                or args.proto_descriptor
                or args.compile_commands
                or args.otel_traces
                or args.ebpf_flows
                or args.memgraph
                or args.vmmap
                or args.port_listeners
                or args.probe_local_ports
                or args.companion_out
            ):
                comp = _build_combined_companion_summary(
                    report,
                    trivy_path=args.trivy_report,
                    syft_path=args.syft_sbom,
                    cp_model_proto_path=args.cp_model_proto,
                    cp_solver_response_path=args.cp_solver_response,
                    binary_paths=args.binary,
                    proto_descriptor_path=args.proto_descriptor,
                    compile_commands_path=args.compile_commands,
                    otel_traces_path=args.otel_traces,
                    ebpf_flows_path=args.ebpf_flows,
                    memgraph_path=args.memgraph,
                    vmmap_path=args.vmmap,
                    port_listeners_path=args.port_listeners,
                    probe_local_ports=bool(args.probe_local_ports),
                    allow_local_plugins=allow_local,
                    local_plugin_modules=local_mods,
                )
                crate = comp["crate_stage"]  # type: ignore[index]
                syft_s = crate["syft_sbom"]  # type: ignore[index]
                trivy_s = crate["trivy_report"]  # type: ignore[index]
                print(
                    f"  Companion Crate Summary  : Syft packages={syft_s['package_count']}, "
                    f"Trivy vulns={trivy_s['vulnerability_count']}, "
                    f"misconfigs={trivy_s['misconfiguration_count']}, "
                    f"secrets={trivy_s['secret_count']}"
                )
                print(f"  Companion Disclaimer     : {comp['non_certification_disclaimer']}")
                if args.companion_out:
                    out_c = _write_json_file(args.companion_out, json.dumps(comp, indent=2))
                    print(f"  Companion JSON written   : {out_c}")
            if getattr(args, "sarif_out", None):
                sarif = build_sarif_log(report)
                out_s = _write_json_file(args.sarif_out, json.dumps(sarif, indent=2))
                print(f"  SARIF written            : {out_s}")
            if args.cmd == "gate":
                return {"PASS": 0, "RATCHET_PASS": 0, "FAIL": 1, "INCOMPLETE": 2}[
                    report.gate.verdict
                ]
            return 0
    except Exception as exc:  # noqa: BLE001 - fail-closed CLI operational exit code 2
        print(f"wythe error: {exc}", file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
