"""Wythe CLI: scan, fail-closed gate, PR diff/blast-radius, SARIF, portable sync, & server."""

from __future__ import annotations

import argparse
import json
import re
import sys
import urllib.parse
import urllib.request
from pathlib import Path

import uvicorn

from app.adapters.autodetect import detect_repository_stack
from app.core.config import load_settings
from app.db.session import get_session_factory
from app.main import create_app, initialize_database
from app.models import TargetProject
from app.schemas.atlas import TargetProjectCreate
from app.services.diff_and_sarif_service import (
    build_sarif_log,
    compute_diff_and_blast_radius,
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


def _resolve_cli_target(
    session,
    target_or_path: str,
    profile: str,
    *,
    ensure_persisted: bool = False,
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

    detected = detect_repository_stack(session, str(candidate))
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
            "  Maturity: Experimental polyglot profile — prefer 'wythe diff' or ratchets over '--strict' until tuned for your repo."
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
        f"  Lineage                  : {s.verified_edges} verified edges, {s.end_to_end_chains} end-to-end 3-tier chains"
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


def _write_json_file(dest: str, payload_str: str) -> Path:
    out_p = Path(dest).expanduser().resolve()
    out_p.parent.mkdir(parents=True, exist_ok=True)
    out_p.write_text(payload_str + "\n", encoding="utf-8")
    return out_p


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(prog="wythe", description="Wythe — 3-Tier Architecture & Lineage Verifier")
    sub = parser.add_subparsers(dest="cmd", required=True)

    p_scan = sub.add_parser("scan", help="Scan a target slug or repository path")
    p_scan.add_argument("target", help="Registered target slug or filesystem path")
    p_scan.add_argument("--profile", default="auto", help="Stack profile slug or 'auto' (default)")
    p_scan.add_argument("--dsn", default=None, help="Optional read-only SQL DB DSN")
    p_scan.add_argument("--redis-dsn", default=None, help="Optional read-only Redis DSN (keyspace metadata only)")
    p_scan.add_argument("--strict", action="store_true", help="Ignore ratchet baselines")
    p_scan.add_argument("--json", dest="json_out", default=None, help="Write full JSON report to file")
    p_scan.add_argument("--sarif", dest="sarif_out", default=None, help="Write SARIF 2.1.0 report to file")
    _add_probe_args(p_scan)

    p_gate = sub.add_parser("gate", help="Fail-closed 3-tier boundary check (exit 0 pass, 1 violation, 2 error)")
    p_gate.add_argument("target", help="Registered target slug or filesystem path")
    p_gate.add_argument("--profile", default="auto", help="Stack profile slug or 'auto' (default)")
    p_gate.add_argument("--dsn", default=None, help="Optional read-only SQL DB DSN")
    p_gate.add_argument("--redis-dsn", default=None, help="Optional read-only Redis DSN")
    p_gate.add_argument("--strict", action="store_true", help="Require zero blocking violations (ignore ratchet)")
    p_gate.add_argument("--sync-config", action="store_true", help="Hydrate DB from .wythe/governance.json first")
    p_gate.add_argument("--sarif", dest="sarif_out", default=None, help="Write SARIF 2.1.0 report to file")
    _add_probe_args(p_gate)

    p_diff = sub.add_parser("diff", help="PR diff gate & 3-tier blast-radius analyzer (exit 0 pass, 1 new blocking)")
    p_diff.add_argument("target", help="Registered target slug or filesystem path")
    p_diff.add_argument("--profile", default="auto", help="Stack profile slug or 'auto' (default)")
    p_diff.add_argument("--base", default="HEAD~1", help="Git base ref to diff against (or WORKING)")
    p_diff.add_argument("--dsn", default=None, help="Optional read-only SQL DB DSN")
    p_diff.add_argument("--redis-dsn", default=None, help="Optional read-only Redis DSN")
    p_diff.add_argument("--json", dest="json_out", default=None, help="Write DiffBlastRadiusReport JSON")
    p_diff.add_argument("--sarif", dest="sarif_out", default=None, help="Write diff-scoped SARIF 2.1.0 report")
    _add_probe_args(p_diff)

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

    p_ctx = sub.add_parser(
        "context",
        help="Slice surgical 3-tier Lineage Cone around a table, file, route, queue, or node ID",
    )
    p_ctx.add_argument("target", help="Registered target slug or filesystem path")
    p_ctx.add_argument("query", help="Table name, file path, HTTP route, queue lane, or node ID")
    p_ctx.add_argument("--profile", default="auto")
    p_ctx.add_argument("--max-nodes", type=int, default=DEFAULT_CONE_NODES)
    p_ctx.add_argument("--json", dest="as_json", action="store_true", help="Emit JSON instead of Markdown")

    sub.add_parser("mcp", help="Run read-only Model Context Protocol (MCP) server over stdio")

    p_focus = sub.add_parser(
        "focus",
        help="Read live 3D GUI focus X-Ray ('what is this?') without copy-pasting",
    )
    p_focus.add_argument("--target", default=None, help="Optional target slug override")
    p_focus.add_argument(
        "--remote",
        default=None,
        help="Optional remote Wythe base URL (e.g. http://100.64.0.10:8780 over private LAN/Tailnet)",
    )
    p_focus.add_argument("--json", dest="as_json", action="store_true", help="Emit JSON instead of Markdown")

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

    args = parser.parse_args(argv)

    if args.cmd == "export-openapi":
        application = create_app()
        out_p = _write_json_file(args.out, json.dumps(application.openapi(), indent=2))
        print(f"Wrote OpenAPI schema to {out_p}")
        return 0

    if args.cmd == "mcp":
        return run_mcp_stdio_server()

    if args.cmd == "focus":
        if args.remote:
            base = args.remote.strip().rstrip("/")
            if not base.endswith("/api/v1"):
                base = f"{base}/api/v1"
            qs = f"?target={urllib.parse.quote(args.target)}" if args.target else ""
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
            explain = explain_ui_focus(session, target_override=args.target)
            if args.as_json:
                print(explain.model_dump_json(indent=2))
            else:
                print(explain.markdown_brief)
        return 0

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
        with factory() as session:
            need_persist = args.cmd == "sync-config" or getattr(args, "sync_config", False)
            target, is_persisted = _resolve_cli_target(
                session, args.target, args.profile, ensure_persisted=need_persist
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

            if args.cmd == "llms":
                rep = run_target_scan(session, target, strict_gate=True, persist_snapshot=False)
                brief = build_llms_txt_brief(rep, max_tokens=args.max_tokens)
                if args.out:
                    out_p = _write_json_file(args.out, brief.markdown)
                    print(f"Wrote llms.txt brief (~{brief.approx_tokens} tokens) -> {out_p}")
                else:
                    print(brief.markdown)
                return 0

            if args.cmd == "context":
                rep = run_target_scan(session, target, strict_gate=True, persist_snapshot=False)
                cone = build_lineage_cone_slice(rep, args.query, max_nodes=args.max_nodes)
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
                )
                diff_rep = compute_diff_and_blast_radius(
                    Path(target.repo_path).resolve(), report, base_ref=args.base
                )
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
                if args.json_out:
                    _write_json_file(args.json_out, diff_rep.model_dump_json(indent=2))
                if args.sarif_out:
                    sarif = build_sarif_log(report, findings_override=diff_rep.new_findings)
                    _write_json_file(args.sarif_out, json.dumps(sarif, indent=2))
                return 0 if diff_rep.diff_verdict == "PASS" else 1

            report = run_target_scan(
                session,
                target,
                pg_dsn=args.dsn,
                redis_dsn=args.redis_dsn,
                strict_gate=args.strict,
                persist_snapshot=is_persisted,
                probe_url=args.probe_url,
                probe_allow_remote=args.probe_allow_remote,
            )
            _print_report_summary(report)
            if args.cmd == "scan" and args.json_out:
                out_p = _write_json_file(args.json_out, report.model_dump_json(indent=2))
                print(f"  JSON written             : {out_p}")
            if getattr(args, "sarif_out", None):
                sarif = build_sarif_log(report)
                out_s = _write_json_file(args.sarif_out, json.dumps(sarif, indent=2))
                print(f"  SARIF written            : {out_s}")
            if args.cmd == "gate":
                return 0 if report.gate.verdict in ("PASS", "RATCHET_PASS") else 1
            return 0
    except Exception as exc:  # noqa: BLE001 - fail-closed CLI operational exit code 2
        print(f"wythe error: {exc}", file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
