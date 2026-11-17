"""Passive `wythe watch-solver` CLI subcommand and standalone entrypoint.

Strictly read-only: tails or replays user-provided solver logs and companion
artifacts through `IncrementalSolverLogParser` without executing target code.
"""

from __future__ import annotations

import argparse
import json
import sys
import time
from pathlib import Path
from typing import Any

from app.db.session import get_session_factory
from app.main import initialize_database
from app.schemas.atlas import validate_semantic_atlas_id
from app.services.mcp_service import _resolve_target_for_mcp
from app.services.scanner_service import run_target_scan
from wythe_plugin_solver_chronicle.forensics import inspect_repo_solver_ast
from wythe_plugin_solver_chronicle.log_parser import (
    CpModelProtoSummary,
    CpSolverResponseSummary,
    IncrementalSolverLogParser,
    ParsedSolverSession,
    parse_cp_model_proto_file,
    parse_cp_solver_response_file,
    read_safe_companion_text,
    resolve_safe_companion_path,
)
from wythe_plugin_solver_chronicle.synthesizer import (
    ChronicleSynthesisResult,
    build_chronicle_permalink,
    build_chronicle_viewport_command,
    default_timeline_id,
    publish_chronicle_to_viewport,
    serialize_chronicle_payload,
    synthesize_solver_chronicle,
)

_LIVE_PUBLISH_MIN_INTERVAL_SEC = 0.05
_LIVE_TAIL_POLL_SEC = 0.025


def _build_arg_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog="wythe watch-solver",
        description="Passive 6-phase 3-tier solver log watcher and forensic replayer.",
    )
    p.add_argument("target_pos", nargs="?", default=None, help="Optional target slug or path")
    p.add_argument("--target", dest="target_opt", default=None, help="Target slug or repo path")
    p.add_argument("--profile", default="auto", help="Stack profile slug or 'auto'")
    p.add_argument("--log", dest="log_path", default=None, help="CP-SAT solve_log file path")
    p.add_argument("--stdin", action="store_true", help="Read solver log lines from stdin")
    mode = p.add_mutually_exclusive_group()
    mode.add_argument("--follow", action="store_true", help="Follow live log stream until halt/done")
    mode.add_argument("--once", action="store_true", help="Single-pass offline replay (default)")
    p.add_argument("--cp-model-proto", default=None, help="Read-only CpModelProto JSON/.pbtxt path")
    p.add_argument("--cp-solver-response", default=None, help="Read-only CpSolverResponse path")
    p.add_argument("--telemetry-jsonl", default=None, help="Read-only telemetry JSONL path")
    p.add_argument("--timeline-id", default=None, help="Explicit chronicle timeline identifier")
    p.add_argument("--phase-index", type=int, default=None, help="Explicit phase index (0..5)")
    p.add_argument("--session-id", default=None, help="Optional viewport browser session ID")
    p.add_argument("--follow-timeout", type=float, default=0.25, help="Idle tail bound in seconds")
    p.add_argument(
        "--max-follow-seconds",
        type=float,
        default=None,
        help="Optional overall wall-clock bound in seconds for --follow (default: unlimited while active)",
    )
    p.add_argument("--json", dest="as_json", action="store_true", help="Emit JSON output")
    p.add_argument("--publish-viewport", action="store_true", help="Publish to loopback viewport bus")
    p.add_argument(
        "--server-url",
        default=None,
        help="Optional running Wythe HTTP server base URL (or set WYTHE_SERVER_URL)",
    )
    p.add_argument(
        "--allow-remote-viewport",
        action="store_true",
        help="Allow --server-url / WYTHE_SERVER_URL to target a non-loopback/non-private host",
    )
    return p


def run_watch_solver_cli(argv: list[str]) -> int:
    """Execute `wythe watch-solver` CLI workflow; returns 0 on success, 2 on error."""
    parser = _build_arg_parser()
    try:
        ns = parser.parse_args(argv)
    except SystemExit as exc:
        return int(exc.code) if isinstance(exc.code, int) else 2

    raw_target = ns.target_opt or ns.target_pos
    if ns.stdin and ns.log_path:
        print("Error: Specify at most one of `--log` or `--stdin`.", file=sys.stderr)
        return 2

    try:
        initialize_database()
        factory = get_session_factory()
        with factory() as db_session:
            target = _resolve_target_for_mcp(db_session, raw_target, profile=ns.profile)
            repo_root = Path(target.repo_path).resolve()
            report = run_target_scan(db_session, target, strict_gate=True, persist_snapshot=False)

        ast_profile = inspect_repo_solver_ast(repo_root, report)
        raw_tl = (ns.timeline_id or "").strip() or default_timeline_id(report.target_slug, None)
        session_timeline_id = validate_semantic_atlas_id(raw_tl[:64], field_name="timeline_id")

        proto: CpModelProtoSummary | None = None
        if ns.cp_model_proto:
            proto = parse_cp_model_proto_file(ns.cp_model_proto, repo_root=repo_root)

        resp: CpSolverResponseSummary | None = None
        if ns.cp_solver_response:
            resp = parse_cp_solver_response_file(ns.cp_solver_response, repo_root=repo_root)

        inc_parser = IncrementalSolverLogParser()
        if resp is not None:
            inc_parser.apply_response_summary(resp)

        if ns.telemetry_jsonl:
            tel_text = read_safe_companion_text(ns.telemetry_jsonl, repo_root=repo_root)
            for tline in tel_text.splitlines():
                inc_parser.feed_telemetry_jsonl_line(tline)

        def _synthesize_and_deliver(
            snap_in: ParsedSolverSession | None,
        ) -> tuple[ChronicleSynthesisResult, int | None, str]:
            syn = synthesize_solver_chronicle(
                repo_root,
                report,
                session=snap_in,
                proto=proto,
                response=resp,
                timeline_id=session_timeline_id,
                phase_index=ns.phase_index,
                ast_profile=ast_profile,
            )
            if ns.publish_viewport:
                ack, plink = publish_chronicle_to_viewport(
                    syn,
                    session_id=ns.session_id,
                    server_url=ns.server_url,
                    allow_remote=bool(ns.allow_remote_viewport),
                )
                return syn, ack.seq, plink
            cmd = build_chronicle_viewport_command(syn, session_id=ns.session_id)
            plink = build_chronicle_permalink(
                cmd,
                timeline_id=syn.timeline_id,
                phase_index=syn.active_phase_index,
            )
            return syn, None, plink

        synthesis: ChronicleSynthesisResult | None = None
        vp_seq: int | None = None
        permalink = ""
        last_pub_state: tuple[int, int, str | None] | None = None
        last_pub_mono = 0.0
        max_deadline = (
            time.monotonic() + max(0.0, float(ns.max_follow_seconds))
            if (ns.follow and ns.max_follow_seconds is not None)
            else None
        )

        if ns.stdin:
            for sline in sys.stdin:
                inc_parser.feed_line(sline)
                if ns.follow and ns.publish_viewport:
                    now_m = time.monotonic()
                    cur_snap = inc_parser.snapshot()
                    cur_key = (cur_snap.line_count, len(cur_snap.incumbents), cur_snap.final_status)
                    if cur_key != last_pub_state and (
                        inc_parser.is_terminal()
                        or (now_m - last_pub_mono) >= _LIVE_PUBLISH_MIN_INTERVAL_SEC
                    ):
                        synthesis, vp_seq, permalink = _synthesize_and_deliver(cur_snap)
                        last_pub_state = cur_key
                        last_pub_mono = now_m
                if ns.follow and (
                    inc_parser.is_terminal()
                    or (max_deadline is not None and time.monotonic() >= max_deadline)
                ):
                    break
        elif ns.log_path:
            safe_log = resolve_safe_companion_path(ns.log_path, repo_root=repo_root)
            with safe_log.open("r", encoding="utf-8", errors="replace") as fh:
                if not ns.follow:
                    for fline in fh:
                        inc_parser.feed_line(fline)
                else:
                    partial_len = 0
                    while True:
                        where_init = fh.tell()
                        fline = fh.readline()
                        if not fline:
                            break
                        if not fline.endswith("\n"):
                            partial_len = len(fline)
                            fh.seek(where_init)
                            break
                        partial_len = 0
                        inc_parser.feed_line(fline)
                    if ns.publish_viewport:
                        init_snap = inc_parser.snapshot()
                        synthesis, vp_seq, permalink = _synthesize_and_deliver(init_snap)
                        last_pub_state = (
                            init_snap.line_count,
                            len(init_snap.incumbents),
                            init_snap.final_status,
                        )
                        last_pub_mono = time.monotonic()
                    if not inc_parser.is_terminal():
                        idle_timeout = max(0.0, float(ns.follow_timeout))
                        idle_deadline = time.monotonic() + idle_timeout
                        dirty = False
                        while not inc_parser.is_terminal():
                            now_m = time.monotonic()
                            if now_m >= idle_deadline or (
                                max_deadline is not None and now_m >= max_deadline
                            ):
                                break
                            where = fh.tell()
                            nxt = fh.readline()
                            if nxt and nxt.endswith("\n"):
                                partial_len = 0
                                inc_parser.feed_line(nxt)
                                dirty = True
                                now_after = time.monotonic()
                                idle_deadline = now_after + idle_timeout
                                if ns.publish_viewport and (
                                    inc_parser.is_terminal()
                                    or (now_after - last_pub_mono) >= _LIVE_PUBLISH_MIN_INTERVAL_SEC
                                ):
                                    cur_snap = inc_parser.snapshot()
                                    synthesis, vp_seq, permalink = _synthesize_and_deliver(cur_snap)
                                    last_pub_state = (
                                        cur_snap.line_count,
                                        len(cur_snap.incumbents),
                                        cur_snap.final_status,
                                    )
                                    last_pub_mono = now_after
                                    dirty = False
                            else:
                                fh.seek(where)
                                if nxt and len(nxt) > partial_len:
                                    partial_len = len(nxt)
                                    idle_deadline = time.monotonic() + idle_timeout
                                if dirty and ns.publish_viewport:
                                    cur_snap = inc_parser.snapshot()
                                    synthesis, vp_seq, permalink = _synthesize_and_deliver(cur_snap)
                                    last_pub_state = (
                                        cur_snap.line_count,
                                        len(cur_snap.incumbents),
                                        cur_snap.final_status,
                                    )
                                    last_pub_mono = time.monotonic()
                                    dirty = False
                                time.sleep(_LIVE_TAIL_POLL_SEC)
                        if not inc_parser.is_terminal():
                            rem = fh.readline()
                            if rem:
                                inc_parser.feed_line(rem)

        final_snap = inc_parser.snapshot()
        has_runtime = bool(
            ns.stdin or ns.log_path or ns.cp_solver_response or ns.telemetry_jsonl
        )
        final_key = (final_snap.line_count, len(final_snap.incumbents), final_snap.final_status)
        if synthesis is None or not ns.publish_viewport or final_key != last_pub_state:
            synthesis, fin_seq, permalink = _synthesize_and_deliver(
                final_snap if has_runtime else None
            )
            if fin_seq is not None:
                vp_seq = fin_seq

        payload = serialize_chronicle_payload(
            synthesis,
            permalink=permalink,
            published_to_viewport=bool(ns.publish_viewport),
            viewport_seq=vp_seq,
        )
        if ns.as_json:
            print(json.dumps(payload, indent=2))
        else:
            _print_human_chronicle(payload)
        return 0
    except Exception as exc:  # noqa: BLE001
        print(f"wythe watch-solver error: {exc}", file=sys.stderr)
        return 2


def _print_human_chronicle(payload: dict[str, Any]) -> None:
    print(f"{payload['title']} [timeline={payload['timeline_id']}]")
    print(f"  Follow   : {'following' if payload['live_following'] else 'halted'}")
    if payload["halted_reason"]:
        print(f"  Halt     : {payload['halted_reason']}")
    print(f"  Permalink: {payload['permalink']}")
    for frame in payload["chronicle_frames"]:
        marker = "*" if frame["phase_index"] == payload["active_phase_index"] else " "
        print(
            f" {marker} [{frame['status'].upper():<7}] {frame['phase_label']} ({frame['tier']}) — {frame['caption']}"
        )


def main(argv: list[str] | None = None) -> int:
    return run_watch_solver_cli(sys.argv[1:] if argv is None else argv)


if __name__ == "__main__":
    raise SystemExit(main())
