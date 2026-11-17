"""Durable shared human-agent investigation state, scan reuse cache, and citation validator."""

from __future__ import annotations

import hashlib
import json
import os
import re
import sqlite3
import threading
import uuid
from collections import OrderedDict
from collections.abc import Sequence
from datetime import datetime
from pathlib import Path
from typing import Any, Final

from sqlalchemy.orm import Session

from app.adapters.plugin_registry import discover_plugins, get_active_stratum_artifacts
from app.core.clock import utc_now
from app.core.config import load_settings
from app.models import TargetProject
from app.schemas.atlas import (
    EpistemicKind,
    EvidenceIdentityRead,
    EvidenceSourceItem,
    FollowState,
    InvestigationActor,
    InvestigationCorrectionCreate,
    InvestigationCorrectionRead,
    InvestigationCreateRequest,
    InvestigationDeltaEventRead,
    InvestigationDeltaEventsResponse,
    InvestigationExportBundle,
    InvestigationFocusSnapshot,
    InvestigationFollowUpdate,
    InvestigationListResponse,
    InvestigationRevisionComparisonRead,
    InvestigationSessionRead,
    InvestigationSummaryRead,
    InvestigationTurnCreate,
    InvestigationTurnRead,
    RetentionPolicyRead,
    TruthAtlasReport,
    ValidatedReferenceRead,
    ViewportCommandReceiptRead,
)
from app.services.governance_service import (
    get_target_by_slug,
    list_policy_vocabularies,
    list_ratchet_baselines,
    list_rule_policies,
    list_rulings,
    list_targets,
)
from app.services.scanner_service import run_target_scan

MAX_INVESTIGATION_SESSIONS: Final[int] = 64
MAX_TURNS_PER_SESSION: Final[int] = 100
MAX_EVENTS_PER_SESSION: Final[int] = 200
_SCAN_CACHE_MAX: Final[int] = 16
_SKIP_WALK_DIRS: Final[frozenset[str]] = frozenset(
    {
        ".git",
        "node_modules",
        ".venv",
        "venv",
        "__pycache__",
        ".next",
        ".pytest_cache",
        ".ruff_cache",
        ".mypy_cache",
        "dist",
        "build",
    }
)
_INVESTIGATION_LOCK = threading.RLock()
_INITIALIZED_DB_INODES: set[tuple[str, int]] = set()
_SCAN_REUSE_CACHE: OrderedDict[tuple[object, ...], TruthAtlasReport] = OrderedDict()
_SCAN_CACHE_STATS: dict[str, int] = {"hits": 0, "misses": 0}


def get_retention_policy() -> RetentionPolicyRead:
    return RetentionPolicyRead(
        max_sessions=MAX_INVESTIGATION_SESSIONS,
        max_turns_per_session=MAX_TURNS_PER_SESSION,
        max_events_per_session=MAX_EVENTS_PER_SESSION,
        storage_backend="sqlite_wal",
        db_filename="viewport_bus.sqlite3",
    )


def get_scan_cache_stats() -> dict[str, int]:
    with _INVESTIGATION_LOCK:
        return dict(_SCAN_CACHE_STATS)


def clear_scan_reuse_cache() -> None:
    with _INVESTIGATION_LOCK:
        _SCAN_REUSE_CACHE.clear()
        _SCAN_CACHE_STATS["hits"] = 0
        _SCAN_CACHE_STATS["misses"] = 0


def resolve_state_base_dir() -> Path:
    explicit_state = os.getenv("WYTHE_STATE_DIR") or os.getenv("TRUTH_ATLAS_STATE_DIR")
    if explicit_state:
        base_dir = Path(explicit_state).expanduser().resolve()
    else:
        settings = load_settings()
        db_url = settings.database_url
        if db_url.startswith("sqlite:///") and ":memory:" not in db_url:
            base_dir = Path(db_url.removeprefix("sqlite:///")).expanduser().resolve().parent
        elif ":memory:" in db_url:
            import tempfile

            uid_suffix = str(os.getuid()) if hasattr(os, "getuid") else "local"
            base_dir = (
                Path(tempfile.gettempdir()) / f"wythe-ephemeral-viewport-{uid_suffix}"
            ).resolve()
        else:
            base_dir = settings.state_dir.expanduser().resolve()
    if base_dir.is_symlink():
        raise RuntimeError(f"Refusing symlinked state directory: {base_dir}")
    base_dir.mkdir(parents=True, exist_ok=True)
    return base_dir


def resolve_investigation_db_path() -> Path:
    return resolve_state_base_dir() / "viewport_bus.sqlite3"


def _ensure_column(conn: sqlite3.Connection, table: str, col: str, col_ddl: str) -> None:
    existing = {str(r[1]) for r in conn.execute(f"PRAGMA table_info({table})").fetchall()}
    if col not in existing:
        conn.execute(f"ALTER TABLE {table} ADD COLUMN {col} {col_ddl}")


def open_investigation_connection(*, create: bool = True) -> sqlite3.Connection | None:
    db_path = resolve_investigation_db_path()
    if db_path.is_symlink():
        raise RuntimeError(f"Refusing symlinked investigation database: {db_path}")
    if not create and not db_path.is_file():
        return None
    db_path.parent.mkdir(parents=True, exist_ok=True)
    conn = sqlite3.connect(str(db_path), timeout=5.0, isolation_level=None)
    conn.execute("PRAGMA busy_timeout = 5000")
    try:
        ino = db_path.stat().st_ino
    except OSError:
        ino = 0
    cache_key = (str(db_path), ino)
    if cache_key not in _INITIALIZED_DB_INODES:
        with _INVESTIGATION_LOCK:
            if cache_key not in _INITIALIZED_DB_INODES:
                conn.execute("PRAGMA journal_mode = WAL")
                conn.execute("PRAGMA synchronous = NORMAL")
                conn.execute(
                    "CREATE TABLE IF NOT EXISTS viewport_events ("
                    "seq INTEGER PRIMARY KEY AUTOINCREMENT, "
                    "target_slug TEXT NOT NULL, "
                    "session_id TEXT, "
                    "permalink TEXT NOT NULL, "
                    "command_json TEXT NOT NULL, "
                    "created_at TEXT NOT NULL, "
                    "command_id TEXT, "
                    "correlation_id TEXT, "
                    "expected_evidence_revision TEXT, "
                    "expires_at TEXT, "
                    "delivery_state TEXT NOT NULL DEFAULT 'accepted_by_service', "
                    "applied_clients_json TEXT NOT NULL DEFAULT '[]'"
                    ")"
                )
                _ensure_column(conn, "viewport_events", "command_id", "TEXT")
                _ensure_column(conn, "viewport_events", "correlation_id", "TEXT")
                _ensure_column(conn, "viewport_events", "expected_evidence_revision", "TEXT")
                _ensure_column(conn, "viewport_events", "expires_at", "TEXT")
                _ensure_column(
                    conn,
                    "viewport_events",
                    "delivery_state",
                    "TEXT NOT NULL DEFAULT 'accepted_by_service'",
                )
                _ensure_column(
                    conn,
                    "viewport_events",
                    "applied_clients_json",
                    "TEXT NOT NULL DEFAULT '[]'",
                )
                conn.execute(
                    "CREATE INDEX IF NOT EXISTS idx_viewport_events_target_seq "
                    "ON viewport_events (target_slug, seq)"
                )
                conn.execute(
                    "CREATE INDEX IF NOT EXISTS idx_viewport_events_cmd_id "
                    "ON viewport_events (command_id)"
                )
                _init_investigation_tables(conn)
                try:
                    ino = db_path.stat().st_ino
                except OSError:
                    ino = 0
                _INITIALIZED_DB_INODES.add((str(db_path), ino))
    return conn


def _init_investigation_tables(conn: sqlite3.Connection) -> None:
    conn.execute(
        "CREATE TABLE IF NOT EXISTS viewport_receipts ("
        "id INTEGER PRIMARY KEY AUTOINCREMENT, "
        "receipt_id TEXT NOT NULL UNIQUE, "
        "command_id TEXT NOT NULL, "
        "seq INTEGER, "
        "target_slug TEXT NOT NULL, "
        "session_id TEXT, "
        "client_id TEXT NOT NULL, "
        "outcome TEXT NOT NULL, "
        "delivery_state TEXT NOT NULL, "
        "applied_focus_revision INTEGER, "
        "note TEXT NOT NULL DEFAULT '', "
        "recorded_at TEXT NOT NULL"
        ")"
    )
    conn.execute(
        "CREATE INDEX IF NOT EXISTS idx_viewport_receipts_cmd "
        "ON viewport_receipts (command_id, id)"
    )
    conn.execute(
        "CREATE TABLE IF NOT EXISTS investigation_sessions ("
        "session_id TEXT PRIMARY KEY, "
        "target_slug TEXT NOT NULL, "
        "title TEXT NOT NULL, "
        "follow_state TEXT NOT NULL DEFAULT 'following', "
        "follow_reason TEXT NOT NULL DEFAULT '', "
        "session_revision INTEGER NOT NULL DEFAULT 0, "
        "focus_revision INTEGER NOT NULL DEFAULT 0, "
        "participating_clients_json TEXT NOT NULL DEFAULT '[]', "
        "pinned_evidence_json TEXT NOT NULL, "
        "pinned_index_json TEXT NOT NULL DEFAULT '{}', "
        "latest_evidence_json TEXT NOT NULL, "
        "focus_state_json TEXT NOT NULL DEFAULT '{}', "
        "created_at TEXT NOT NULL, "
        "updated_at TEXT NOT NULL"
        ")"
    )
    conn.execute(
        "CREATE INDEX IF NOT EXISTS idx_inv_sessions_target_updated "
        "ON investigation_sessions (target_slug, updated_at DESC)"
    )
    conn.execute(
        "CREATE TABLE IF NOT EXISTS investigation_turns ("
        "id INTEGER PRIMARY KEY AUTOINCREMENT, "
        "turn_id TEXT NOT NULL UNIQUE, "
        "session_id TEXT NOT NULL, "
        "client_id TEXT, "
        "actor TEXT NOT NULL DEFAULT 'human', "
        "question TEXT NOT NULL, "
        "answer_markdown TEXT, "
        "status TEXT NOT NULL DEFAULT 'answered', "
        "authored_by TEXT NOT NULL DEFAULT 'model', "
        "engine TEXT, "
        "model_id TEXT, "
        "used_vision INTEGER NOT NULL DEFAULT 0, "
        "image_supplied INTEGER NOT NULL DEFAULT 0, "
        "fallback_reason TEXT, "
        "failure_reason TEXT, "
        "evidence_revision_id TEXT NOT NULL, "
        "focus_revision INTEGER NOT NULL DEFAULT 0, "
        "selected_node_id TEXT, "
        "selected_edge_id TEXT, "
        "selected_finding_id TEXT, "
        "validated_refs_json TEXT NOT NULL DEFAULT '[]', "
        "created_at TEXT NOT NULL"
        ")"
    )
    conn.execute(
        "CREATE INDEX IF NOT EXISTS idx_inv_turns_session "
        "ON investigation_turns (session_id, id ASC)"
    )
    conn.execute(
        "CREATE TABLE IF NOT EXISTS investigation_corrections ("
        "id INTEGER PRIMARY KEY AUTOINCREMENT, "
        "correction_id TEXT NOT NULL UNIQUE, "
        "session_id TEXT NOT NULL, "
        "client_id TEXT, "
        "actor TEXT NOT NULL DEFAULT 'human', "
        "target_ref_id TEXT, "
        "turn_id TEXT, "
        "kind TEXT NOT NULL DEFAULT 'disagreement', "
        "note TEXT NOT NULL, "
        "evidence_revision_id TEXT, "
        "promoted_to_ruling INTEGER NOT NULL DEFAULT 0, "
        "created_at TEXT NOT NULL"
        ")"
    )
    conn.execute(
        "CREATE INDEX IF NOT EXISTS idx_inv_corrections_session "
        "ON investigation_corrections (session_id, id ASC)"
    )
    conn.execute(
        "CREATE TABLE IF NOT EXISTS investigation_events ("
        "id INTEGER PRIMARY KEY AUTOINCREMENT, "
        "session_id TEXT NOT NULL, "
        "revision INTEGER NOT NULL, "
        "event_kind TEXT NOT NULL, "
        "actor TEXT NOT NULL DEFAULT 'system', "
        "client_id TEXT, "
        "summary TEXT NOT NULL, "
        "payload_json TEXT NOT NULL DEFAULT '{}', "
        "created_at TEXT NOT NULL"
        ")"
    )
    conn.execute(
        "CREATE INDEX IF NOT EXISTS idx_inv_events_session_rev "
        "ON investigation_events (session_id, revision ASC)"
    )


def _read_git_head_identity(git_marker: Path) -> bytes:
    """Read deterministic Git HEAD/ref bytes without touching `.git/index` stat caches."""
    try:
        if git_marker.is_file():
            raw_ptr = git_marker.read_text(encoding="utf-8", errors="replace").strip()
            if raw_ptr.startswith("gitdir:"):
                git_dir = (git_marker.parent / raw_ptr.split(":", 1)[1].strip()).resolve()
            else:
                return raw_ptr[:256].encode()
        else:
            git_dir = git_marker.resolve()

        head_file = git_dir / "HEAD"
        if not head_file.is_file():
            return b""
        head_raw = head_file.read_bytes()[:256].strip()
        if head_raw.startswith(b"ref:"):
            ref_rel = head_raw[4:].strip().decode("utf-8", errors="replace")
            ref_file = (git_dir / ref_rel).resolve()
            common_file: Path | None = None
            commondir = git_dir / "commondir"
            if commondir.is_file():
                c_rel = commondir.read_text(encoding="utf-8", errors="replace").strip()
                common_dir = (git_dir / c_rel).resolve()
                cand = (common_dir / ref_rel).resolve()
                if cand.is_relative_to(common_dir) and cand.is_file():
                    common_file = cand
            if ref_file.is_relative_to(git_dir) and ref_file.is_file():
                return head_raw + b"|" + ref_file.read_bytes()[:128].strip()
            if common_file is not None:
                return head_raw + b"|" + common_file.read_bytes()[:128].strip()
        return head_raw
    except OSError:
        return b""


def compute_repo_tree_fingerprint(repo_root: Path) -> tuple[str, bool]:
    """Compute a fast, deterministic SHA-256 content/stat tree fingerprint without spawning git."""
    resolved = repo_root.resolve()
    git_marker = resolved / ".git"
    is_git = git_marker.exists()
    hasher = hashlib.sha256()
    if is_git:
        head_bytes = _read_git_head_identity(git_marker)
        if head_bytes:
            hasher.update(b"GIT_HEAD|" + head_bytes + b"\n")

    bytes_read = 0
    max_inline_bytes = 2_000_000
    stack: list[Path] = [resolved]
    files: list[tuple[str, Path, os.stat_result]] = []
    while stack:
        cur_dir = stack.pop()
        try:
            entries = sorted(os.scandir(cur_dir), key=lambda e: e.name)
        except OSError:
            continue
        for entry in entries:
            if entry.is_symlink():
                continue
            if entry.is_dir(follow_symlinks=False):
                if entry.name not in _SKIP_WALK_DIRS:
                    stack.append(Path(entry.path))
                continue
            if entry.is_file(follow_symlinks=False):
                try:
                    st = entry.stat(follow_symlinks=False)
                    rel = Path(entry.path).relative_to(resolved).as_posix()
                    files.append((rel, Path(entry.path), st))
                except OSError:
                    continue

    files.sort(key=lambda item: item[0])
    for rel, fpath, st in files:
        hasher.update(f"F|{rel}|{st.st_size}|".encode())
        if st.st_size <= 65536 and (bytes_read + st.st_size) <= max_inline_bytes:
            try:
                raw = fpath.read_bytes()
                bytes_read += len(raw)
                hasher.update(hashlib.sha256(raw).digest())
                continue
            except OSError:
                pass
        hasher.update(f"{st.st_mtime_ns}".encode())
    return hasher.hexdigest(), is_git


def _governance_db_signature(session: Session, target_id: int | None) -> tuple[object, ...]:
    rules = tuple(
        (r.rule_code, r.severity, r.enabled, r.blocks_gate)
        for r in list_rule_policies(session)
    )
    vocabs = tuple(
        (v.domain_pack, v.token, v.is_enabled)
        for v in list_policy_vocabularies(session)
    )
    ruling_sig: tuple[object, ...] = ()
    ratchet_sig: tuple[object, ...] = ()
    if target_id:
        ruling_sig = tuple(
            (r.id, r.node_id, r.disposition, r.summary)
            for r in list_rulings(session, target_id)
        )
        ratchet_sig = tuple(
            (rb.rule_code, rb.max_allowed_count)
            for rb in list_ratchet_baselines(session, target_id)
        )
    return (rules, vocabs, ruling_sig, ratchet_sig)


def get_or_run_cached_scan(
    session: Session,
    target: TargetProject,
    *,
    strict_gate: bool = True,
    force_rescan: bool = False,
) -> TruthAtlasReport:
    """Return cached `TruthAtlasReport` when worktree & governance state match (`< 5ms`)."""
    repo_root = Path(target.repo_path).expanduser().resolve()
    tree_sha, _ = compute_repo_tree_fingerprint(repo_root)
    gov_sig = _governance_db_signature(session, target.id or None)
    active_artifacts = tuple(sorted((k, tuple(v)) for k, v in get_active_stratum_artifacts().items()))
    cache_key = (
        target.slug,
        str(repo_root),
        target.stack_profile_slug,
        target.backend_subdir,
        target.frontend_subdir,
        target.legacy_snapshot_relpath or "",
        bool(strict_gate),
        gov_sig,
        tree_sha,
        active_artifacts,
    )
    if not force_rescan:
        with _INVESTIGATION_LOCK:
            hit = _SCAN_REUSE_CACHE.get(cache_key)
            if hit is not None:
                _SCAN_REUSE_CACHE.move_to_end(cache_key)
                _SCAN_CACHE_STATS["hits"] += 1
                return hit.model_copy(deep=True)

    report = run_target_scan(
        session,
        target,
        strict_gate=strict_gate,
        persist_snapshot=False,
    )
    with _INVESTIGATION_LOCK:
        _SCAN_CACHE_STATS["misses"] += 1
        _SCAN_REUSE_CACHE[cache_key] = report.model_copy(deep=True)
        while len(_SCAN_REUSE_CACHE) > _SCAN_CACHE_MAX:
            _SCAN_REUSE_CACHE.popitem(last=False)
    return report


def build_evidence_identity(report: TruthAtlasReport) -> EvidenceIdentityRead:
    """Build deterministic `EvidenceIdentityRead` (explicit `non_git:<sha256>` outside Git)."""
    repo_root = Path(report.repo_path).expanduser().resolve()
    tree_sha, is_git = compute_repo_tree_fingerprint(repo_root)
    is_non_git = (
        not is_git
        or report.worktree_dirty is None
        or report.source_commit in ("unavailable", "", "non_git")
    )
    eff_commit = f"non_git:{tree_sha}" if is_non_git else report.source_commit

    specs = [s for s in discover_plugins() if s.enabled_by_default]
    active_plugin_names = [s.name for s in specs]
    active_artifacts = get_active_stratum_artifacts()

    freshness = (
        "non_git_worktree"
        if is_non_git
        else ("dirty_worktree" if report.worktree_dirty else "clean_git_commit")
    )
    sources: list[EvidenceSourceItem] = [
        EvidenceSourceItem(
            kind="source_static",
            producer="wythe-scanner",
            freshness=freshness,
            sampling_note=(
                "Complete static AST/config extraction."
                if report.coverage_complete
                else "Partial static coverage; inspect `scan_notes`."
            ),
        )
    ]
    _runtime_artifact_keys = frozenset(
        {"otel_traces", "ebpf_flows", "memgraph", "vmmap", "port_listeners", "probe_local_ports"}
    )
    has_active_compiled = any(k not in _runtime_artifact_keys for k in active_artifacts)
    has_active_runtime = any(k in _runtime_artifact_keys for k in active_artifacts)
    for artifact_kind, paths in sorted(active_artifacts.items()):
        if artifact_kind in _runtime_artifact_keys:
            is_live_ports = artifact_kind == "probe_local_ports"
            sources.append(
                EvidenceSourceItem(
                    kind="runtime_capture",
                    producer=f"wiretap:{artifact_kind}",
                    freshness="live_host_probe" if is_live_ports else "captured_sample_window",
                    sampling_note=(
                        "Opt-in passive host listener snapshot; point-in-time observation only."
                        if is_live_ports
                        else (
                            f"{len(paths)} passive runtime capture file(s) attached; sampled window only "
                            "(unexercised paths are static dark matter, never dead-code proof)."
                        )
                    ),
                )
            )
        else:
            sources.append(
                EvidenceSourceItem(
                    kind="compiled_artifact",
                    producer=f"artifact:{artifact_kind}",
                    freshness="user_supplied_snapshot",
                    sampling_note=f"{len(paths)} read-only artifact path(s) attached.",
                )
            )
    for spec in specs:
        ekinds = spec.resolved_evidence_source_kinds()
        if "compiled_artifact" in ekinds and not has_active_compiled:
            sources.append(
                EvidenceSourceItem(
                    kind="compiled_artifact",
                    producer=spec.name,
                    freshness="plugin_inspector_ready",
                    sampling_note="Companion/stratum inspector available; supply artifact flags when needed.",
                )
            )
        if "runtime_capture" in ekinds and not (has_active_runtime and "wiretap" in spec.name):
            sources.append(
                EvidenceSourceItem(
                    kind="runtime_capture",
                    producer=spec.name,
                    freshness="passive_capture_only",
                    sampling_note="Sampled/bounded passive telemetry; does not prove unrecorded paths.",
                )
            )

    rev_payload = json.dumps(
        {
            "target_slug": report.target_slug,
            "source_commit": eff_commit,
            "tree_sha256": tree_sha,
            "content_digest": report.content_digest,
            "active_plugins": active_plugin_names,
            "active_artifacts": {k: list(v) for k, v in sorted(active_artifacts.items())},
        },
        sort_keys=True,
    )
    rev_id = f"ev_{hashlib.sha256(rev_payload.encode('utf-8')).hexdigest()[:16]}"
    return EvidenceIdentityRead(
        evidence_revision_id=rev_id,
        snapshot_id=report.snapshot_id,
        source_commit=eff_commit,
        content_tree_sha256=tree_sha,
        worktree_dirty=report.worktree_dirty,
        dirty_path_count=report.dirty_path_count,
        content_digest=report.content_digest,
        observed_at=report.observed_at,
        coverage_complete=report.coverage_complete,
        stack_profile=report.stack_profile,
        active_plugins=active_plugin_names,
        evidence_sources=sources,
    )


def build_pinned_index(report: TruthAtlasReport) -> dict[str, Any]:
    """Capture compact node/edge/finding snapshots so vanished items are never rebound."""
    return {
        "nodes": {
            n.id: {
                "label": n.label,
                "tier": n.tier,
                "subkind": n.subkind,
                "source_file": n.source_file,
                "line": n.line,
                "status": n.status,
                "pfc_state": n.policy_field_consumption.state if n.policy_field_consumption else None,
            }
            for n in report.nodes
        },
        "edges": {
            e.id: {
                "source_id": e.source_id,
                "target_id": e.target_id,
                "kind": e.kind,
                "verification": e.verification,
                "evidence_path": e.evidence_path,
                "pfc_state": e.policy_field_consumption.state if e.policy_field_consumption else None,
            }
            for e in report.edges
        },
        "findings": {
            f.id: {
                "rule_code": f.rule_code,
                "tier": f.tier,
                "severity": f.severity,
                "node_id": f.node_id,
                "source_file": f.source_file,
                "line": f.line,
                "title": f.title,
            }
            for f in report.findings
        },
    }


_BACKTICK_TOKEN_RE = re.compile(r"`([^`\n]{2,180})`")
_SNIPPET_PTR_RE = re.compile(r"^([A-Za-z0-9_./-]+\.[A-Za-z0-9_+-]+):(\d+)$")


def _classify_finding_epistemic(rule_code: str) -> EpistemicKind:
    up = rule_code.upper()
    if up.startswith(("PORT-", "WIRETAP-", "TRACE-")):
        return "runtime_capture"
    if up.startswith(("BIN-", "IR-", "CPSAT-PROTO")):
        return "compiled_artifact"
    return "static_inference"


def _match_pinned_findings_to_current(
    pinned_findings: dict[str, Any],
    current_findings: Sequence[Any],
) -> tuple[dict[str, Any], list[str]]:
    """Match findings semantically by `(rule_code, source_file, node_id)` rather than positional `f:RULE:idx`."""
    used_cur_indices: set[int] = set()
    pinned_to_cur: dict[str, Any] = {}

    def _sem_key(rule_code: object, source_file: object, node_id: object) -> tuple[str, str, str]:
        return (str(rule_code or ""), str(source_file or ""), str(node_id or ""))

    by_sem: dict[tuple[str, str, str], list[int]] = {}
    for idx, cf in enumerate(current_findings):
        key = _sem_key(cf.rule_code, cf.source_file, cf.node_id)
        by_sem.setdefault(key, []).append(idx)

    # Pass 1: exact (rule_code, source_file, node_id, title, line)
    for pf_id, pf in pinned_findings.items():
        key = _sem_key(pf.get("rule_code"), pf.get("source_file"), pf.get("node_id"))
        pf_title = str(pf.get("title") or "")
        pf_line = int(pf.get("line") or 0)
        for idx in by_sem.get(key, ()):
            if idx in used_cur_indices:
                continue
            cf = current_findings[idx]
            if cf.title == pf_title and int(cf.line or 0) == pf_line:
                used_cur_indices.add(idx)
                pinned_to_cur[pf_id] = cf
                break

    # Pass 2: same (rule_code, source_file, node_id), closest line (preferring matching title)
    for pf_id, pf in pinned_findings.items():
        if pf_id in pinned_to_cur:
            continue
        key = _sem_key(pf.get("rule_code"), pf.get("source_file"), pf.get("node_id"))
        pf_title = str(pf.get("title") or "")
        pf_line = int(pf.get("line") or 0)
        candidates = [idx for idx in by_sem.get(key, ()) if idx not in used_cur_indices]
        if not candidates:
            continue
        best_idx = min(
            candidates,
            key=lambda idx: (
                0 if current_findings[idx].title == pf_title else 1,
                abs(int(current_findings[idx].line or 0) - pf_line),
                idx,
            ),
        )
        used_cur_indices.add(best_idx)
        pinned_to_cur[pf_id] = current_findings[best_idx]

    unmatched_cur_ids = [
        str(cf.id) for idx, cf in enumerate(current_findings) if idx not in used_cur_indices
    ]
    return pinned_to_cur, unmatched_cur_ids


def validate_references_against_report(
    explicit_ids: Sequence[str],
    report: TruthAtlasReport | None,
    *,
    evidence_revision_id: str,
    pinned_index: dict[str, Any] | None = None,
    answer_markdown: str | None = None,
) -> list[ValidatedReferenceRead]:
    """Validate explicit IDs & markdown citations against `report` (`validated` vs `text_convenience`)."""
    nodes_by_id = {n.id: n for n in (report.nodes if report else ())}
    edges_by_id = {e.id: e for e in (report.edges if report else ())}
    findings_by_id = {f.id: f for f in (report.findings if report else ())}
    repo_root = Path(report.repo_path).resolve() if report else None

    pinned_nodes = (pinned_index or {}).get("nodes") or {}
    pinned_edges = (pinned_index or {}).get("edges") or {}
    pinned_findings = (pinned_index or {}).get("findings") or {}
    pinned_finding_matches, _ = (
        _match_pinned_findings_to_current(pinned_findings, report.findings if report else ())
        if pinned_findings
        else ({}, [])
    )

    candidate_explicit: list[str] = []
    for raw in explicit_ids:
        cleaned = str(raw or "").strip()
        if cleaned and cleaned not in candidate_explicit:
            candidate_explicit.append(cleaned)

    if answer_markdown:
        for match in _BACKTICK_TOKEN_RE.finditer(answer_markdown):
            tok = match.group(1).strip()
            if (
                tok in nodes_by_id
                or tok in edges_by_id
                or tok in findings_by_id
                or tok in pinned_nodes
                or tok in pinned_edges
                or tok in pinned_findings
                or _SNIPPET_PTR_RE.match(tok)
                or tok.startswith("capture:")
            ) and tok not in candidate_explicit:
                candidate_explicit.append(tok)

    results: list[ValidatedReferenceRead] = []
    seen_refs: set[str] = set()

    for ref_id in candidate_explicit[:32]:
        if ref_id in seen_refs:
            continue
        seen_refs.add(ref_id)
        if ref_id in nodes_by_id:
            n = nodes_by_id[ref_id]
            ep: EpistemicKind = (
                "observation"
                if report and "db_catalog" in report.observation_source and n.tier == "truth"
                else "static_inference"
            )
            results.append(
                ValidatedReferenceRead(
                    ref_id=n.id,
                    kind="node",
                    label=n.label,
                    source_file=n.source_file,
                    line=n.line,
                    evidence_revision_id=evidence_revision_id,
                    validation_state="validated",
                    epistemic_kind=ep,
                )
            )
        elif ref_id in edges_by_id:
            e = edges_by_id[ref_id]
            results.append(
                ValidatedReferenceRead(
                    ref_id=e.id,
                    kind="edge",
                    label=f"{e.source_id} -> {e.target_id}",
                    source_file=e.evidence_path,
                    evidence_revision_id=evidence_revision_id,
                    validation_state="validated",
                    epistemic_kind="verified_result" if e.verification == "verified" else "static_inference",
                )
            )
        elif ref_id in pinned_findings:
            pf = pinned_findings[ref_id]
            matched_cf = pinned_finding_matches.get(ref_id)
            if matched_cf is not None:
                results.append(
                    ValidatedReferenceRead(
                        ref_id=ref_id,
                        kind="finding",
                        label=f"{matched_cf.rule_code}: {matched_cf.title}",
                        source_file=matched_cf.source_file,
                        line=matched_cf.line,
                        evidence_revision_id=evidence_revision_id,
                        validation_state="validated",
                        epistemic_kind=_classify_finding_epistemic(matched_cf.rule_code),
                    )
                )
            else:
                results.append(
                    ValidatedReferenceRead(
                        ref_id=ref_id,
                        kind="finding",
                        label=f"{pf.get('rule_code')}: {pf.get('title')}",
                        source_file=pf.get("source_file"),
                        line=pf.get("line"),
                        evidence_revision_id=evidence_revision_id,
                        validation_state="vanished_in_current_scan",
                        epistemic_kind="static_inference",
                        note="Finding resolved or vanished in current scan (preserved from pinned snapshot without rebinding).",
                    )
                )
        elif ref_id in findings_by_id:
            f = findings_by_id[ref_id]
            results.append(
                ValidatedReferenceRead(
                    ref_id=f.id,
                    kind="finding",
                    label=f"{f.rule_code}: {f.title}",
                    source_file=f.source_file,
                    line=f.line,
                    evidence_revision_id=evidence_revision_id,
                    validation_state="validated",
                    epistemic_kind=_classify_finding_epistemic(f.rule_code),
                )
            )
        elif (m_snip := _SNIPPET_PTR_RE.match(ref_id)) is not None:
            rel_p, line_s = m_snip.group(1), int(m_snip.group(2))
            is_valid_file = False
            if repo_root is not None:
                cand_f = repo_root / rel_p
                try:
                    resolved_f = cand_f.resolve()
                    is_valid_file = (
                        not cand_f.is_symlink()
                        and resolved_f.is_relative_to(repo_root)
                        and resolved_f.is_file()
                    )
                except OSError:
                    is_valid_file = False
            results.append(
                ValidatedReferenceRead(
                    ref_id=ref_id,
                    kind="snippet",
                    label=ref_id,
                    source_file=rel_p,
                    line=line_s,
                    evidence_revision_id=evidence_revision_id,
                    validation_state="validated" if is_valid_file else "unresolved",
                    epistemic_kind="observation" if is_valid_file else "static_inference",
                )
            )
        elif ref_id.startswith(("capture:", "ui_focus_", "wiretap:", "wt:wiretap:", "z3:")):
            is_wiretap_ref = ref_id.startswith(("wiretap:", "wt:wiretap:", "z3:"))
            active_rt = any(
                k in get_active_stratum_artifacts()
                for k in ("otel_traces", "ebpf_flows", "memgraph", "vmmap", "port_listeners", "probe_local_ports")
            )
            results.append(
                ValidatedReferenceRead(
                    ref_id=ref_id,
                    kind="capture",
                    label=ref_id,
                    evidence_revision_id=evidence_revision_id,
                    validation_state="validated" if (not is_wiretap_ref or active_rt or ref_id.startswith("wiretap:")) else "text_convenience",
                    epistemic_kind="runtime_capture",
                    producer="wythe-plugin-wiretap" if is_wiretap_ref else "wythe-ui-focus",
                    note=(
                        "Sampled passive runtime capture reference; unexercised paths are static dark matter."
                        if is_wiretap_ref
                        else ""
                    ),
                )
            )
        elif ref_id in pinned_nodes:
            pn = pinned_nodes[ref_id]
            results.append(
                ValidatedReferenceRead(
                    ref_id=ref_id,
                    kind="node",
                    label=str(pn.get("label") or ref_id),
                    source_file=pn.get("source_file"),
                    line=pn.get("line"),
                    evidence_revision_id=evidence_revision_id,
                    validation_state="vanished_in_current_scan",
                    epistemic_kind="static_inference",
                    note="Present in pinned session evidence; absent from current scan (never rebound).",
                )
            )
        elif ref_id in pinned_edges:
            pe = pinned_edges[ref_id]
            results.append(
                ValidatedReferenceRead(
                    ref_id=ref_id,
                    kind="edge",
                    label=f"{pe.get('source_id')} -> {pe.get('target_id')}",
                    source_file=pe.get("evidence_path"),
                    evidence_revision_id=evidence_revision_id,
                    validation_state="vanished_in_current_scan",
                    epistemic_kind="static_inference",
                    note="Edge vanished in current scan.",
                )
            )
        elif ref_id in pinned_findings:
            pf = pinned_findings[ref_id]
            results.append(
                ValidatedReferenceRead(
                    ref_id=ref_id,
                    kind="finding",
                    label=f"{pf.get('rule_code')}: {pf.get('title')}",
                    source_file=pf.get("source_file"),
                    line=pf.get("line"),
                    evidence_revision_id=evidence_revision_id,
                    validation_state="vanished_in_current_scan",
                    epistemic_kind="static_inference",
                    note="Finding resolved or vanished in current scan.",
                )
            )
        else:
            inferred_kind = (
                "edge"
                if ref_id.startswith("e:")
                else ("finding" if ref_id.startswith("f:") else "node")
            )
            results.append(
                ValidatedReferenceRead(
                    ref_id=ref_id,
                    kind=inferred_kind,  # type: ignore[arg-type]
                    label=ref_id,
                    evidence_revision_id=evidence_revision_id,
                    validation_state="unresolved",
                    epistemic_kind="model_interpretation",
                    note="Reference ID not found in referenced scan.",
                )
            )

    if answer_markdown and report is not None:
        low_ans = answer_markdown.lower()
        for node in report.nodes:
            if len(results) >= 12:
                break
            if node.id in seen_refs:
                continue
            lbl_low = node.label.lower()
            is_code_ident = "_" in lbl_low or "/" in lbl_low or ":" in lbl_low
            if f"`{lbl_low}`" in low_ans or (is_code_ident and len(lbl_low) >= 5 and lbl_low in low_ans):
                seen_refs.add(node.id)
                results.append(
                    ValidatedReferenceRead(
                        ref_id=node.id,
                        kind="node",
                        label=node.label,
                        source_file=node.source_file,
                        line=node.line,
                        evidence_revision_id=evidence_revision_id,
                        validation_state="text_convenience",
                        epistemic_kind="model_interpretation",
                        note="Matched by label text convenience; verify explicit ID.",
                    )
                )
    return results


def _new_session_id(target_slug: str) -> str:
    safe = re.sub(r"[^a-zA-Z0-9_-]", "-", target_slug)[:24].strip("-") or "inv"
    return f"{safe}-{uuid.uuid4().hex[:8]}"


def sanitize_session_file_token(session_id: str) -> str:
    cleaned = re.sub(r"[^A-Za-z0-9_-]", "_", session_id.strip())[:64]
    if not cleaned:
        raise ValueError("Invalid empty `session_id`.")
    return cleaned


def _append_delta_in_tx(
    conn: sqlite3.Connection,
    *,
    session_id: str,
    event_kind: str,
    actor: InvestigationActor,
    client_id: str | None,
    summary: str,
    payload: dict[str, Any] | None = None,
    now_iso: str | None = None,
) -> int:
    ts = now_iso or utc_now().isoformat()
    row = conn.execute(
        "SELECT session_revision FROM investigation_sessions WHERE session_id = ?",
        (session_id,),
    ).fetchone()
    if row is None:
        return 0
    next_rev = int(row[0]) + 1
    conn.execute(
        "UPDATE investigation_sessions SET session_revision = ?, updated_at = ? WHERE session_id = ?",
        (next_rev, ts, session_id),
    )
    conn.execute(
        "INSERT INTO investigation_events "
        "(session_id, revision, event_kind, actor, client_id, summary, payload_json, created_at) "
        "VALUES (?, ?, ?, ?, ?, ?, ?, ?)",
        (
            session_id,
            next_rev,
            event_kind,
            actor,
            client_id,
            summary[:400],
            json.dumps(payload or {}),
            ts,
        ),
    )
    conn.execute(
        "DELETE FROM investigation_events "
        "WHERE session_id = ? AND id <= COALESCE(("
        "SELECT id FROM investigation_events WHERE session_id = ? "
        "ORDER BY id DESC LIMIT 1 OFFSET ?"
        "), 0)",
        (session_id, session_id, MAX_EVENTS_PER_SESSION),
    )
    return next_rev


def append_session_delta_event(
    session_id: str | None,
    *,
    event_kind: str,
    actor: InvestigationActor = "system",
    client_id: str | None = None,
    summary: str,
    payload: dict[str, Any] | None = None,
) -> int:
    if not session_id or not session_id.strip():
        return 0
    clean_sid = session_id.strip()
    with _INVESTIGATION_LOCK:
        conn = open_investigation_connection(create=False)
        if conn is None:
            return 0
        try:
            conn.execute("BEGIN IMMEDIATE")
            rev = _append_delta_in_tx(
                conn,
                session_id=clean_sid,
                event_kind=event_kind,
                actor=actor,
                client_id=client_id,
                summary=summary,
                payload=payload,
            )
            conn.execute("COMMIT")
            return rev
        finally:
            conn.close()


def _enforce_session_retention_in_tx(conn: sqlite3.Connection) -> None:
    stale_rows = conn.execute(
        "SELECT session_id FROM investigation_sessions "
        "ORDER BY updated_at DESC LIMIT -1 OFFSET ?",
        (MAX_INVESTIGATION_SESSIONS,),
    ).fetchall()
    if not stale_rows:
        return
    base_dir = resolve_state_base_dir()
    for (stale_sid,) in stale_rows:
        sid = str(stale_sid)
        conn.execute("DELETE FROM investigation_turns WHERE session_id = ?", (sid,))
        conn.execute("DELETE FROM investigation_corrections WHERE session_id = ?", (sid,))
        conn.execute("DELETE FROM investigation_events WHERE session_id = ?", (sid,))
        conn.execute("DELETE FROM investigation_sessions WHERE session_id = ?", (sid,))
        try:
            tok = sanitize_session_file_token(sid)
            for ext in (".webp", ".png", ".jpg"):
                (base_dir / f"ui_focus_session_{tok}{ext}").unlink(missing_ok=True)
        except ValueError:
            pass


def _resolve_target_or_raise(db_session: Session, target_slug: str) -> TargetProject:
    target = get_target_by_slug(db_session, target_slug.strip())
    if target is not None:
        return target
    registered = [t.slug for t in list_targets(db_session)]
    known_str = ", ".join(f"`{s}`" for s in registered) if registered else "none"
    raise LookupError(f"Unknown target `{target_slug}`. Registered targets: {known_str}.")


def create_or_reopen_investigation(
    db_session: Session,
    payload: InvestigationCreateRequest,
    *,
    precomputed_report: TruthAtlasReport | None = None,
) -> InvestigationSessionRead:
    """Create a new durable investigation session or reopen an existing `session_id`."""
    target = _resolve_target_or_raise(db_session, payload.target_slug)
    report = precomputed_report or get_or_run_cached_scan(db_session, target)
    ev_identity = build_evidence_identity(report)
    pinned_idx = build_pinned_index(report)
    sid = (payload.session_id or "").strip() or _new_session_id(target.slug)
    client_id = (payload.client_id or "").strip() or None
    now = utc_now()
    now_iso = now.isoformat()

    with _INVESTIGATION_LOCK:
        conn = open_investigation_connection(create=True)
        assert conn is not None
        try:
            conn.execute("BEGIN IMMEDIATE")
            existing = conn.execute(
                "SELECT target_slug, participating_clients_json, title "
                "FROM investigation_sessions WHERE session_id = ?",
                (sid,),
            ).fetchone()
            if existing is not None:
                existing_slug = str(existing[0])
                if existing_slug != target.slug:
                    raise ValueError(
                        f"Investigation session `{sid}` belongs to target `{existing_slug}` "
                        f"and cannot be reopened on `{target.slug}`."
                    )
                clients: list[str] = json.loads(str(existing[1] or "[]"))
                if client_id and client_id not in clients:
                    clients.append(client_id)
                new_title = (payload.title or "").strip() or str(existing[2])
                conn.execute(
                    "UPDATE investigation_sessions "
                    "SET participating_clients_json = ?, title = ?, latest_evidence_json = ?, updated_at = ? "
                    "WHERE session_id = ?",
                    (
                        json.dumps(clients[:32]),
                        new_title,
                        ev_identity.model_dump_json(),
                        now_iso,
                        sid,
                    ),
                )
                _append_delta_in_tx(
                    conn,
                    session_id=sid,
                    event_kind="session_reopened",
                    actor="human",
                    client_id=client_id,
                    summary=f"Reopened investigation `{sid}` on `{target.slug}`.",
                    payload={"evidence_revision_id": ev_identity.evidence_revision_id},
                    now_iso=now_iso,
                )
            else:
                clients = [client_id] if client_id else []
                init_title = (payload.title or "").strip() or f"Investigation · {target.name}"
                init_focus = {"active_slug": target.slug, "updated_at": now_iso}
                conn.execute(
                    "INSERT INTO investigation_sessions ("
                    "session_id, target_slug, title, follow_state, follow_reason, "
                    "session_revision, focus_revision, participating_clients_json, "
                    "pinned_evidence_json, pinned_index_json, latest_evidence_json, "
                    "focus_state_json, created_at, updated_at"
                    ") VALUES (?, ?, ?, 'following', '', 0, 0, ?, ?, ?, ?, ?, ?, ?)",
                    (
                        sid,
                        target.slug,
                        init_title,
                        json.dumps(clients),
                        ev_identity.model_dump_json(),
                        json.dumps(pinned_idx),
                        ev_identity.model_dump_json(),
                        json.dumps(init_focus),
                        now_iso,
                        now_iso,
                    ),
                )
                _append_delta_in_tx(
                    conn,
                    session_id=sid,
                    event_kind="session_created",
                    actor="human",
                    client_id=client_id,
                    summary=f"Started investigation `{sid}` on `{target.slug}` ({ev_identity.evidence_revision_id}).",
                    payload={"evidence_revision_id": ev_identity.evidence_revision_id},
                    now_iso=now_iso,
                )
                _enforce_session_retention_in_tx(conn)
            conn.execute("COMMIT")
        finally:
            conn.close()
    out = get_investigation_session(sid)
    assert out is not None
    return out


def _row_to_focus_snapshot(
    focus_dict: dict[str, Any],
    focus_revision: int,
    fallback_ts: str,
) -> InvestigationFocusSnapshot:
    raw_ts = str(focus_dict.get("observed_at") or focus_dict.get("updated_at") or fallback_ts)
    snap_path = focus_dict.get("snapshot_path")
    return InvestigationFocusSnapshot(
        focus_revision=focus_revision,
        actor=focus_dict.get("actor") if focus_dict.get("actor") in ("human", "agent", "system") else "human",
        client_id=focus_dict.get("client_id"),
        active_tab=str(focus_dict.get("active_tab") or "3d"),
        selected_node_id=focus_dict.get("selected_node_id"),
        selected_edge_id=focus_dict.get("selected_edge_id"),
        selected_finding_id=focus_dict.get("selected_finding_id"),
        hovered_node_id=focus_dict.get("hovered_node_id"),
        focused_district=focus_dict.get("focused_district"),
        lens=str(focus_dict.get("lens") or "status"),
        layout_mode=str(focus_dict.get("layout_mode") or "cluster"),
        blast_mode=str(focus_dict.get("blast_mode") or "off"),
        diff_base_ref=str(focus_dict.get("diff_base_ref") or "HEAD~1"),
        has_snapshot=bool(snap_path),
        snapshot_path=snap_path,
        snapshot_focus_revision=focus_dict.get("snapshot_focus_revision"),
        snapshot_evidence_revision=focus_dict.get("snapshot_evidence_revision"),
        updated_at=datetime.fromisoformat(raw_ts),
    )


def _load_receipts_for_session_in_conn(
    conn: sqlite3.Connection,
    target_slug: str,
    session_id: str | None,
    *,
    limit: int = 20,
) -> list[ViewportCommandReceiptRead]:
    rows = conn.execute(
        "SELECT r.receipt_id, r.command_id, r.seq, r.target_slug, r.session_id, "
        "r.client_id, r.outcome, r.delivery_state, r.applied_focus_revision, r.note, r.recorded_at, "
        "COALESCE(e.applied_clients_json, '[]') "
        "FROM viewport_receipts r "
        "LEFT JOIN viewport_events e ON e.command_id = r.command_id "
        "WHERE r.target_slug = ? AND (? IS NULL OR r.session_id IS NULL OR r.session_id = ?) "
        "ORDER BY r.id DESC LIMIT ?",
        (target_slug, session_id, session_id, limit),
    ).fetchall()
    out: list[ViewportCommandReceiptRead] = []
    for r in reversed(rows):
        out.append(
            ViewportCommandReceiptRead(
                receipt_id=str(r[0]),
                command_id=str(r[1]),
                seq=int(r[2]) if r[2] is not None else None,
                target_slug=str(r[3]),
                session_id=str(r[4]) if r[4] is not None else None,
                client_id=str(r[5]),
                outcome=r[6],
                delivery_state=r[7],
                applied_by_client_ids=json.loads(str(r[11] or "[]")),
                applied_focus_revision=int(r[8]) if r[8] is not None else None,
                note=str(r[9] or ""),
                recorded_at=datetime.fromisoformat(str(r[10])),
            )
        )
    return out


def list_investigations(target_slug: str | None = None) -> InvestigationListResponse:
    conn = open_investigation_connection(create=False)
    if conn is None:
        return InvestigationListResponse(sessions=[], retention_policy=get_retention_policy())
    try:
        if target_slug and target_slug.strip():
            rows = conn.execute(
                "SELECT session_id, target_slug, title, follow_state, session_revision, focus_revision, "
                "participating_clients_json, pinned_evidence_json, latest_evidence_json, "
                "focus_state_json, created_at, updated_at "
                "FROM investigation_sessions WHERE target_slug = ? ORDER BY updated_at DESC",
                (target_slug.strip(),),
            ).fetchall()
        else:
            rows = conn.execute(
                "SELECT session_id, target_slug, title, follow_state, session_revision, focus_revision, "
                "participating_clients_json, pinned_evidence_json, latest_evidence_json, "
                "focus_state_json, created_at, updated_at "
                "FROM investigation_sessions ORDER BY updated_at DESC"
            ).fetchall()

        summaries: list[InvestigationSummaryRead] = []
        for r in rows:
            sid = str(r[0])
            pinned_ev = json.loads(str(r[7]))
            latest_ev = json.loads(str(r[8]))
            focus_d = json.loads(str(r[9] or "{}"))
            t_total = int(
                conn.execute(
                    "SELECT COUNT(*) FROM investigation_turns WHERE session_id = ?", (sid,)
                ).fetchone()[0]
            )
            t_unres = int(
                conn.execute(
                    "SELECT COUNT(*) FROM investigation_turns WHERE session_id = ? AND status = 'unresolved'",
                    (sid,),
                ).fetchone()[0]
            )
            c_cnt = int(
                conn.execute(
                    "SELECT COUNT(*) FROM investigation_corrections WHERE session_id = ?", (sid,)
                ).fetchone()[0]
            )
            summaries.append(
                InvestigationSummaryRead(
                    session_id=sid,
                    target_slug=str(r[1]),
                    title=str(r[2]),
                    follow_state=r[3] if r[3] in ("following", "paused") else "following",
                    session_revision=int(r[4]),
                    focus_revision=int(r[5]),
                    pinned_evidence_revision_id=str(pinned_ev.get("evidence_revision_id") or ""),
                    latest_evidence_revision_id=str(latest_ev.get("evidence_revision_id") or ""),
                    participating_client_ids=json.loads(str(r[6] or "[]")),
                    turn_count=t_total,
                    unresolved_question_count=t_unres,
                    correction_count=c_cnt,
                    selected_node_id=focus_d.get("selected_node_id"),
                    selected_edge_id=focus_d.get("selected_edge_id"),
                    selected_finding_id=focus_d.get("selected_finding_id"),
                    created_at=datetime.fromisoformat(str(r[10])),
                    updated_at=datetime.fromisoformat(str(r[11])),
                )
            )
        return InvestigationListResponse(sessions=summaries, retention_policy=get_retention_policy())
    finally:
        conn.close()


def get_active_session_ids_for_target(target_slug: str) -> list[str]:
    conn = open_investigation_connection(create=False)
    if conn is None:
        return []
    try:
        rows = conn.execute(
            "SELECT session_id FROM investigation_sessions WHERE target_slug = ? ORDER BY updated_at DESC",
            (target_slug.strip(),),
        ).fetchall()
        return [str(r[0]) for r in rows]
    finally:
        conn.close()


def get_session_follow_state(target_slug: str, session_id: str | None) -> FollowState | None:
    conn = open_investigation_connection(create=False)
    if conn is None:
        return None
    try:
        if session_id and session_id.strip():
            row = conn.execute(
                "SELECT follow_state FROM investigation_sessions WHERE session_id = ?",
                (session_id.strip(),),
            ).fetchone()
            if row is not None and row[0] in ("following", "paused"):
                return row[0]
            return None
        rows = conn.execute(
            "SELECT follow_state FROM investigation_sessions WHERE target_slug = ? ORDER BY updated_at DESC LIMIT 2",
            (target_slug.strip(),),
        ).fetchall()
        if len(rows) == 1 and rows[0][0] in ("following", "paused"):
            return rows[0][0]
        return None
    finally:
        conn.close()


def get_session_raw_focus_state(session_id: str) -> tuple[dict[str, Any], int, FollowState, str | None] | None:
    conn = open_investigation_connection(create=False)
    if conn is None:
        return None
    try:
        row = conn.execute(
            "SELECT focus_state_json, focus_revision, follow_state, latest_evidence_json "
            "FROM investigation_sessions WHERE session_id = ?",
            (session_id.strip(),),
        ).fetchone()
        if row is None:
            return None
        focus_d = json.loads(str(row[0] or "{}"))
        latest_ev = json.loads(str(row[3] or "{}"))
        fstate: FollowState = row[2] if row[2] in ("following", "paused") else "following"
        return focus_d, int(row[1]), fstate, latest_ev.get("evidence_revision_id")
    finally:
        conn.close()


def get_investigation_session(session_id: str) -> InvestigationSessionRead | None:
    conn = open_investigation_connection(create=False)
    if conn is None:
        return None
    try:
        row = conn.execute(
            "SELECT session_id, target_slug, title, follow_state, follow_reason, "
            "session_revision, focus_revision, participating_clients_json, "
            "pinned_evidence_json, latest_evidence_json, focus_state_json, created_at, updated_at "
            "FROM investigation_sessions WHERE session_id = ?",
            (session_id.strip(),),
        ).fetchone()
        if row is None:
            return None
        sid = str(row[0])
        slug = str(row[1])
        pinned_ev = EvidenceIdentityRead.model_validate_json(str(row[8]))
        latest_ev = EvidenceIdentityRead.model_validate_json(str(row[9]))
        focus_d = json.loads(str(row[10] or "{}"))
        focus_snap = _row_to_focus_snapshot(focus_d, int(row[6]), str(row[12]))

        turn_rows = conn.execute(
            "SELECT turn_id, session_id, client_id, actor, question, answer_markdown, "
            "status, authored_by, engine, model_id, used_vision, image_supplied, "
            "fallback_reason, failure_reason, evidence_revision_id, focus_revision, "
            "selected_node_id, selected_edge_id, selected_finding_id, validated_refs_json, created_at "
            "FROM investigation_turns WHERE session_id = ? ORDER BY id ASC",
            (sid,),
        ).fetchall()
        turns: list[InvestigationTurnRead] = []
        for tr in turn_rows:
            t_ev_id = str(tr[14])
            refs = [
                ValidatedReferenceRead.model_validate(it)
                for it in json.loads(str(tr[19] or "[]"))
            ]
            turns.append(
                InvestigationTurnRead(
                    turn_id=str(tr[0]),
                    session_id=str(tr[1]),
                    client_id=tr[2],
                    actor=tr[3] if tr[3] in ("human", "agent", "system") else "human",
                    question=str(tr[4]),
                    answer_markdown=tr[5],
                    status="unresolved" if tr[6] == "unresolved" else "answered",
                    authored_by=tr[7] if tr[7] in ("model", "scanner_brief", "none") else "model",
                    engine=tr[8],
                    model_id=tr[9],
                    used_vision=bool(tr[10]),
                    image_supplied=bool(tr[11]),
                    fallback_reason=tr[12],
                    failure_reason=tr[13],
                    evidence_revision_id=t_ev_id,
                    focus_revision=int(tr[15]),
                    selected_node_id=tr[16],
                    selected_edge_id=tr[17],
                    selected_finding_id=tr[18],
                    validated_references=refs,
                    needs_revalidation=(t_ev_id != latest_ev.evidence_revision_id),
                    created_at=datetime.fromisoformat(str(tr[20])),
                )
            )

        corr_rows = conn.execute(
            "SELECT correction_id, session_id, client_id, actor, target_ref_id, turn_id, "
            "kind, note, evidence_revision_id, promoted_to_ruling, created_at "
            "FROM investigation_corrections WHERE session_id = ? ORDER BY id ASC",
            (sid,),
        ).fetchall()
        corrections = [
            InvestigationCorrectionRead(
                correction_id=str(cr[0]),
                session_id=str(cr[1]),
                client_id=cr[2],
                actor=cr[3] if cr[3] in ("human", "agent", "system") else "human",
                target_ref_id=cr[4],
                turn_id=cr[5],
                kind=str(cr[6]),
                note=str(cr[7]),
                evidence_revision_id=cr[8],
                promoted_to_ruling=bool(cr[9]),
                created_at=datetime.fromisoformat(str(cr[10])),
            )
            for cr in corr_rows
        ]

        ev_rows = conn.execute(
            "SELECT revision, session_id, event_kind, actor, client_id, summary, payload_json, created_at "
            "FROM investigation_events WHERE session_id = ? ORDER BY revision DESC LIMIT 50",
            (sid,),
        ).fetchall()
        events = [
            InvestigationDeltaEventRead(
                revision=int(er[0]),
                session_id=str(er[1]),
                event_kind=str(er[2]),
                actor=er[3] if er[3] in ("human", "agent", "system") else "system",
                client_id=er[4],
                summary=str(er[5]),
                payload=json.loads(str(er[6] or "{}")),
                created_at=datetime.fromisoformat(str(er[7])),
            )
            for er in reversed(ev_rows)
        ]

        receipts = _load_receipts_for_session_in_conn(conn, slug, sid, limit=25)
        focus_part = f"&focus={focus_snap.selected_node_id}" if focus_snap.selected_node_id else ""
        permalink = f"/#target={slug}&session={sid}{focus_part}&preset=iso_overview&zoom=1"
        return InvestigationSessionRead(
            session_id=sid,
            target_slug=slug,
            title=str(row[2]),
            follow_state=row[3] if row[3] in ("following", "paused") else "following",
            follow_reason=str(row[4] or ""),
            session_revision=int(row[5]),
            focus_revision=int(row[6]),
            participating_client_ids=json.loads(str(row[7] or "[]")),
            pinned_evidence=pinned_ev,
            latest_evidence=latest_ev,
            evidence_drifted=(
                pinned_ev.content_digest != latest_ev.content_digest
                or pinned_ev.evidence_revision_id != latest_ev.evidence_revision_id
            ),
            focus=focus_snap,
            turns=turns,
            unresolved_questions=[t for t in turns if t.status == "unresolved"],
            corrections=corrections,
            recent_receipts=receipts,
            recent_events=events,
            retention_policy=get_retention_policy(),
            permalink=permalink,
            created_at=datetime.fromisoformat(str(row[11])),
            updated_at=datetime.fromisoformat(str(row[12])),
        )
    finally:
        conn.close()


def sync_session_focus(
    *,
    session_id: str,
    target_slug: str,
    serialized_focus: dict[str, Any],
    client_id: str | None = None,
    actor: InvestigationActor = "human",
    follow_state_override: FollowState | None = None,
    evidence_identity: EvidenceIdentityRead | None = None,
    pinned_index: dict[str, Any] | None = None,
) -> tuple[int, FollowState, str | None]:
    """Persist per-session focus state safely in SQLite without clobbering sibling tabs."""
    sid = session_id.strip()
    now = utc_now()
    now_iso = now.isoformat()
    clean_client = (client_id or "").strip() or None
    wrote_fresh = bool(serialized_focus.pop("wrote_fresh_snapshot", False))

    with _INVESTIGATION_LOCK:
        conn = open_investigation_connection(create=True)
        assert conn is not None
        try:
            conn.execute("BEGIN IMMEDIATE")
            row = conn.execute(
                "SELECT target_slug, focus_revision, follow_state, participating_clients_json, "
                "focus_state_json, latest_evidence_json "
                "FROM investigation_sessions WHERE session_id = ?",
                (sid,),
            ).fetchone()
            if row is None:
                fallback_ev = evidence_identity or EvidenceIdentityRead(
                    evidence_revision_id=str(
                        serialized_focus.get("evidence_revision_id")
                        or f"ev_unscanned_{target_slug[:16]}"
                    ),
                    source_commit="unscanned",
                    content_digest="",
                    observed_at=now,
                    coverage_complete=True,
                    stack_profile="auto",
                )
                init_fstate: FollowState = follow_state_override or "following"
                focus_rev = int(serialized_focus.get("focus_revision") or 1)
                if wrote_fresh or (
                    serialized_focus.get("snapshot_path")
                    and serialized_focus.get("snapshot_focus_revision") is None
                ):
                    serialized_focus["snapshot_focus_revision"] = focus_rev
                if wrote_fresh or (
                    serialized_focus.get("snapshot_path")
                    and serialized_focus.get("snapshot_evidence_revision") is None
                ):
                    serialized_focus["snapshot_evidence_revision"] = fallback_ev.evidence_revision_id
                clients = [clean_client] if clean_client else []
                conn.execute(
                    "INSERT INTO investigation_sessions ("
                    "session_id, target_slug, title, follow_state, follow_reason, "
                    "session_revision, focus_revision, participating_clients_json, "
                    "pinned_evidence_json, pinned_index_json, latest_evidence_json, "
                    "focus_state_json, created_at, updated_at"
                    ") VALUES (?, ?, ?, ?, '', 0, ?, ?, ?, ?, ?, ?, ?, ?)",
                    (
                        sid,
                        target_slug,
                        f"Investigation · {target_slug}",
                        init_fstate,
                        focus_rev,
                        json.dumps(clients),
                        fallback_ev.model_dump_json(),
                        json.dumps(pinned_index or {}),
                        fallback_ev.model_dump_json(),
                        json.dumps(serialized_focus),
                        now_iso,
                        now_iso,
                    ),
                )
                _append_delta_in_tx(
                    conn,
                    session_id=sid,
                    event_kind="focus_updated",
                    actor=actor,
                    client_id=clean_client,
                    summary=f"Initialized focus on `{target_slug}` (rev={focus_rev}).",
                    payload={
                        "focus_revision": focus_rev,
                        "selected_node_id": serialized_focus.get("selected_node_id"),
                        "selected_finding_id": serialized_focus.get("selected_finding_id"),
                        "selected_edge_id": serialized_focus.get("selected_edge_id"),
                    },
                    now_iso=now_iso,
                )
                _enforce_session_retention_in_tx(conn)
                conn.execute("COMMIT")
                return focus_rev, init_fstate, fallback_ev.evidence_revision_id

            existing_slug = str(row[0])
            if existing_slug != target_slug:
                raise ValueError(
                    f"Investigation session `{sid}` belongs to target `{existing_slug}` "
                    f"and cannot sync focus onto `{target_slug}`."
                )
            prev_rev = int(row[1])
            cur_fstate: FollowState = (
                follow_state_override
                if follow_state_override in ("following", "paused")
                else (row[2] if row[2] in ("following", "paused") else "following")
            )
            clients = json.loads(str(row[3] or "[]"))
            if clean_client and clean_client not in clients:
                clients.append(clean_client)
            prev_focus = json.loads(str(row[4] or "{}"))
            latest_ev_dict = json.loads(str(row[5] or "{}"))
            eff_ev_json = (
                evidence_identity.model_dump_json()
                if evidence_identity is not None
                else str(row[5])
            )
            eff_ev_id = (
                evidence_identity.evidence_revision_id
                if evidence_identity is not None
                else (
                    serialized_focus.get("evidence_revision_id")
                    or latest_ev_dict.get("evidence_revision_id")
                )
            )
            selection_changed = any(
                serialized_focus.get(k) != prev_focus.get(k)
                for k in (
                    "active_slug",
                    "active_tab",
                    "selected_node_id",
                    "selected_edge_id",
                    "selected_finding_id",
                    "lens",
                    "layout_mode",
                )
            )
            next_focus_rev = prev_rev + 1
            if wrote_fresh:
                serialized_focus["snapshot_focus_revision"] = next_focus_rev
                serialized_focus["snapshot_evidence_revision"] = eff_ev_id
            else:
                serialized_focus.setdefault(
                    "snapshot_focus_revision", prev_focus.get("snapshot_focus_revision")
                )
                serialized_focus.setdefault(
                    "snapshot_evidence_revision", prev_focus.get("snapshot_evidence_revision")
                )

            if (
                pinned_index
                and str(latest_ev_dict.get("source_commit") or "") == "unscanned"
                and evidence_identity is not None
            ):
                conn.execute(
                    "UPDATE investigation_sessions SET pinned_evidence_json = ?, pinned_index_json = ? "
                    "WHERE session_id = ?",
                    (evidence_identity.model_dump_json(), json.dumps(pinned_index), sid),
                )

            conn.execute(
                "UPDATE investigation_sessions "
                "SET follow_state = ?, focus_revision = ?, "
                "participating_clients_json = ?, latest_evidence_json = ?, "
                "focus_state_json = ?, updated_at = ? WHERE session_id = ?",
                (
                    cur_fstate,
                    next_focus_rev,
                    json.dumps(clients[:32]),
                    eff_ev_json,
                    json.dumps(serialized_focus),
                    now_iso,
                    sid,
                ),
            )
            if selection_changed or follow_state_override is not None:
                _append_delta_in_tx(
                    conn,
                    session_id=sid,
                    event_kind="focus_updated",
                    actor=actor,
                    client_id=clean_client,
                    summary=(
                        f"Focus rev {next_focus_rev}: node={serialized_focus.get('selected_node_id')}, "
                        f"finding={serialized_focus.get('selected_finding_id')}, tab={serialized_focus.get('active_tab')}."
                    ),
                    payload={
                        "focus_revision": next_focus_rev,
                        "selected_node_id": serialized_focus.get("selected_node_id"),
                        "selected_edge_id": serialized_focus.get("selected_edge_id"),
                        "selected_finding_id": serialized_focus.get("selected_finding_id"),
                        "active_tab": serialized_focus.get("active_tab"),
                        "follow_state": cur_fstate,
                    },
                    now_iso=now_iso,
                )
            conn.execute("COMMIT")
            return next_focus_rev, cur_fstate, eff_ev_id
        finally:
            conn.close()


def list_session_corrections(session_id: str | None) -> list[InvestigationCorrectionRead]:
    if not session_id or not session_id.strip():
        return []
    conn = open_investigation_connection(create=False)
    if conn is None:
        return []
    try:
        rows = conn.execute(
            "SELECT correction_id, session_id, client_id, actor, target_ref_id, turn_id, "
            "kind, note, evidence_revision_id, promoted_to_ruling, created_at "
            "FROM investigation_corrections WHERE session_id = ? ORDER BY id ASC",
            (session_id.strip(),),
        ).fetchall()
        return [
            InvestigationCorrectionRead(
                correction_id=str(r[0]),
                session_id=str(r[1]),
                client_id=r[2],
                actor=r[3] if r[3] in ("human", "agent", "system") else "human",
                target_ref_id=r[4],
                turn_id=r[5],
                kind=str(r[6]),
                note=str(r[7]),
                evidence_revision_id=r[8],
                promoted_to_ruling=bool(r[9]),
                created_at=datetime.fromisoformat(str(r[10])),
            )
            for r in rows
        ]
    finally:
        conn.close()


def add_investigation_correction(
    session_id: str,
    payload: InvestigationCorrectionCreate,
) -> InvestigationCorrectionRead:
    """Record a human/agent correction without mutating or disabling governance rules."""
    sid = session_id.strip()
    now = utc_now()
    now_iso = now.isoformat()
    cid = f"corr_{uuid.uuid4().hex[:12]}"
    clean_client = (payload.client_id or "").strip() or None

    with _INVESTIGATION_LOCK:
        conn = open_investigation_connection(create=False)
        if conn is None:
            raise LookupError(f"Investigation session `{sid}` not found.")
        try:
            conn.execute("BEGIN IMMEDIATE")
            row = conn.execute(
                "SELECT latest_evidence_json, participating_clients_json "
                "FROM investigation_sessions WHERE session_id = ?",
                (sid,),
            ).fetchone()
            if row is None:
                raise LookupError(f"Investigation session `{sid}` not found.")
            latest_ev = json.loads(str(row[0] or "{}"))
            ev_rev_id = latest_ev.get("evidence_revision_id")
            clients = json.loads(str(row[1] or "[]"))
            if clean_client and clean_client not in clients:
                clients.append(clean_client)
                conn.execute(
                    "UPDATE investigation_sessions SET participating_clients_json = ? WHERE session_id = ?",
                    (json.dumps(clients[:32]), sid),
                )
            conn.execute(
                "INSERT INTO investigation_corrections ("
                "correction_id, session_id, client_id, actor, target_ref_id, turn_id, "
                "kind, note, evidence_revision_id, promoted_to_ruling, created_at"
                ") VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, 0, ?)",
                (
                    cid,
                    sid,
                    clean_client,
                    payload.actor,
                    payload.target_ref_id,
                    payload.turn_id,
                    payload.kind,
                    payload.note,
                    ev_rev_id,
                    now_iso,
                ),
            )
            _append_delta_in_tx(
                conn,
                session_id=sid,
                event_kind="correction_added",
                actor=payload.actor,
                client_id=clean_client,
                summary=f"Correction ({payload.kind}): {payload.note[:140]}",
                payload={
                    "correction_id": cid,
                    "target_ref_id": payload.target_ref_id,
                    "turn_id": payload.turn_id,
                    "kind": payload.kind,
                    "note": payload.note,
                    "promoted_to_ruling": False,
                },
                now_iso=now_iso,
            )
            conn.execute("COMMIT")
        finally:
            conn.close()
    return InvestigationCorrectionRead(
        correction_id=cid,
        session_id=sid,
        client_id=clean_client,
        actor=payload.actor,
        target_ref_id=payload.target_ref_id,
        turn_id=payload.turn_id,
        kind=payload.kind,
        note=payload.note,
        evidence_revision_id=ev_rev_id,
        promoted_to_ruling=False,
        created_at=now,
    )


def update_investigation_follow(
    session_id: str,
    payload: InvestigationFollowUpdate,
) -> InvestigationSessionRead:
    sid = session_id.strip()
    now_iso = utc_now().isoformat()
    clean_client = (payload.client_id or "").strip() or None
    with _INVESTIGATION_LOCK:
        conn = open_investigation_connection(create=False)
        if conn is None:
            raise LookupError(f"Investigation session `{sid}` not found.")
        try:
            conn.execute("BEGIN IMMEDIATE")
            row = conn.execute(
                "SELECT participating_clients_json FROM investigation_sessions WHERE session_id = ?",
                (sid,),
            ).fetchone()
            if row is None:
                raise LookupError(f"Investigation session `{sid}` not found.")
            clients = json.loads(str(row[0] or "[]"))
            if clean_client and clean_client not in clients:
                clients.append(clean_client)
            conn.execute(
                "UPDATE investigation_sessions "
                "SET follow_state = ?, follow_reason = ?, participating_clients_json = ?, updated_at = ? "
                "WHERE session_id = ?",
                (
                    payload.follow_state,
                    payload.reason,
                    json.dumps(clients[:32]),
                    now_iso,
                    sid,
                ),
            )
            _append_delta_in_tx(
                conn,
                session_id=sid,
                event_kind="follow_updated",
                actor=payload.actor,
                client_id=clean_client,
                summary=f"Follow state set to `{payload.follow_state}`"
                + (f" ({payload.reason})" if payload.reason else ""),
                payload={"follow_state": payload.follow_state, "reason": payload.reason},
                now_iso=now_iso,
            )
            conn.execute("COMMIT")
        finally:
            conn.close()
    out = get_investigation_session(sid)
    assert out is not None
    return out


def record_investigation_turn(
    db_session: Session | None,
    session_id: str,
    payload: InvestigationTurnCreate,
    *,
    report: TruthAtlasReport | None = None,
) -> InvestigationTurnRead:
    """Persist an answered or unresolved (`answer_markdown=None`) turn with validated citations."""
    sid = session_id.strip()
    now = utc_now()
    now_iso = now.isoformat()
    tid = f"turn_{uuid.uuid4().hex[:12]}"
    clean_client = (payload.client_id or "").strip() or None

    with _INVESTIGATION_LOCK:
        conn = open_investigation_connection(create=False)
        if conn is None:
            raise LookupError(f"Investigation session `{sid}` not found.")
        try:
            row = conn.execute(
                "SELECT target_slug, focus_revision, focus_state_json, "
                "pinned_index_json, latest_evidence_json, participating_clients_json "
                "FROM investigation_sessions WHERE session_id = ?",
                (sid,),
            ).fetchone()
        finally:
            conn.close()
        if row is None:
            raise LookupError(f"Investigation session `{sid}` not found.")

    slug = str(row[0])
    focus_rev = int(row[1])
    focus_d = json.loads(str(row[2] or "{}"))
    pinned_idx = json.loads(str(row[3] or "{}"))
    latest_ev_dict = json.loads(str(row[4] or "{}"))

    eff_report = report
    if eff_report is None and db_session is not None:
        target = get_target_by_slug(db_session, slug)
        if target is not None:
            eff_report = get_or_run_cached_scan(db_session, target)

    if eff_report is not None:
        ev_id = build_evidence_identity(eff_report).evidence_revision_id
    else:
        ev_id = str(latest_ev_dict.get("evidence_revision_id") or f"ev_unscanned_{slug[:16]}")

    sel_node = payload.selected_node_id or focus_d.get("selected_node_id")
    sel_edge = payload.selected_edge_id or focus_d.get("selected_edge_id")
    sel_finding = payload.selected_finding_id or focus_d.get("selected_finding_id")
    explicit_seed_ids = [
        x for x in (sel_node, sel_edge, sel_finding, *payload.referenced_ids) if x
    ]
    val_refs = validate_references_against_report(
        explicit_seed_ids,
        eff_report,
        evidence_revision_id=ev_id,
        pinned_index=pinned_idx,
        answer_markdown=payload.answer_markdown,
    )
    is_answered = bool(payload.answer_markdown and payload.answer_markdown.strip())
    turn_status = "answered" if is_answered else "unresolved"
    eff_authored = payload.authored_by if is_answered else "none"

    with _INVESTIGATION_LOCK:
        conn = open_investigation_connection(create=True)
        assert conn is not None
        try:
            conn.execute("BEGIN IMMEDIATE")
            clients = json.loads(str(row[5] or "[]"))
            if clean_client and clean_client not in clients:
                clients.append(clean_client)
                conn.execute(
                    "UPDATE investigation_sessions SET participating_clients_json = ? WHERE session_id = ?",
                    (json.dumps(clients[:32]), sid),
                )
            conn.execute(
                "INSERT INTO investigation_turns ("
                "turn_id, session_id, client_id, actor, question, answer_markdown, "
                "status, authored_by, engine, model_id, used_vision, image_supplied, "
                "fallback_reason, failure_reason, evidence_revision_id, focus_revision, "
                "selected_node_id, selected_edge_id, selected_finding_id, validated_refs_json, created_at"
                ") VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
                (
                    tid,
                    sid,
                    clean_client,
                    payload.actor,
                    payload.question.strip(),
                    payload.answer_markdown.strip() if is_answered and payload.answer_markdown else None,
                    turn_status,
                    eff_authored,
                    payload.engine,
                    payload.model_id,
                    1 if payload.used_vision else 0,
                    1 if payload.image_supplied else 0,
                    payload.fallback_reason,
                    payload.failure_reason,
                    ev_id,
                    focus_rev,
                    sel_node,
                    sel_edge,
                    sel_finding,
                    json.dumps([r.model_dump(mode="json") for r in val_refs]),
                    now_iso,
                ),
            )
            conn.execute(
                "DELETE FROM investigation_turns "
                "WHERE session_id = ? AND id <= COALESCE(("
                "SELECT id FROM investigation_turns WHERE session_id = ? "
                "ORDER BY id DESC LIMIT 1 OFFSET ?"
                "), 0)",
                (sid, sid, MAX_TURNS_PER_SESSION),
            )
            _append_delta_in_tx(
                conn,
                session_id=sid,
                event_kind="turn_recorded" if is_answered else "question_unresolved",
                actor=payload.actor,
                client_id=clean_client,
                summary=(
                    f"Turn `{tid}` answered via `{payload.engine or 'client'}`: {payload.question[:96]}"
                    if is_answered
                    else f"Preserved unresolved question `{tid}` ({payload.failure_reason or 'model unavailable'}): {payload.question[:96]}"
                ),
                payload={
                    "turn_id": tid,
                    "status": turn_status,
                    "engine": payload.engine,
                    "model_id": payload.model_id,
                    "evidence_revision_id": ev_id,
                },
                now_iso=now_iso,
            )
            conn.execute("COMMIT")
        finally:
            conn.close()

    return InvestigationTurnRead(
        turn_id=tid,
        session_id=sid,
        client_id=clean_client,
        actor=payload.actor,
        question=payload.question.strip(),
        answer_markdown=payload.answer_markdown.strip() if is_answered and payload.answer_markdown else None,
        status=turn_status,  # type: ignore[arg-type]
        authored_by=eff_authored,  # type: ignore[arg-type]
        engine=payload.engine,
        model_id=payload.model_id,
        used_vision=payload.used_vision,
        image_supplied=payload.image_supplied,
        fallback_reason=payload.fallback_reason,
        failure_reason=payload.failure_reason,
        evidence_revision_id=ev_id,
        focus_revision=focus_rev,
        selected_node_id=sel_node,
        selected_edge_id=sel_edge,
        selected_finding_id=sel_finding,
        validated_references=val_refs,
        needs_revalidation=False,
        created_at=now,
    )


def get_investigation_delta_events(
    session_id: str,
    *,
    since_revision: int = 0,
) -> InvestigationDeltaEventsResponse:
    sid = session_id.strip()
    conn = open_investigation_connection(create=False)
    if conn is None:
        raise LookupError(f"Investigation session `{sid}` not found.")
    try:
        head_row = conn.execute(
            "SELECT session_revision FROM investigation_sessions WHERE session_id = ?",
            (sid,),
        ).fetchone()
        if head_row is None:
            raise LookupError(f"Investigation session `{sid}` not found.")
        latest_rev = int(head_row[0])
        rows = conn.execute(
            "SELECT revision, session_id, event_kind, actor, client_id, summary, payload_json, created_at "
            "FROM investigation_events WHERE session_id = ? AND revision > ? ORDER BY revision ASC",
            (sid, max(0, since_revision)),
        ).fetchall()
        events = [
            InvestigationDeltaEventRead(
                revision=int(r[0]),
                session_id=str(r[1]),
                event_kind=str(r[2]),
                actor=r[3] if r[3] in ("human", "agent", "system") else "system",
                client_id=r[4],
                summary=str(r[5]),
                payload=json.loads(str(r[6] or "{}")),
                created_at=datetime.fromisoformat(str(r[7])),
            )
            for r in rows
        ]
        return InvestigationDeltaEventsResponse(
            session_id=sid,
            latest_revision=latest_rev,
            since_revision=max(0, since_revision),
            events=events,
        )
    finally:
        conn.close()


def compare_investigation_revisions(
    db_session: Session,
    session_id: str,
) -> InvestigationRevisionComparisonRead:
    """Compare pinned session evidence against a fresh current scan without rebinding vanished refs."""
    sid = session_id.strip()
    inv = get_investigation_session(sid)
    if inv is None:
        raise LookupError(f"Investigation session `{sid}` not found.")

    conn = open_investigation_connection(create=False)
    assert conn is not None
    try:
        idx_row = conn.execute(
            "SELECT pinned_index_json FROM investigation_sessions WHERE session_id = ?",
            (sid,),
        ).fetchone()
        pinned_idx = json.loads(str((idx_row[0] if idx_row else "{}") or "{}"))
    finally:
        conn.close()

    target = _resolve_target_or_raise(db_session, inv.target_slug)
    fresh_report = get_or_run_cached_scan(db_session, target, force_rescan=True)
    current_ev = build_evidence_identity(fresh_report)

    nodes_now = {n.id: n for n in fresh_report.nodes}
    edges_now = {e.id: e for e in fresh_report.edges}
    findings_now = {f.id: f for f in fresh_report.findings}
    pinned_nodes: dict[str, Any] = pinned_idx.get("nodes") or {}
    pinned_edges: dict[str, Any] = pinned_idx.get("edges") or {}
    pinned_findings: dict[str, Any] = pinned_idx.get("findings") or {}
    pinned_finding_matches, unmatched_cur_finding_ids = _match_pinned_findings_to_current(
        pinned_findings, fresh_report.findings
    )

    tracked_ids: list[str] = []

    def _track(val: str | None) -> None:
        if val and val not in tracked_ids:
            tracked_ids.append(val)

    _track(inv.focus.selected_node_id)
    _track(inv.focus.selected_edge_id)
    _track(inv.focus.selected_finding_id)
    for t in inv.turns:
        _track(t.selected_node_id)
        _track(t.selected_edge_id)
        _track(t.selected_finding_id)
        for ref in t.validated_references:
            _track(ref.ref_id)
    for c in inv.corrections:
        _track(c.target_ref_id)
    for nid in pinned_nodes:
        _track(nid)
    for fid in pinned_findings:
        _track(fid)

    surviving: list[ValidatedReferenceRead] = []
    vanished: list[ValidatedReferenceRead] = []
    modified: list[ValidatedReferenceRead] = []

    for ref_id in tracked_ids:
        if ref_id in nodes_now:
            n = nodes_now[ref_id]
            old_n = pinned_nodes.get(ref_id)
            cur_pfc = n.policy_field_consumption.state if n.policy_field_consumption else None
            changed = bool(
                old_n
                and (
                    old_n.get("status") != n.status
                    or old_n.get("line") != n.line
                    or old_n.get("pfc_state") != cur_pfc
                )
            )
            item = ValidatedReferenceRead(
                ref_id=n.id,
                kind="node",
                label=n.label,
                source_file=n.source_file,
                line=n.line,
                evidence_revision_id=current_ev.evidence_revision_id,
                validation_state="validated",
                epistemic_kind="static_inference",
                note=(
                    f"Modified since pinned scan (status `{old_n.get('status')}` -> `{n.status}`, "
                    f"policy `{old_n.get('pfc_state')}` -> `{cur_pfc}`)."
                    if changed and old_n
                    else "Unchanged in current scan."
                ),
            )
            (modified if changed else surviving).append(item)
        elif ref_id in edges_now:
            e = edges_now[ref_id]
            old_e = pinned_edges.get(ref_id)
            cur_pfc = e.policy_field_consumption.state if e.policy_field_consumption else None
            changed = bool(
                old_e
                and (
                    old_e.get("verification") != e.verification
                    or old_e.get("pfc_state") != cur_pfc
                )
            )
            item = ValidatedReferenceRead(
                ref_id=e.id,
                kind="edge",
                label=f"{e.source_id} -> {e.target_id}",
                source_file=e.evidence_path,
                evidence_revision_id=current_ev.evidence_revision_id,
                validation_state="validated",
                epistemic_kind="verified_result" if e.verification == "verified" else "static_inference",
                note="Modified edge verification/consumption." if changed else "Surviving edge.",
            )
            (modified if changed else surviving).append(item)
        elif ref_id in pinned_findings:
            old_f = pinned_findings[ref_id]
            matched_f = pinned_finding_matches.get(ref_id)
            if matched_f is not None:
                f_changed = bool(
                    old_f.get("line") != matched_f.line
                    or old_f.get("severity") != matched_f.severity
                    or old_f.get("title") != matched_f.title
                )
                f_item = ValidatedReferenceRead(
                    ref_id=ref_id,
                    kind="finding",
                    label=f"{matched_f.rule_code}: {matched_f.title}",
                    source_file=matched_f.source_file,
                    line=matched_f.line,
                    evidence_revision_id=current_ev.evidence_revision_id,
                    validation_state="validated",
                    epistemic_kind=_classify_finding_epistemic(matched_f.rule_code),
                    note=(
                        f"Finding shifted line/detail ({old_f.get('line')} -> {matched_f.line})."
                        if f_changed
                        else "Surviving finding matched semantically."
                    ),
                )
                (modified if f_changed else surviving).append(f_item)
            else:
                vanished.append(
                    ValidatedReferenceRead(
                        ref_id=ref_id,
                        kind="finding",
                        label=f"{old_f.get('rule_code')}: {old_f.get('title')}",
                        source_file=old_f.get("source_file"),
                        line=old_f.get("line"),
                        evidence_revision_id=current_ev.evidence_revision_id,
                        validation_state="vanished_in_current_scan",
                        epistemic_kind="static_inference",
                        note="Finding resolved or vanished in current scan; preserved from pinned snapshot without rebinding.",
                    )
                )
        elif ref_id in findings_now:
            f = findings_now[ref_id]
            surviving.append(
                ValidatedReferenceRead(
                    ref_id=f.id,
                    kind="finding",
                    label=f"{f.rule_code}: {f.title}",
                    source_file=f.source_file,
                    line=f.line,
                    evidence_revision_id=current_ev.evidence_revision_id,
                    validation_state="validated",
                    epistemic_kind=_classify_finding_epistemic(f.rule_code),
                )
            )
        elif (m_snip := _SNIPPET_PTR_RE.match(ref_id)) is not None:
            rel_p, line_s = m_snip.group(1), int(m_snip.group(2))
            repo_root = Path(fresh_report.repo_path).resolve()
            cand_f = repo_root / rel_p
            is_valid_file = False
            try:
                resolved_f = cand_f.resolve()
                is_valid_file = (
                    not cand_f.is_symlink()
                    and resolved_f.is_relative_to(repo_root)
                    and resolved_f.is_file()
                )
            except OSError:
                is_valid_file = False
            if is_valid_file:
                surviving.append(
                    ValidatedReferenceRead(
                        ref_id=ref_id,
                        kind="snippet",
                        label=ref_id,
                        source_file=rel_p,
                        line=line_s,
                        evidence_revision_id=current_ev.evidence_revision_id,
                        validation_state="validated",
                        epistemic_kind="observation",
                        note="Referenced file still present in current scan.",
                    )
                )
            else:
                vanished.append(
                    ValidatedReferenceRead(
                        ref_id=ref_id,
                        kind="snippet",
                        label=ref_id,
                        source_file=rel_p,
                        line=line_s,
                        evidence_revision_id=current_ev.evidence_revision_id,
                        validation_state="vanished_in_current_scan",
                        epistemic_kind="observation",
                        note="Referenced source file vanished in current scan.",
                    )
                )
        elif ref_id.startswith(("capture:", "ui_focus_", "wiretap:", "wt:wiretap:", "z3:")):
            surviving.append(
                ValidatedReferenceRead(
                    ref_id=ref_id,
                    kind="capture",
                    label=ref_id,
                    evidence_revision_id=current_ev.evidence_revision_id,
                    validation_state="validated",
                    epistemic_kind="runtime_capture",
                    note="Captured runtime/viewport artifact reference preserved.",
                )
            )
        else:
            old_n = pinned_nodes.get(ref_id)
            old_e = pinned_edges.get(ref_id)
            old_f = pinned_findings.get(ref_id)
            kind = "edge" if (old_e or ref_id.startswith("e:")) else ("finding" if (old_f or ref_id.startswith("f:")) else "node")
            lbl = (
                str(old_n.get("label"))
                if old_n
                else (
                    f"{old_e.get('source_id')} -> {old_e.get('target_id')}"
                    if old_e
                    else (f"{old_f.get('rule_code')}: {old_f.get('title')}" if old_f else ref_id)
                )
            )
            src_f = (old_n or old_e or old_f or {}).get("source_file") or (old_e or {}).get("evidence_path")
            src_ln = (old_n or old_f or {}).get("line")
            vanished.append(
                ValidatedReferenceRead(
                    ref_id=ref_id,
                    kind=kind,  # type: ignore[arg-type]
                    label=lbl,
                    source_file=src_f,
                    line=src_ln,
                    evidence_revision_id=current_ev.evidence_revision_id,
                    validation_state="vanished_in_current_scan",
                    epistemic_kind="static_inference",
                    note="Vanished in current scan; preserved from pinned snapshot without rebinding.",
                )
            )

    added_findings = sorted(unmatched_cur_finding_ids)
    resolved_findings = sorted(fid for fid in pinned_findings if fid not in pinned_finding_matches)
    digest_changed = (
        inv.pinned_evidence.content_digest != current_ev.content_digest
        or inv.pinned_evidence.evidence_revision_id != current_ev.evidence_revision_id
    )
    vanished_set = {v.ref_id for v in vanished}
    modified_set = {m.ref_id for m in modified}
    invalidated_turns = [
        t.turn_id
        for t in inv.turns
        if digest_changed
        or any(r.ref_id in (vanished_set | modified_set) for r in t.validated_references)
    ]

    with _INVESTIGATION_LOCK:
        conn2 = open_investigation_connection(create=False)
        if conn2 is not None:
            try:
                conn2.execute("BEGIN IMMEDIATE")
                conn2.execute(
                    "UPDATE investigation_sessions SET latest_evidence_json = ?, updated_at = ? WHERE session_id = ?",
                    (current_ev.model_dump_json(), utc_now().isoformat(), sid),
                )
                if digest_changed:
                    for t in inv.turns:
                        if t.evidence_revision_id == current_ev.evidence_revision_id:
                            continue
                        updated_refs: list[dict[str, Any]] = []
                        for r in t.validated_references:
                            if r.ref_id in vanished_set:
                                updated_refs.append(
                                    r.model_copy(
                                        update={
                                            "validation_state": "vanished_in_current_scan",
                                            "note": "Vanished in current scan; preserved without rebinding.",
                                        }
                                    ).model_dump(mode="json")
                                )
                            elif r.validation_state in ("validated", "text_convenience"):
                                updated_refs.append(
                                    r.model_copy(
                                        update={
                                            "validation_state": "historical_needs_revalidation",
                                            "note": (
                                                f"Historical explanation from {t.evidence_revision_id}; "
                                                f"revalidate against {current_ev.evidence_revision_id}."
                                            ),
                                        }
                                    ).model_dump(mode="json")
                                )
                            else:
                                updated_refs.append(r.model_dump(mode="json"))
                        conn2.execute(
                            "UPDATE investigation_turns SET validated_refs_json = ? WHERE turn_id = ?",
                            (json.dumps(updated_refs), t.turn_id),
                        )
                _append_delta_in_tx(
                    conn2,
                    session_id=sid,
                    event_kind="evidence_compared",
                    actor="system",
                    client_id=None,
                    summary=(
                        f"Compared pinned `{inv.pinned_evidence.evidence_revision_id}` -> "
                        f"`{current_ev.evidence_revision_id}` (digest_changed={digest_changed}, "
                        f"vanished={len(vanished)}, modified={len(modified)}, resolved_findings={len(resolved_findings)})."
                    ),
                    payload={
                        "pinned_evidence_revision_id": inv.pinned_evidence.evidence_revision_id,
                        "current_evidence_revision_id": current_ev.evidence_revision_id,
                        "digest_changed": digest_changed,
                        "vanished_ref_ids": [v.ref_id for v in vanished],
                        "resolved_finding_ids": resolved_findings,
                        "added_finding_ids": added_findings,
                    },
                )
                conn2.execute("COMMIT")
            finally:
                conn2.close()

    md_lines = [
        f"# Investigation Evidence Comparison :: `{sid}` (`{inv.target_slug}`)",
        (
            f"> Pinned: `{inv.pinned_evidence.evidence_revision_id}` (`{inv.pinned_evidence.content_digest[:12]}`) -> "
            f"Current: `{current_ev.evidence_revision_id}` (`{current_ev.content_digest[:12]}`) | "
            f"Digest changed: `{digest_changed}`"
        ),
        f"- **Surviving references**: {len(surviving)}",
        f"- **Modified references**: {len(modified)}"
        + (f" ({', '.join(f'`{m.ref_id}`' for m in modified[:8])})" if modified else ""),
        f"- **Vanished references (never rebound)**: {len(vanished)}"
        + (f" ({', '.join(f'`{v.ref_id}`' for v in vanished[:8])})" if vanished else ""),
        f"- **Resolved findings**: {len(resolved_findings)}"
        + (f" ({', '.join(f'`{fid}`' for fid in resolved_findings[:8])})" if resolved_findings else ""),
        f"- **Added findings**: {len(added_findings)}"
        + (f" ({', '.join(f'`{fid}`' for fid in added_findings[:8])})" if added_findings else ""),
    ]
    return InvestigationRevisionComparisonRead(
        session_id=sid,
        target_slug=inv.target_slug,
        pinned_evidence=inv.pinned_evidence,
        current_evidence=current_ev,
        digest_changed=digest_changed,
        surviving_refs=surviving,
        vanished_refs=vanished,
        modified_refs=modified,
        added_finding_ids=added_findings,
        resolved_finding_ids=resolved_findings,
        invalidated_turn_ids=invalidated_turns,
        summary_markdown="\n".join(md_lines),
    )


def export_investigation_session(
    db_session: Session,
    session_id: str,
) -> InvestigationExportBundle:
    inv = get_investigation_session(session_id)
    if inv is None:
        raise LookupError(f"Investigation session `{session_id.strip()}` not found.")
    comp: InvestigationRevisionComparisonRead | None = None
    if get_target_by_slug(db_session, inv.target_slug) is not None:
        comp = compare_investigation_revisions(db_session, inv.session_id)
        inv = get_investigation_session(session_id) or inv
    return InvestigationExportBundle(
        schema_version="1.0",
        exported_at=utc_now(),
        session=inv,
        comparison=comp,
    )


def reset_investigation_session(
    db_session: Session,
    session_id: str,
) -> InvestigationSessionRead:
    sid = session_id.strip()
    inv = get_investigation_session(sid)
    if inv is None:
        raise LookupError(f"Investigation session `{sid}` not found.")
    target = _resolve_target_or_raise(db_session, inv.target_slug)
    fresh_report = get_or_run_cached_scan(db_session, target, force_rescan=True)
    ev_identity = build_evidence_identity(fresh_report)
    pinned_idx = build_pinned_index(fresh_report)
    now_iso = utc_now().isoformat()

    with _INVESTIGATION_LOCK:
        conn = open_investigation_connection(create=False)
        assert conn is not None
        try:
            conn.execute("BEGIN IMMEDIATE")
            conn.execute("DELETE FROM investigation_turns WHERE session_id = ?", (sid,))
            conn.execute("DELETE FROM investigation_corrections WHERE session_id = ?", (sid,))
            conn.execute(
                "UPDATE investigation_sessions "
                "SET follow_state = 'following', follow_reason = '', focus_revision = 0, "
                "pinned_evidence_json = ?, pinned_index_json = ?, latest_evidence_json = ?, "
                "focus_state_json = ?, updated_at = ? WHERE session_id = ?",
                (
                    ev_identity.model_dump_json(),
                    json.dumps(pinned_idx),
                    ev_identity.model_dump_json(),
                    json.dumps({"active_slug": inv.target_slug, "updated_at": now_iso}),
                    now_iso,
                    sid,
                ),
            )
            _append_delta_in_tx(
                conn,
                session_id=sid,
                event_kind="session_reset",
                actor="human",
                client_id=None,
                summary=f"Reset investigation `{sid}` and repinned to `{ev_identity.evidence_revision_id}`.",
                payload={"evidence_revision_id": ev_identity.evidence_revision_id},
                now_iso=now_iso,
            )
            conn.execute("COMMIT")
        finally:
            conn.close()
    out = get_investigation_session(sid)
    assert out is not None
    return out


def delete_investigation_session(session_id: str) -> bool:
    sid = session_id.strip()
    with _INVESTIGATION_LOCK:
        conn = open_investigation_connection(create=False)
        if conn is None:
            return False
        try:
            conn.execute("BEGIN IMMEDIATE")
            cur = conn.execute("DELETE FROM investigation_sessions WHERE session_id = ?", (sid,))
            deleted = (cur.rowcount or 0) > 0
            if deleted:
                conn.execute("DELETE FROM investigation_turns WHERE session_id = ?", (sid,))
                conn.execute("DELETE FROM investigation_corrections WHERE session_id = ?", (sid,))
                conn.execute("DELETE FROM investigation_events WHERE session_id = ?", (sid,))
            conn.execute("COMMIT")
        finally:
            conn.close()
    if deleted:
        try:
            base_dir = resolve_state_base_dir()
            tok = sanitize_session_file_token(sid)
            for ext in (".webp", ".png", ".jpg"):
                (base_dir / f"ui_focus_session_{tok}{ext}").unlink(missing_ok=True)
        except ValueError:
            pass
    return deleted
