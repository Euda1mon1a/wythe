"""Loopback Agent -> Human 3D Viewport Choreography Bus (`viewport` & SSE)."""

from __future__ import annotations

import asyncio
import contextlib
import contextvars
import ipaddress
import json
import os
import socket
import sqlite3
import tempfile
import threading
import urllib.parse
import uuid
from collections.abc import AsyncIterator, Awaitable, Callable, Iterator
from dataclasses import dataclass
from datetime import UTC, datetime
from pathlib import Path
from typing import Final

import httpx

from app.core.clock import utc_now
from app.core.config import load_settings
from app.schemas.atlas import (
    ViewportCommand,
    ViewportCommandAck,
    ViewportCommandEvent,
    ViewportCommandReceiptCreate,
    ViewportCommandReceiptRead,
    ViewportDeliveryState,
    ViewportStateRead,
)

VIEWPORT_RING_MAXLEN: Final[int] = 64
VIEWPORT_QUEUE_MAXLEN: Final[int] = 64
DEFAULT_VIEWPORT_ORIGIN: Final[str] = "http://127.0.0.1:8780"
_SSE_POLL_INTERVAL_SEC: Final[float] = 0.06
_SSE_KEEPALIVE_SEC: Final[float] = 15.0
_HTTP_TIMEOUT_SEC: Final[float] = 5.0
_CGNAT_NET = ipaddress.ip_network("100.64.0.0/10")
_INIT_SCHEMA_LOCK = threading.Lock()
_INITIALIZED_INODES: set[tuple[str, int]] = set()


def _resolve_viewport_bus_db_path() -> Path:
    explicit_state = os.getenv("WYTHE_STATE_DIR") or os.getenv("TRUTH_ATLAS_STATE_DIR")
    if explicit_state:
        base_dir = Path(explicit_state).expanduser().resolve()
    else:
        settings = load_settings()
        db_url = settings.database_url
        if db_url.startswith("sqlite:///") and ":memory:" not in db_url:
            base_dir = Path(db_url.removeprefix("sqlite:///")).expanduser().resolve().parent
        elif ":memory:" in db_url:
            uid_suffix = str(os.getuid()) if hasattr(os, "getuid") else "local"
            base_dir = (Path(tempfile.gettempdir()) / f"wythe-ephemeral-viewport-{uid_suffix}").resolve()
        else:
            base_dir = settings.state_dir.expanduser().resolve()
    return base_dir / "viewport_bus.sqlite3"


def _open_bus_connection(db_path: Path, *, create: bool) -> sqlite3.Connection | None:
    if db_path.is_symlink():
        raise RuntimeError(f"Refusing symlinked viewport bus database: {db_path}")
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
    if cache_key not in _INITIALIZED_INODES:
        with _INIT_SCHEMA_LOCK:
            if cache_key not in _INITIALIZED_INODES:
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
                existing_cols = {
                    str(r[1]) for r in conn.execute("PRAGMA table_info(viewport_events)").fetchall()
                }
                for col, ddl in (
                    ("command_id", "TEXT"),
                    ("correlation_id", "TEXT"),
                    ("expected_evidence_revision", "TEXT"),
                    ("expires_at", "TEXT"),
                    ("delivery_state", "TEXT NOT NULL DEFAULT 'accepted_by_service'"),
                    ("applied_clients_json", "TEXT NOT NULL DEFAULT '[]'"),
                ):
                    if col not in existing_cols:
                        conn.execute(f"ALTER TABLE viewport_events ADD COLUMN {col} {ddl}")
                conn.execute(
                    "CREATE INDEX IF NOT EXISTS idx_viewport_events_target_seq "
                    "ON viewport_events (target_slug, seq)"
                )
                conn.execute(
                    "CREATE INDEX IF NOT EXISTS idx_viewport_events_cmd_id "
                    "ON viewport_events (command_id)"
                )
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
                try:
                    ino = db_path.stat().st_ino
                except OSError:
                    ino = 0
                _INITIALIZED_INODES.add((str(db_path), ino))
    return conn


def _resolve_host_ips(host: str) -> set[ipaddress.IPv4Address | ipaddress.IPv6Address]:
    clean_host = host.split("%", 1)[0]
    try:
        return {ipaddress.ip_address(clean_host)}
    except ValueError:
        pass
    try:
        infos = socket.getaddrinfo(host, None)
    except OSError:
        return set()
    resolved: set[ipaddress.IPv4Address | ipaddress.IPv6Address] = set()
    for info in infos:
        raw_addr = str(info[4][0]).split("%", 1)[0]
        try:
            resolved.add(ipaddress.ip_address(raw_addr))
        except ValueError:
            continue
    return resolved


def _validate_viewport_server_url(raw_url: str, *, allow_remote: bool) -> str:
    cleaned = raw_url.strip()
    parts = urllib.parse.urlsplit(cleaned)
    if parts.scheme not in ("http", "https") or not parts.netloc or not parts.hostname:
        raise ValueError(
            f"Invalid viewport server URL '{raw_url}'; expected http(s)://host[:port]."
        )
    host = parts.hostname
    ips = _resolve_host_ips(host)
    for ip in ips:
        if ip.is_link_local or ip.is_multicast or ip.is_unspecified:
            raise ValueError(
                f"Viewport server host '{host}' resolves to a link-local, multicast, or "
                f"unspecified address ({ip}) and cannot be targeted."
            )
    is_local_name = host == "localhost" or host.endswith(".localhost")
    is_local_ip = bool(ips) and all(
        (ip.is_loopback or ip.is_private or (isinstance(ip, ipaddress.IPv4Address) and ip in _CGNAT_NET))
        and not (ip.is_link_local or ip.is_multicast or ip.is_unspecified)
        for ip in ips
    )
    if not (is_local_name or is_local_ip) and not allow_remote:
        raise ValueError(
            f"Viewport server host '{host}' is not loopback or private; "
            "pass --allow-remote-viewport to publish to a remote host."
        )
    base_path = parts.path.rstrip("/")
    if base_path.endswith("/api/v1/viewport/command"):
        endpoint_path = base_path
    elif base_path.endswith("/api/v1/viewport"):
        endpoint_path = f"{base_path}/command"
    elif base_path.endswith("/api/v1"):
        endpoint_path = f"{base_path}/viewport/command"
    else:
        endpoint_path = f"{base_path}/api/v1/viewport/command"
    return f"{parts.scheme}://{parts.netloc}{endpoint_path}"


def _post_viewport_command_http(
    cmd: ViewportCommand,
    server_url: str,
    *,
    allow_remote: bool = False,
) -> ViewportCommandAck:
    endpoint_url = _validate_viewport_server_url(server_url, allow_remote=allow_remote)
    body = cmd.model_dump_json().encode("utf-8")
    try:
        with httpx.Client(
            trust_env=False,
            follow_redirects=False,
            timeout=_HTTP_TIMEOUT_SEC,
        ) as client:
            resp = client.post(
                endpoint_url,
                content=body,
                headers={"Content-Type": "application/json"},
            )
    except httpx.HTTPError as exc:
        raise RuntimeError(f"Viewport server unreachable at {endpoint_url}: {exc}") from exc
    if resp.status_code < 200 or resp.status_code >= 300:
        snippet = resp.text[:240].strip()
        raise RuntimeError(
            f"Viewport server at {endpoint_url} rejected command (HTTP {resp.status_code}): {snippet}"
        )
    return ViewportCommandAck.model_validate(resp.json())


def build_viewport_permalink(
    cmd: ViewportCommand,
    base_origin: str = DEFAULT_VIEWPORT_ORIGIN,
) -> str:
    """Build a canonical deterministic URL permalink omitting unset optional keys."""
    pairs: list[tuple[str, str]] = [
        ("target", urllib.parse.quote(cmd.target_slug, safe="")),
    ]
    if cmd.session_id:
        pairs.append(("session", urllib.parse.quote(cmd.session_id, safe="")))
    if cmd.focus_node_ids:
        dedup_nodes = list(dict.fromkeys(cmd.focus_node_ids))
        pairs.append(
            ("focus", ",".join(urllib.parse.quote(nid, safe="") for nid in dedup_nodes))
        )
    if cmd.highlight_edge_ids:
        dedup_edges = list(dict.fromkeys(cmd.highlight_edge_ids))
        pairs.append(
            ("edges", ",".join(urllib.parse.quote(eid, safe="") for eid in dedup_edges))
        )
    if cmd.lens is not None:
        pairs.append(("lens", urllib.parse.quote(cmd.lens, safe="")))
    if cmd.layout_mode is not None:
        pairs.append(("layout", urllib.parse.quote(cmd.layout_mode, safe="")))
    pairs.append(("preset", urllib.parse.quote(cmd.framing_preset, safe="")))
    if cmd.z_wythe_slice is not None:
        pairs.append(("z", urllib.parse.quote(cmd.z_wythe_slice, safe="")))
    pairs.append(("zoom", str(cmd.zoom_stratum)))
    if cmd.chronicle_timeline is not None:
        pairs.append(
            ("chronicle", urllib.parse.quote(cmd.chronicle_timeline.timeline_id, safe=""))
        )
        pairs.append(("phase", str(cmd.chronicle_timeline.active_phase_index)))
    if cmd.finding_id:
        pairs.append(("finding", urllib.parse.quote(cmd.finding_id, safe="")))
    if cmd.selected_node_id:
        pairs.append(("selected_node", urllib.parse.quote(cmd.selected_node_id, safe="")))
    if cmd.selected_edge_id:
        pairs.append(("selected_edge", urllib.parse.quote(cmd.selected_edge_id, safe="")))
    if cmd.tier_filter and cmd.tier_filter != "all":
        pairs.append(("tier", urllib.parse.quote(cmd.tier_filter, safe="")))
    if cmd.subkind_filter and cmd.subkind_filter != "all":
        pairs.append(("subkind", urllib.parse.quote(cmd.subkind_filter, safe="")))
    if cmd.edge_filter and cmd.edge_filter != "all":
        pairs.append(("edge_filter", urllib.parse.quote(cmd.edge_filter, safe="")))
    if cmd.only_flagged is True:
        pairs.append(("only_flagged", "1"))
    if cmd.isolate_cone is True:
        pairs.append(("isolate_cone", "1"))
    if cmd.connected_only is True:
        pairs.append(("connected_only", "1"))
    if cmd.neighborhood_hops in (1, 2):
        pairs.append(("hops", str(cmd.neighborhood_hops)))
    if cmd.search_query:
        pairs.append(("q", urllib.parse.quote(cmd.search_query, safe="")))
    if cmd.blast_mode and cmd.blast_mode != "off":
        pairs.append(("blast", urllib.parse.quote(cmd.blast_mode, safe="")))
        if cmd.diff_base_ref and cmd.blast_mode == "git":
            pairs.append(("base_ref", urllib.parse.quote(cmd.diff_base_ref, safe="")))
    if cmd.working_set_only is True:
        pairs.append(("working_set", "1"))
    if cmd.compact_visible is True:
        pairs.append(("compact", "1"))
    if cmd.flatten_2d is True:
        pairs.append(("flat2d", "1"))
    if cmd.group_by and cmd.group_by != "none":
        pairs.append(("group_by", urllib.parse.quote(cmd.group_by, safe="")))
    if cmd.active_tab and cmd.active_tab != "3d":
        pairs.append(("tab", urllib.parse.quote(cmd.active_tab, safe="")))

    fragment = "&".join(f"{key}={val}" for key, val in pairs)
    prefix = base_origin.rstrip("/") if base_origin else ""
    return f"{prefix}/#{fragment}"


def matches_viewport_scope(
    cmd: ViewportCommand,
    target_slug: str,
    subscriber_session_id: str | None = None,
) -> bool:
    """Return True when `cmd` belongs to `target_slug` and matches `subscriber_session_id`."""
    if cmd.target_slug != target_slug:
        return False
    norm_sub = (subscriber_session_id or "").strip() or None
    return cmd.session_id is None or cmd.session_id == norm_sub


def format_sse_viewport_event(event: ViewportCommandEvent) -> str:
    """Serialize a `ViewportCommandEvent` as a standard SSE frame."""
    return (
        f"id: {event.seq}\n"
        f"event: viewport_command\n"
        f"data: {event.model_dump_json()}\n\n"
    )


def _as_utc(dt: datetime) -> datetime:
    if dt.tzinfo is None:
        return dt.replace(tzinfo=UTC)
    return dt.astimezone(UTC)


def _effective_delivery_state(
    raw_state: str | None,
    expires_at_raw: str | datetime | None,
    now: datetime,
) -> ViewportDeliveryState:
    state: ViewportDeliveryState = (
        raw_state  # type: ignore[assignment]
        if raw_state
        in (
            "accepted_by_service",
            "waiting_for_follow",
            "applied_by_browser",
            "paused_by_human",
            "rejected",
            "stale",
            "expired",
        )
        else "accepted_by_service"
    )
    if expires_at_raw and state in ("accepted_by_service", "waiting_for_follow"):
        try:
            exp_dt = (
                expires_at_raw
                if isinstance(expires_at_raw, datetime)
                else datetime.fromisoformat(str(expires_at_raw))
            )
            if _as_utc(exp_dt) <= _as_utc(now):
                return "expired"
        except ValueError:
            pass
    return state


def _max_seq_for_target(db_path: Path, target_slug: str) -> int:
    conn = _open_bus_connection(db_path, create=False)
    if conn is None:
        return 0
    try:
        row = conn.execute(
            "SELECT COALESCE(MAX(seq), 0) FROM viewport_events WHERE target_slug = ?",
            (target_slug,),
        ).fetchone()
        return int(row[0] or 0) if row else 0
    finally:
        conn.close()


def _query_stored_events(
    db_path: Path,
    target_slug: str,
    session_id: str | None,
    *,
    since_seq: int = 0,
) -> list[ViewportCommandEvent]:
    conn = _open_bus_connection(db_path, create=False)
    if conn is None:
        return []
    try:
        rows = conn.execute(
            "SELECT seq, permalink, command_json, created_at, delivery_state, "
            "applied_clients_json, expires_at "
            "FROM viewport_events "
            "WHERE target_slug = ? AND seq > ? "
            "ORDER BY seq ASC",
            (target_slug, since_seq),
        ).fetchall()
    finally:
        conn.close()
    now = utc_now()
    events: list[ViewportCommandEvent] = []
    for raw_seq, permalink, command_json, created_at, raw_state, raw_clients, raw_exp in rows:
        cmd = ViewportCommand.model_validate_json(command_json)
        if matches_viewport_scope(cmd, target_slug, session_id):
            clients: list[str] = json.loads(str(raw_clients or "[]"))
            eff_state = _effective_delivery_state(raw_state, raw_exp or cmd.expires_at, now)
            synced_cmd = cmd.model_copy(
                update={"delivery_state": eff_state, "applied_by_client_ids": clients}
            )
            events.append(
                ViewportCommandEvent(
                    seq=int(raw_seq),
                    issued_at=datetime.fromisoformat(str(created_at)),
                    permalink=str(permalink),
                    delivery_state=eff_state,
                    applied_by_client_ids=clients,
                    command=synced_cmd,
                )
            )
    return events


@dataclass(eq=False)
class _ViewportSubscriber:
    db_path: Path
    target_slug: str
    session_id: str | None
    loop: asyncio.AbstractEventLoop
    wakeup: asyncio.Event
    closed: bool = False


class ViewportBus:
    """Cross-process SQLite IPC ring buffer and async SSE broadcaster for viewport commands."""

    def __init__(self, max_events: int = VIEWPORT_RING_MAXLEN) -> None:
        self._lock = threading.Lock()
        self._max_events = max_events
        self._subscribers: set[_ViewportSubscriber] = set()

    def clear_state(self, target_slug: str | None = None) -> None:
        db_path = _resolve_viewport_bus_db_path()
        with self._lock:
            conn = _open_bus_connection(db_path, create=False)
            if conn is not None:
                try:
                    conn.execute("BEGIN IMMEDIATE")
                    if target_slug is None:
                        conn.execute("DELETE FROM viewport_events")
                        conn.execute(
                            "DELETE FROM sqlite_sequence WHERE name = 'viewport_events'"
                        )
                    else:
                        conn.execute(
                            "DELETE FROM viewport_events WHERE target_slug = ?",
                            (target_slug.strip(),),
                        )
                    conn.execute("COMMIT")
                finally:
                    conn.close()

    def reset(self) -> None:
        self.clear_state(None)
        with self._lock:
            subs = list(self._subscribers)
            self._subscribers.clear()
        for sub in subs:
            sub.closed = True
            try:
                sub.loop.call_soon_threadsafe(sub.wakeup.set)
            except RuntimeError:
                pass

    def publish(
        self,
        cmd: ViewportCommand,
        *,
        base_origin: str = DEFAULT_VIEWPORT_ORIGIN,
        current_evidence_revision: str | None = None,
    ) -> ViewportCommandAck:
        from app.services.investigation_service import (
            append_session_delta_event,
            get_active_session_ids_for_target,
            get_session_follow_state,
            get_session_raw_focus_state,
        )

        db_path = _resolve_viewport_bus_db_path()
        issued_at = utc_now()
        eff_ev_rev = current_evidence_revision
        if eff_ev_rev is None and cmd.expected_evidence_revision:
            sid_lookup = cmd.session_id
            if not sid_lookup:
                active_sids = get_active_session_ids_for_target(cmd.target_slug)
                if len(active_sids) == 1:
                    sid_lookup = active_sids[0]
            if sid_lookup:
                raw_f = get_session_raw_focus_state(sid_lookup)
                if raw_f is not None:
                    eff_ev_rev = raw_f[3]
        fstate = get_session_follow_state(cmd.target_slug, cmd.session_id)

        with self._lock:
            conn = _open_bus_connection(db_path, create=True)
            assert conn is not None
            try:
                conn.execute("BEGIN IMMEDIATE")
                if cmd.correlation_id:
                    existing_row = conn.execute(
                        "SELECT seq, permalink, command_json, created_at, command_id, "
                        "delivery_state, applied_clients_json, expires_at "
                        "FROM viewport_events "
                        "WHERE target_slug = ? AND COALESCE(session_id, '') = COALESCE(?, '') "
                        "AND correlation_id = ? ORDER BY seq DESC LIMIT 1",
                        (cmd.target_slug, cmd.session_id, cmd.correlation_id),
                    ).fetchone()
                    if existing_row is not None:
                        conn.execute("COMMIT")
                        ex_seq = int(existing_row[0])
                        ex_plink = str(existing_row[1])
                        ex_cmd = ViewportCommand.model_validate_json(str(existing_row[2]))
                        ex_issued = datetime.fromisoformat(str(existing_row[3]))
                        ex_cid = str(existing_row[4] or ex_cmd.command_id)
                        ex_clients: list[str] = json.loads(str(existing_row[6] or "[]"))
                        ex_state = _effective_delivery_state(
                            existing_row[5], existing_row[7] or ex_cmd.expires_at, issued_at
                        )
                        synced_ex = ex_cmd.model_copy(
                            update={
                                "command_id": ex_cid,
                                "delivery_state": ex_state,
                                "applied_by_client_ids": ex_clients,
                            }
                        )
                        sub_cnt = sum(
                            1
                            for sub in self._subscribers
                            if sub.db_path == db_path
                            and matches_viewport_scope(synced_ex, sub.target_slug, sub.session_id)
                        )
                        return ViewportCommandAck(
                            seq=ex_seq,
                            command_id=ex_cid,
                            correlation_id=cmd.correlation_id,
                            issued_at=ex_issued,
                            target_slug=synced_ex.target_slug,
                            session_id=synced_ex.session_id,
                            permalink=ex_plink,
                            subscriber_count=sub_cnt,
                            delivery_state=ex_state,
                            applied_by_client_ids=ex_clients,
                            idempotent_replay=True,
                            command=synced_ex,
                        )

                matching_subs = [
                    sub
                    for sub in self._subscribers
                    if sub.db_path == db_path
                    and matches_viewport_scope(cmd, sub.target_slug, sub.session_id)
                ]
                if cmd.expires_at is not None and _as_utc(cmd.expires_at) <= _as_utc(issued_at):
                    init_state: ViewportDeliveryState = "expired"
                elif (
                    cmd.expected_evidence_revision
                    and eff_ev_rev
                    and cmd.expected_evidence_revision != eff_ev_rev
                ):
                    init_state = "stale"
                elif fstate == "paused":
                    init_state = "paused_by_human"
                elif matching_subs:
                    init_state = "waiting_for_follow"
                else:
                    init_state = "accepted_by_service"

                stored_cmd = cmd.model_copy(
                    update={"delivery_state": init_state, "applied_by_client_ids": []}
                )
                permalink = build_viewport_permalink(stored_cmd, base_origin=base_origin)
                cmd_json = stored_cmd.model_dump_json()
                exp_iso = stored_cmd.expires_at.isoformat() if stored_cmd.expires_at else None
                cur = conn.execute(
                    "INSERT INTO viewport_events ("
                    "target_slug, session_id, permalink, command_json, created_at, "
                    "command_id, correlation_id, expected_evidence_revision, expires_at, "
                    "delivery_state, applied_clients_json"
                    ") VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, '[]')",
                    (
                        stored_cmd.target_slug,
                        stored_cmd.session_id,
                        permalink,
                        cmd_json,
                        issued_at.isoformat(),
                        stored_cmd.command_id,
                        stored_cmd.correlation_id,
                        stored_cmd.expected_evidence_revision,
                        exp_iso,
                        init_state,
                    ),
                )
                seq = int(cur.lastrowid or 1)
                conn.execute(
                    "DELETE FROM viewport_events "
                    "WHERE target_slug = ? AND seq <= COALESCE(("
                    "SELECT seq FROM viewport_events WHERE target_slug = ? "
                    "ORDER BY seq DESC LIMIT 1 OFFSET ?"
                    "), 0)",
                    (stored_cmd.target_slug, stored_cmd.target_slug, self._max_events),
                )
                conn.execute("COMMIT")
            finally:
                conn.close()

        delta_sid = stored_cmd.session_id
        if not delta_sid:
            sids = get_active_session_ids_for_target(stored_cmd.target_slug)
            if len(sids) == 1:
                delta_sid = sids[0]
        if delta_sid:
            append_session_delta_event(
                delta_sid,
                event_kind="command_published",
                actor="agent",
                summary=f"Viewport command `{stored_cmd.command_id}` (seq={seq}) -> `{init_state}`.",
                payload={
                    "seq": seq,
                    "command_id": stored_cmd.command_id,
                    "correlation_id": stored_cmd.correlation_id,
                    "delivery_state": init_state,
                    "focus_node_ids": stored_cmd.focus_node_ids,
                },
            )

        delivered = 0
        if init_state not in ("stale", "expired", "rejected"):
            for sub in matching_subs:
                try:
                    sub.loop.call_soon_threadsafe(sub.wakeup.set)
                    delivered += 1
                except RuntimeError:
                    pass
        return ViewportCommandAck(
            seq=seq,
            command_id=stored_cmd.command_id,
            correlation_id=stored_cmd.correlation_id,
            issued_at=issued_at,
            target_slug=stored_cmd.target_slug,
            session_id=stored_cmd.session_id,
            permalink=permalink,
            subscriber_count=delivered,
            delivery_state=init_state,
            applied_by_client_ids=[],
            idempotent_replay=False,
            command=stored_cmd,
        )

    def get_state(
        self,
        target_slug: str,
        *,
        session_id: str | None = None,
        since_seq: int = 0,
    ) -> ViewportStateRead:
        db_path = _resolve_viewport_bus_db_path()
        norm_slug = target_slug.strip()
        norm_session = (session_id or "").strip() or None
        with self._lock:
            matching = _query_stored_events(db_path, norm_slug, norm_session, since_seq=0)
            sub_count = sum(
                1
                for sub in self._subscribers
                if sub.db_path == db_path
                and sub.target_slug == norm_slug
                and (norm_session is None or sub.session_id == norm_session)
            )
        latest = matching[-1] if matching else None
        history = [ev for ev in matching if ev.seq > since_seq]
        return ViewportStateRead(
            target_slug=norm_slug,
            session_id=norm_session,
            latest=latest,
            history=history,
            subscriber_count=sub_count,
        )

    async def stream_events(
        self,
        target_slug: str,
        *,
        session_id: str | None = None,
        since_seq: int = 0,
        once: bool = False,
        is_disconnected: Callable[[], Awaitable[bool]] | None = None,
    ) -> AsyncIterator[str]:
        db_path = _resolve_viewport_bus_db_path()
        norm_slug = target_slug.strip()
        norm_session = (session_id or "").strip() or None
        if once:
            with self._lock:
                replay = [
                    ev
                    for ev in _query_stored_events(
                        db_path, norm_slug, norm_session, since_seq=since_seq
                    )
                    if ev.delivery_state not in ("stale", "expired")
                ]
            if not replay:
                yield ": viewport-bus idle\n\n"
                return
            for ev in replay:
                yield format_sse_viewport_event(ev)
            return

        loop = asyncio.get_running_loop()
        sub = _ViewportSubscriber(
            db_path=db_path,
            target_slug=norm_slug,
            session_id=norm_session,
            loop=loop,
            wakeup=asyncio.Event(),
        )
        with self._lock:
            self._subscribers.add(sub)
            if since_seq == 0:
                replay = []
                last_sent_seq = _max_seq_for_target(db_path, norm_slug)
            else:
                replay = [
                    ev
                    for ev in _query_stored_events(
                        db_path, norm_slug, norm_session, since_seq=since_seq
                    )
                    if ev.delivery_state in ("accepted_by_service", "waiting_for_follow")
                ]
                last_sent_seq = max(since_seq, _max_seq_for_target(db_path, norm_slug))

        last_keepalive = loop.time()
        try:
            yield ": viewport-bus connected\n\n"
            for ev in replay:
                yield format_sse_viewport_event(ev)

            while not sub.closed:
                if is_disconnected is not None and await is_disconnected():
                    break
                try:
                    await asyncio.wait_for(sub.wakeup.wait(), timeout=_SSE_POLL_INTERVAL_SEC)
                    sub.wakeup.clear()
                except TimeoutError:
                    pass
                if sub.closed:
                    break
                with self._lock:
                    fresh = _query_stored_events(
                        db_path, norm_slug, norm_session, since_seq=last_sent_seq
                    )
                if fresh:
                    emitted_any = False
                    for ev in fresh:
                        if ev.seq > last_sent_seq:
                            last_sent_seq = ev.seq
                            if ev.delivery_state not in ("stale", "expired", "rejected"):
                                emitted_any = True
                                yield format_sse_viewport_event(ev)
                    if emitted_any:
                        last_keepalive = loop.time()
                    continue
                if is_disconnected is not None and await is_disconnected():
                    break
                now_mono = loop.time()
                if now_mono - last_keepalive >= _SSE_KEEPALIVE_SEC:
                    last_keepalive = now_mono
                    yield ": keepalive\n\n"
        finally:
            with self._lock:
                self._subscribers.discard(sub)


_VIEWPORT_BUS = ViewportBus()


@dataclass(frozen=True)
class _ViewportDeliveryConfig:
    server_url: str | None = None
    allow_remote: bool = False
    local_only: bool = False


_VIEWPORT_DELIVERY_SCOPE: contextvars.ContextVar[_ViewportDeliveryConfig | None] = (
    contextvars.ContextVar("wythe_viewport_delivery_scope", default=None)
)


@contextlib.contextmanager
def viewport_delivery_scope(
    *,
    server_url: str | None = None,
    allow_remote: bool = False,
    local_only: bool = False,
) -> Iterator[None]:
    """Bind viewport transport overrides across nested core and plugin MCP calls."""
    ctx_handle = _VIEWPORT_DELIVERY_SCOPE.set(
        _ViewportDeliveryConfig(
            server_url=server_url,
            allow_remote=allow_remote,
            local_only=local_only,
        )
    )
    try:
        yield
    finally:
        _VIEWPORT_DELIVERY_SCOPE.reset(ctx_handle)


def publish_viewport_command(
    cmd: ViewportCommand,
    *,
    base_origin: str = DEFAULT_VIEWPORT_ORIGIN,
    server_url: str | None = None,
    allow_remote: bool = False,
    local_only: bool = False,
    current_evidence_revision: str | None = None,
) -> ViewportCommandAck:
    """Publish a validated `ViewportCommand` via configured HTTP server or shared SQLite bus."""
    active_scope = _VIEWPORT_DELIVERY_SCOPE.get()
    eff_local_only = local_only or bool(active_scope and active_scope.local_only)
    eff_server_url = (
        server_url
        if server_url is not None
        else (active_scope.server_url if active_scope is not None else None)
    )
    eff_allow_remote = allow_remote or bool(active_scope and active_scope.allow_remote)
    if not eff_local_only:
        configured_url = (
            eff_server_url.strip()
            if eff_server_url is not None
            else (os.getenv("WYTHE_SERVER_URL") or os.getenv("TRUTH_ATLAS_SERVER_URL") or "").strip()
        )
        if configured_url:
            env_allow = os.getenv("WYTHE_ALLOW_REMOTE_VIEWPORT", "").strip().lower() in (
                "1",
                "true",
                "yes",
            )
            return _post_viewport_command_http(
                cmd,
                configured_url,
                allow_remote=(eff_allow_remote or env_allow),
            )
    return _VIEWPORT_BUS.publish(
        cmd,
        base_origin=base_origin,
        current_evidence_revision=current_evidence_revision,
    )


def record_viewport_receipt(
    payload: ViewportCommandReceiptCreate,
) -> ViewportCommandReceiptRead:
    """Record a browser application/pause/rejection receipt and update `delivery_state` in SQLite."""
    from app.services.investigation_service import (
        append_session_delta_event,
        get_active_session_ids_for_target,
        get_investigation_session,
    )

    db_path = _resolve_viewport_bus_db_path()
    now = utc_now()
    now_iso = now.isoformat()
    receipt_id = f"rcpt_{uuid.uuid4().hex[:12]}"
    clean_client = payload.client_id.strip()
    clean_slug = payload.target_slug.strip()
    clean_cmd_id = payload.command_id.strip()
    req_sid = (payload.session_id or "").strip() or None

    with _VIEWPORT_BUS._lock:
        conn = _open_bus_connection(db_path, create=True)
        assert conn is not None
        try:
            conn.execute("BEGIN IMMEDIATE")
            if clean_cmd_id:
                row = conn.execute(
                    "SELECT seq, session_id, command_json, delivery_state, applied_clients_json "
                    "FROM viewport_events WHERE command_id = ? AND target_slug = ? "
                    "ORDER BY seq DESC LIMIT 1",
                    (clean_cmd_id, clean_slug),
                ).fetchone()
                if row is None:
                    raise LookupError(
                        f"Viewport command `{clean_cmd_id}` not found for target `{clean_slug}`."
                    )
            elif payload.seq is not None:
                row = conn.execute(
                    "SELECT seq, session_id, command_json, delivery_state, applied_clients_json "
                    "FROM viewport_events WHERE seq = ? AND target_slug = ?",
                    (payload.seq, clean_slug),
                ).fetchone()
                if row is None:
                    raise LookupError(
                        f"Viewport event seq={payload.seq} not found for target `{clean_slug}`."
                    )
            else:
                raise ValueError("Viewport receipt requires `command_id` or `seq`.")

            ev_seq = int(row[0])
            if payload.seq is not None and ev_seq != int(payload.seq):
                raise ValueError(
                    f"Contradictory viewport receipt identity for `{clean_cmd_id}`: "
                    f"stored seq={ev_seq} does not match supplied seq={payload.seq}."
                )

            cmd_obj = ViewportCommand.model_validate_json(str(row[2]))
            ev_sid = (str(row[1]).strip() if row[1] is not None else "") or (
                (cmd_obj.session_id or "").strip() or None
            )
            if ev_sid is not None and req_sid != ev_sid:
                raise ValueError(
                    f"Viewport command `{clean_cmd_id}` belongs to session `{ev_sid}`, "
                    f"not `{req_sid or 'unscoped'}`."
                )
            if ev_sid is None and req_sid is not None:
                existing_inv = get_investigation_session(req_sid)
                if existing_inv is not None and existing_inv.target_slug != clean_slug:
                    raise ValueError(
                        f"Session `{req_sid}` belongs to target `{existing_inv.target_slug}`, "
                        f"not `{clean_slug}`."
                    )

            prev_state = str(row[3] or "accepted_by_service")
            clients: list[str] = json.loads(str(row[4] or "[]"))

            if payload.outcome == "applied":
                new_state: ViewportDeliveryState = "applied_by_browser"
                if clean_client not in clients:
                    clients.append(clean_client)
            elif payload.outcome == "paused_by_human":
                new_state = "applied_by_browser" if prev_state == "applied_by_browser" else "paused_by_human"
            elif payload.outcome == "stale_revision":
                new_state = "stale"
            else:
                new_state = "rejected"

            updated_cmd = cmd_obj.model_copy(
                update={
                    "delivery_state": new_state,
                    "applied_by_client_ids": clients,
                }
            )
            conn.execute(
                "UPDATE viewport_events "
                "SET delivery_state = ?, applied_clients_json = ?, command_json = ? "
                "WHERE seq = ? AND target_slug = ?",
                (
                    new_state,
                    json.dumps(clients[:32]),
                    updated_cmd.model_dump_json(),
                    ev_seq,
                    clean_slug,
                ),
            )
            eff_sid = ev_sid or req_sid
            conn.execute(
                "INSERT INTO viewport_receipts ("
                "receipt_id, command_id, seq, target_slug, session_id, client_id, "
                "outcome, delivery_state, applied_focus_revision, note, recorded_at"
                ") VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
                (
                    receipt_id,
                    updated_cmd.command_id,
                    ev_seq,
                    clean_slug,
                    eff_sid,
                    clean_client,
                    payload.outcome,
                    new_state,
                    payload.applied_focus_revision,
                    payload.note,
                    now_iso,
                ),
            )
            conn.execute("COMMIT")
        finally:
            if conn.in_transaction:
                conn.execute("ROLLBACK")
            conn.close()

    delta_sid = eff_sid
    if not delta_sid:
        sids = get_active_session_ids_for_target(clean_slug)
        if len(sids) == 1:
            delta_sid = sids[0]
    if delta_sid:
        append_session_delta_event(
            delta_sid,
            event_kind="command_receipt",
            actor="human",
            client_id=clean_client,
            summary=(
                f"Client `{clean_client}` reported `{payload.outcome}` for `{updated_cmd.command_id}` "
                f"-> `{new_state}`."
            ),
            payload={
                "receipt_id": receipt_id,
                "command_id": updated_cmd.command_id,
                "seq": ev_seq,
                "client_id": clean_client,
                "outcome": payload.outcome,
                "delivery_state": new_state,
                "applied_by_client_ids": clients,
                "applied_focus_revision": payload.applied_focus_revision,
            },
        )

    return ViewportCommandReceiptRead(
        receipt_id=receipt_id,
        command_id=updated_cmd.command_id,
        seq=ev_seq,
        target_slug=clean_slug,
        session_id=eff_sid,
        client_id=clean_client,
        outcome=payload.outcome,
        delivery_state=new_state,
        applied_by_client_ids=clients,
        applied_focus_revision=payload.applied_focus_revision,
        note=payload.note,
        recorded_at=now,
    )


def list_viewport_receipts(
    *,
    target_slug: str | None = None,
    session_id: str | None = None,
    command_id: str | None = None,
    limit: int = 50,
) -> list[ViewportCommandReceiptRead]:
    db_path = _resolve_viewport_bus_db_path()
    conn = _open_bus_connection(db_path, create=False)
    if conn is None:
        return []
    try:
        clauses: list[str] = []
        params: list[object] = []
        if target_slug and target_slug.strip():
            clauses.append("r.target_slug = ?")
            params.append(target_slug.strip())
        if session_id and session_id.strip():
            clauses.append("(r.session_id IS NULL OR r.session_id = ?)")
            params.append(session_id.strip())
        if command_id and command_id.strip():
            clauses.append("r.command_id = ?")
            params.append(command_id.strip())
        where_sql = f"WHERE {' AND '.join(clauses)} " if clauses else ""
        params.append(max(1, min(200, limit)))
        rows = conn.execute(
            "SELECT r.receipt_id, r.command_id, r.seq, r.target_slug, r.session_id, "
            "r.client_id, r.outcome, r.delivery_state, r.applied_focus_revision, r.note, r.recorded_at, "
            "COALESCE(e.applied_clients_json, '[]') "
            "FROM viewport_receipts r "
            "LEFT JOIN viewport_events e ON e.command_id = r.command_id AND e.target_slug = r.target_slug "
            f"{where_sql}"
            "ORDER BY r.id DESC LIMIT ?",
            tuple(params),
        ).fetchall()
        return [
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
            for r in reversed(rows)
        ]
    finally:
        conn.close()


def get_viewport_state(
    target_slug: str,
    *,
    session_id: str | None = None,
    since_seq: int = 0,
) -> ViewportStateRead:
    """Read latest command and buffered history for `(target_slug, session_id)`."""
    return _VIEWPORT_BUS.get_state(
        target_slug,
        session_id=session_id,
        since_seq=since_seq,
    )


def clear_viewport_state(target_slug: str | None = None) -> None:
    """Clear shared viewport command history (for `target_slug` or all targets)."""
    _VIEWPORT_BUS.clear_state(target_slug)


def stream_viewport_events(
    target_slug: str,
    *,
    session_id: str | None = None,
    since_seq: int = 0,
    once: bool = False,
    is_disconnected: Callable[[], Awaitable[bool]] | None = None,
) -> AsyncIterator[str]:
    """Stream SSE `viewport_command` events scoped by `target_slug` and `session_id`."""
    return _VIEWPORT_BUS.stream_events(
        target_slug,
        session_id=session_id,
        since_seq=since_seq,
        once=once,
        is_disconnected=is_disconnected,
    )


def reset_viewport_bus() -> None:
    """Clear shared viewport bus history and close active streams (for test isolation)."""
    _VIEWPORT_BUS.reset()
