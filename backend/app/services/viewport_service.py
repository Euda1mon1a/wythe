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
import time
import urllib.parse
import uuid
from collections.abc import AsyncIterator, Awaitable, Callable, Iterator
from dataclasses import dataclass
from datetime import UTC, datetime
from pathlib import Path
from typing import Any, Final

import httpcore
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
VIEWPORT_RECEIPTS_MAXLEN: Final[int] = 256
DEFAULT_VIEWPORT_ORIGIN: Final[str] = "http://127.0.0.1:8780"
_SSE_POLL_INTERVAL_SEC: Final[float] = 0.06
_SSE_KEEPALIVE_SEC: Final[float] = 15.0
_HTTP_TIMEOUT_SEC: Final[float] = 5.0
_MAX_VIEWPORT_RESPONSE_BYTES: Final[int] = 1 * 1024 * 1024
_ALLOWED_LOCAL_V4_NETS = (
    ipaddress.ip_network("127.0.0.0/8"),
    ipaddress.ip_network("10.0.0.0/8"),
    ipaddress.ip_network("172.16.0.0/12"),
    ipaddress.ip_network("192.168.0.0/16"),
    ipaddress.ip_network("100.64.0.0/10"),
)
_ALLOWED_LOCAL_V6_NETS = (
    ipaddress.ip_network("::1/128"),
    ipaddress.ip_network("fc00::/7"),
)
_BLOCKED_METADATA_V4_NETS = (
    ipaddress.ip_network("0.0.0.0/8"),
    ipaddress.ip_network("100.100.100.200/32"),
    ipaddress.ip_network("169.254.169.254/32"),
)
_BLOCKED_METADATA_V6_NETS = (
    ipaddress.ip_network("fd00:ec2::/32"),
    ipaddress.ip_network("fec0::/10"),
)
_INIT_SCHEMA_LOCK = threading.Lock()
_INITIALIZED_INODES: set[tuple[str, int]] = set()


class _PinnedSyncBackend(httpcore.SyncBackend):
    def __init__(self, pinned_ips: tuple[str, ...]) -> None:
        super().__init__()
        self._pinned_ips = pinned_ips

    def connect_tcp(
        self,
        host: str,
        port: int,
        timeout: float | None = None,
        local_address: str | None = None,
        socket_options: Any = None,
    ) -> httpcore.NetworkStream:
        last_exc: Exception | None = None
        for ip_str in self._pinned_ips:
            try:
                return super().connect_tcp(
                    ip_str,
                    port,
                    timeout=timeout,
                    local_address=local_address,
                    socket_options=socket_options,
                )
            except (OSError, httpcore.ConnectError, httpcore.ConnectTimeout) as exc:
                last_exc = exc
        if last_exc is not None:
            raise last_exc
        raise httpcore.ConnectError(f"No pinned IP available for {host}")


def _ensure_json_nesting_bounded(raw_text: str, *, max_depth: int = 128) -> None:
    depth = 0
    in_str = False
    esc = False
    for ch in raw_text:
        if in_str:
            if esc:
                esc = False
            elif ch == "\\":
                esc = True
            elif ch == '"':
                in_str = False
            continue
        if ch == '"':
            in_str = True
        elif ch in "{[":
            depth += 1
            if depth > max_depth:
                raise ValueError(f"JSON payload exceeds maximum nesting depth ({max_depth}).")
        elif ch in "}]" and depth > 0:
            depth -= 1


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
                conn.execute(
                    "CREATE INDEX IF NOT EXISTS idx_viewport_receipts_target_id "
                    "ON viewport_receipts (target_slug, id)"
                )
                try:
                    ino = db_path.stat().st_ino
                except OSError:
                    ino = 0
                _INITIALIZED_INODES.add((str(db_path), ino))
    return conn


def _is_blocked_ip_single(addr: ipaddress.IPv4Address | ipaddress.IPv6Address) -> bool:
    if (
        addr.is_link_local
        or addr.is_multicast
        or addr.is_unspecified
        or (addr.is_reserved and not addr.is_loopback)
    ):
        return True
    if isinstance(addr, ipaddress.IPv4Address):
        return any(addr in net for net in _BLOCKED_METADATA_V4_NETS)
    return any(addr in net for net in _BLOCKED_METADATA_V6_NETS)


def _iter_unwrapped_ips(
    ip: ipaddress.IPv4Address | ipaddress.IPv6Address,
    *,
    _depth: int = 0,
) -> tuple[ipaddress.IPv4Address | ipaddress.IPv6Address, ...]:
    if _depth > 8 or not isinstance(ip, ipaddress.IPv6Address):
        return (ip,)
    out: list[ipaddress.IPv4Address | ipaddress.IPv6Address] = [ip]
    if ip.ipv4_mapped is not None:
        out.extend(_iter_unwrapped_ips(ip.ipv4_mapped, _depth=_depth + 1))
    if ip.sixtofour is not None:
        out.extend(_iter_unwrapped_ips(ip.sixtofour, _depth=_depth + 1))
    if ip.teredo is not None:
        srv_v4, cli_v4 = ip.teredo
        out.extend(_iter_unwrapped_ips(srv_v4, _depth=_depth + 1))
        out.extend(_iter_unwrapped_ips(cli_v4, _depth=_depth + 1))
    return tuple(dict.fromkeys(out))


def _unwrap_ip(ip: ipaddress.IPv4Address | ipaddress.IPv6Address) -> ipaddress.IPv4Address | ipaddress.IPv6Address:
    if isinstance(ip, ipaddress.IPv6Address):
        if ip.ipv4_mapped is not None:
            return _unwrap_ip(ip.ipv4_mapped)
        if ip.sixtofour is not None:
            return _unwrap_ip(ip.sixtofour)
        if ip.teredo is not None:
            srv_v4, cli_v4 = ip.teredo
            u_srv = _unwrap_ip(srv_v4)
            u_cli = _unwrap_ip(cli_v4)
            if _is_blocked_ip_single(u_srv):
                return u_srv
            if _is_blocked_ip_single(u_cli):
                return u_cli
            if isinstance(u_srv, ipaddress.IPv4Address) and any(
                u_srv in net for net in _ALLOWED_LOCAL_V4_NETS
            ):
                return u_srv
            return u_cli
    return ip


def _is_allowed_local_ip(ip: ipaddress.IPv4Address | ipaddress.IPv6Address) -> bool:
    unwrapped = _iter_unwrapped_ips(ip)
    if any(_is_blocked_ip_single(addr) for addr in unwrapped):
        return False
    if isinstance(ip, ipaddress.IPv6Address) and (
        ip.sixtofour is not None or ip.teredo is not None
    ):
        return False
    eff = _unwrap_ip(ip)
    if isinstance(eff, ipaddress.IPv4Address):
        return any(eff in net for net in _ALLOWED_LOCAL_V4_NETS)
    return any(eff in net for net in _ALLOWED_LOCAL_V6_NETS)


def _resolve_host_ips(host: str) -> list[ipaddress.IPv4Address | ipaddress.IPv6Address]:
    if "%" in host:
        return []
    try:
        return [ipaddress.ip_address(host)]
    except ValueError:
        pass
    try:
        infos = socket.getaddrinfo(host, None, type=socket.SOCK_STREAM)
    except OSError:
        return []
    resolved: list[ipaddress.IPv4Address | ipaddress.IPv6Address] = []
    seen: set[ipaddress.IPv4Address | ipaddress.IPv6Address] = set()
    for info in infos:
        raw_addr = str(info[4][0]).split("%", 1)[0]
        try:
            ip_obj = ipaddress.ip_address(raw_addr)
        except ValueError:
            continue
        if ip_obj not in seen:
            seen.add(ip_obj)
            resolved.append(ip_obj)
    return resolved


def _validate_and_resolve_viewport_server_url(
    raw_url: str, *, allow_remote: bool
) -> tuple[str, tuple[str, ...]]:
    cleaned = raw_url.strip()
    authority_prefix = cleaned.split("?", 1)[0].split("#", 1)[0]
    if "\\" in authority_prefix:
        raise ValueError(
            f"Invalid viewport server URL '{raw_url}'; backslashes are forbidden in URL authority."
        )
    parts = urllib.parse.urlsplit(cleaned)
    if parts.scheme not in ("http", "https") or not parts.netloc or not parts.hostname:
        raise ValueError(
            f"Invalid viewport server URL '{raw_url}'; expected http(s)://host[:port]."
        )
    try:
        port = parts.port
    except ValueError as exc:
        raise ValueError(
            f"Invalid viewport server URL '{raw_url}'; invalid port."
        ) from exc
    host = parts.hostname.lower()
    if "%" in host:
        raise ValueError(
            f"Viewport server host '{host}' contains an unsupported IPv6 zone identifier."
        )
    ips = _resolve_host_ips(host)
    if not ips:
        raise ValueError(
            f"Viewport server host '{host}' could not be resolved to an IP address."
        )
    for ip in ips:
        unwrapped = _iter_unwrapped_ips(ip)
        for addr in unwrapped:
            if _is_blocked_ip_single(addr):
                raise ValueError(
                    f"Viewport server host '{host}' resolves to a cloud metadata, link-local, "
                    f"multicast, unspecified, or reserved address ({ip}) and cannot be targeted."
                )
        if isinstance(ip, ipaddress.IPv6Address) and (
            ip.sixtofour is not None or ip.teredo is not None
        ):
            for addr in unwrapped:
                if isinstance(addr, ipaddress.IPv4Address) and any(
                    addr in net for net in _ALLOWED_LOCAL_V4_NETS
                ):
                    raise ValueError(
                        f"Viewport server host '{host}' tunnels a private/loopback IPv4 address "
                        f"via 6to4/Teredo ({ip}) and cannot be targeted."
                    )
    is_local_ip = all(_is_allowed_local_ip(ip) for ip in ips)
    if not is_local_ip and not allow_remote:
        raise ValueError(
            f"Viewport server host '{host}' is not loopback or private; "
            "pass --allow-remote-viewport to publish to a remote host."
        )
    netloc = f"[{host}]" if ":" in host and not host.startswith("[") else host
    if port is not None:
        netloc = f"{netloc}:{port}"
    base_path = parts.path.rstrip("/")
    if base_path.endswith("/api/v1/viewport/command"):
        endpoint_path = base_path
    elif base_path.endswith("/api/v1/viewport"):
        endpoint_path = f"{base_path}/command"
    elif base_path.endswith("/api/v1"):
        endpoint_path = f"{base_path}/viewport/command"
    else:
        endpoint_path = f"{base_path}/api/v1/viewport/command"
    return f"{parts.scheme.lower()}://{netloc}{endpoint_path}", tuple(str(ip) for ip in ips)


def _validate_viewport_server_url(raw_url: str, *, allow_remote: bool) -> str:
    endpoint_url, _ = _validate_and_resolve_viewport_server_url(raw_url, allow_remote=allow_remote)
    return endpoint_url


def _post_viewport_command_http(
    cmd: ViewportCommand,
    server_url: str,
    *,
    allow_remote: bool = False,
) -> ViewportCommandAck:
    endpoint_url, pinned_ips = _validate_and_resolve_viewport_server_url(
        server_url, allow_remote=allow_remote
    )
    body = cmd.model_dump_json().encode("utf-8")
    transport = httpx.HTTPTransport()
    pool = getattr(transport, "_pool", None)
    if isinstance(pool, httpcore.ConnectionPool) and pinned_ips:
        pool._network_backend = _PinnedSyncBackend(pinned_ips)
    deadline = time.monotonic() + _HTTP_TIMEOUT_SEC
    try:
        with (
            httpx.Client(
                transport=transport,
                trust_env=False,
                follow_redirects=False,
                timeout=_HTTP_TIMEOUT_SEC,
            ) as client,
            client.stream(
                "POST",
                endpoint_url,
                content=body,
                headers={"Content-Type": "application/json", "Accept-Encoding": "identity"},
            ) as resp,
        ):
            enc = (resp.headers.get("content-encoding") or "").strip().lower()
            if enc and enc != "identity":
                raise RuntimeError(
                    f"Viewport server at {endpoint_url} returned disallowed Content-Encoding `{enc}`."
                )
            raw_cl = resp.headers.get("content-length")
            if raw_cl:
                try:
                    if int(raw_cl) > _MAX_VIEWPORT_RESPONSE_BYTES:
                        raise RuntimeError(
                            f"Viewport server response declared Content-Length {raw_cl} exceeding "
                            f"{_MAX_VIEWPORT_RESPONSE_BYTES} byte safety limit."
                        )
                except ValueError:
                    pass
            buf = bytearray()
            if time.monotonic() > deadline:
                raise TimeoutError(
                    f"Viewport server response from {endpoint_url} exceeded {_HTTP_TIMEOUT_SEC}s deadline."
                )
            for chunk in resp.iter_raw():
                if time.monotonic() > deadline:
                    raise TimeoutError(
                        f"Viewport server response from {endpoint_url} exceeded {_HTTP_TIMEOUT_SEC}s deadline."
                    )
                buf.extend(chunk)
                if len(buf) > _MAX_VIEWPORT_RESPONSE_BYTES:
                    raise RuntimeError(
                        f"Viewport server response from {endpoint_url} exceeded "
                        f"{_MAX_VIEWPORT_RESPONSE_BYTES} byte safety limit."
                    )
            status_code = resp.status_code
            raw_bytes = bytes(buf)
    except (httpx.HTTPError, TimeoutError) as exc:
        raise RuntimeError(f"Viewport server unreachable at {endpoint_url}: {exc}") from exc
    if status_code < 200 or status_code >= 300:
        snippet = raw_bytes.decode("utf-8", errors="replace")[:240].strip()
        raise RuntimeError(
            f"Viewport server at {endpoint_url} rejected command (HTTP {status_code}): {snippet}"
        )
    try:
        decoded_body = raw_bytes.decode("utf-8", errors="replace")
        _ensure_json_nesting_bounded(decoded_body)
        parsed = json.loads(decoded_body)
    except (ValueError, RecursionError) as exc:
        raise RuntimeError(f"Viewport server at {endpoint_url} returned invalid JSON.") from exc
    if not isinstance(parsed, dict):
        raise RuntimeError(  # noqa: TRY004
            f"Viewport server at {endpoint_url} returned unexpected non-object JSON."
        )
    return ViewportCommandAck.model_validate(parsed)


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
    if expires_at_raw and state in ("accepted_by_service", "waiting_for_follow", "paused_by_human"):
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


def _query_stored_events_from_conn(
    conn: sqlite3.Connection,
    target_slug: str,
    session_id: str | None,
    *,
    since_seq: int = 0,
) -> list[ViewportCommandEvent]:
    rows = conn.execute(
        "SELECT seq, permalink, command_json, created_at, delivery_state, "
        "applied_clients_json, expires_at "
        "FROM viewport_events "
        "WHERE target_slug = ? AND seq > ? "
        "ORDER BY seq ASC",
        (target_slug, since_seq),
    ).fetchall()
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
        return _query_stored_events_from_conn(
            conn, target_slug, session_id, since_seq=since_seq
        )
    finally:
        conn.close()


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
                        conn.execute("DELETE FROM viewport_receipts")
                        conn.execute(
                            "DELETE FROM sqlite_sequence WHERE name IN ('viewport_events', 'viewport_receipts')"
                        )
                    else:
                        clean_slug = target_slug.strip()
                        conn.execute(
                            "DELETE FROM viewport_events WHERE target_slug = ?",
                            (clean_slug,),
                        )
                        conn.execute(
                            "DELETE FROM viewport_receipts WHERE target_slug = ?",
                            (clean_slug,),
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
            get_investigation_session,
            get_session_follow_state,
            get_session_raw_focus_state,
        )

        for check_sid in dict.fromkeys(
            sid for sid in (cmd.session_id, cmd.refresh_session_id) if sid
        ):
            existing_inv = get_investigation_session(check_sid)
            if existing_inv is not None and existing_inv.target_slug != cmd.target_slug:
                raise ValueError(
                    f"Session `{check_sid}` belongs to target `{existing_inv.target_slug}`, "
                    f"not `{cmd.target_slug}`."
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

    def _poll_stored_events(
        self,
        db_path: Path,
        target_slug: str,
        session_id: str | None,
        since_seq: int,
    ) -> list[ViewportCommandEvent]:
        with self._lock:
            return _query_stored_events(
                db_path, target_slug, session_id, since_seq=since_seq
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
            def _load_once_replay() -> list[ViewportCommandEvent]:
                with self._lock:
                    return [
                        ev
                        for ev in _query_stored_events(
                            db_path, norm_slug, norm_session, since_seq=since_seq
                        )
                        if ev.delivery_state not in ("stale", "expired")
                    ]

            replay = await asyncio.to_thread(_load_once_replay)
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

        def _subscribe_and_load() -> tuple[list[ViewportCommandEvent], int]:
            with self._lock:
                self._subscribers.add(sub)
                conn = _open_bus_connection(db_path, create=False)
                if conn is None:
                    return [], since_seq
                try:
                    conn.execute("BEGIN")
                    row = conn.execute(
                        "SELECT COALESCE(MAX(seq), 0) FROM viewport_events WHERE target_slug = ?",
                        (norm_slug,),
                    ).fetchone()
                    max_seq = int(row[0] or 0) if row else 0
                    if since_seq == 0:
                        replay_events: list[ViewportCommandEvent] = []
                        baseline = max_seq
                    else:
                        replay_events = [
                            ev
                            for ev in _query_stored_events_from_conn(
                                conn, norm_slug, norm_session, since_seq=since_seq
                            )
                            if ev.delivery_state
                            in ("accepted_by_service", "waiting_for_follow", "paused_by_human")
                        ]
                        baseline = max(since_seq, max_seq)
                    conn.execute("COMMIT")
                    return replay_events, baseline
                finally:
                    with contextlib.suppress(sqlite3.Error):
                        if conn.in_transaction:
                            conn.execute("ROLLBACK")
                    conn.close()

        def _unsubscribe() -> None:
            with self._lock:
                self._subscribers.discard(sub)

        try:
            replay, last_sent_seq = await asyncio.to_thread(_subscribe_and_load)
            last_keepalive = loop.time()
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
                fresh = await asyncio.to_thread(
                    self._poll_stored_events,
                    db_path,
                    norm_slug,
                    norm_session,
                    last_sent_seq,
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
            sub.closed = True
            unsubscribed = False
            try:
                await asyncio.to_thread(_unsubscribe)
                unsubscribed = True
            except RuntimeError:
                _unsubscribe()
                unsubscribed = True
            finally:
                if not unsubscribed:
                    _unsubscribe()


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
    clean_client = (payload.client_id or "").strip()
    clean_slug = (payload.target_slug or "").strip()
    clean_cmd_id = (payload.command_id or "").strip()
    req_sid = (payload.session_id or "").strip() or None
    if not clean_cmd_id:
        raise ValueError("Viewport receipt requires a non-empty `command_id`.")
    if not clean_client:
        raise ValueError("Viewport receipt requires a non-empty `client_id`.")
    if not clean_slug:
        raise ValueError("Viewport receipt requires a non-empty `target_slug`.")

    with _VIEWPORT_BUS._lock:
        conn = _open_bus_connection(db_path, create=True)
        assert conn is not None
        try:
            conn.execute("BEGIN IMMEDIATE")
            if payload.seq is not None:
                row = conn.execute(
                    "SELECT seq, session_id, command_json, delivery_state, "
                    "applied_clients_json, expires_at "
                    "FROM viewport_events WHERE command_id = ? AND target_slug = ? AND seq = ?",
                    (clean_cmd_id, clean_slug, int(payload.seq)),
                ).fetchone()
                if row is None:
                    any_cmd = conn.execute(
                        "SELECT seq FROM viewport_events WHERE command_id = ? AND target_slug = ? "
                        "ORDER BY seq DESC LIMIT 1",
                        (clean_cmd_id, clean_slug),
                    ).fetchone()
                    if any_cmd is not None:
                        raise ValueError(
                            f"Contradictory viewport receipt identity for `{clean_cmd_id}`: "
                            f"stored seq={int(any_cmd[0])} does not match supplied seq={payload.seq}."
                        )
                    raise LookupError(
                        f"Viewport command `{clean_cmd_id}` not found for target `{clean_slug}`."
                    )
            else:
                row = conn.execute(
                    "SELECT seq, session_id, command_json, delivery_state, "
                    "applied_clients_json, expires_at "
                    "FROM viewport_events WHERE command_id = ? AND target_slug = ? "
                    "ORDER BY seq DESC LIMIT 1",
                    (clean_cmd_id, clean_slug),
                ).fetchone()
                if row is None:
                    raise LookupError(
                        f"Viewport command `{clean_cmd_id}` not found for target `{clean_slug}`."
                    )

            ev_seq = int(row[0])
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

            prev_state = _effective_delivery_state(
                str(row[3] or "accepted_by_service"),
                row[5] or cmd_obj.expires_at,
                now,
            )
            clients: list[str] = json.loads(str(row[4] or "[]"))

            if payload.outcome == "applied":
                if prev_state in ("expired", "stale", "rejected"):
                    raise ValueError(
                        f"Cannot apply viewport command `{clean_cmd_id}` in `{prev_state}` state."
                    )
                new_state: ViewportDeliveryState = "applied_by_browser"
                if clean_client not in clients:
                    clients.append(clean_client)
            elif payload.outcome == "paused_by_human":
                if prev_state in ("expired", "stale", "rejected"):
                    raise ValueError(
                        f"Cannot pause viewport command `{clean_cmd_id}` in `{prev_state}` state."
                    )
                new_state = (
                    "applied_by_browser" if prev_state == "applied_by_browser" else "paused_by_human"
                )
            elif payload.outcome == "stale_revision":
                new_state = (
                    prev_state
                    if prev_state in ("expired", "rejected", "applied_by_browser")
                    else "stale"
                )
            else:
                new_state = (
                    prev_state
                    if prev_state in ("expired", "stale", "applied_by_browser")
                    else "rejected"
                )

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
                "DELETE FROM viewport_receipts "
                "WHERE target_slug = ? AND COALESCE(session_id, '') = COALESCE(?, '') "
                "AND command_id = ? AND COALESCE(seq, -1) = COALESCE(?, -1) AND client_id = ?",
                (clean_slug, eff_sid, updated_cmd.command_id, ev_seq, clean_client),
            )
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
            conn.execute(
                "DELETE FROM viewport_receipts "
                "WHERE target_slug = ? AND id <= COALESCE(("
                "SELECT id FROM viewport_receipts WHERE target_slug = ? "
                "ORDER BY id DESC LIMIT 1 OFFSET ?"
                "), 0)",
                (clean_slug, clean_slug, VIEWPORT_RECEIPTS_MAXLEN),
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
    seq: int | None = None,
    limit: int = 50,
) -> list[ViewportCommandReceiptRead]:
    clean_slug = target_slug.strip() if (target_slug and target_slug.strip()) else None
    clean_sid = session_id.strip() if (session_id and session_id.strip()) else None
    if clean_sid is not None:
        from app.services.investigation_service import get_investigation_session

        inv_sess = get_investigation_session(clean_sid)
        if inv_sess is not None:
            if clean_slug is not None and inv_sess.target_slug != clean_slug:
                return []
            clean_slug = clean_slug or inv_sess.target_slug
        elif clean_slug is None:
            # Browser-only or evicted session without an explicit target_slug must not bleed across targets.
            return []

    db_path = _resolve_viewport_bus_db_path()
    conn = _open_bus_connection(db_path, create=False)
    if conn is None:
        return []
    try:
        clauses: list[str] = []
        params: list[object] = []
        if clean_slug:
            clauses.append("r.target_slug = ?")
            params.append(clean_slug)
        if clean_sid:
            clauses.append("r.session_id = ?")
            params.append(clean_sid)
        if command_id and command_id.strip():
            clauses.append("r.command_id = ?")
            params.append(command_id.strip())
        if seq is not None:
            clauses.append("r.seq = ?")
            params.append(int(seq))
        where_sql = f"WHERE {' AND '.join(clauses)} " if clauses else ""
        params.append(max(1, min(200, limit)))
        rows = conn.execute(
            "SELECT r.receipt_id, r.command_id, r.seq, r.target_slug, r.session_id, "
            "r.client_id, r.outcome, r.delivery_state, r.applied_focus_revision, r.note, r.recorded_at, "
            "COALESCE(e.applied_clients_json, '[]') "
            "FROM viewport_receipts r "
            "LEFT JOIN viewport_events e "
            "  ON e.target_slug = r.target_slug "
            " AND e.command_id = r.command_id "
            " AND (r.seq IS NULL OR e.seq = r.seq) "
            " AND (e.session_id IS NULL OR r.session_id IS NULL OR e.session_id = r.session_id) "
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
