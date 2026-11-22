"""Opt-in live HTTP probe that confirms or clears unbacked frontend calls (DISP-004 / DISP-007).

Routing runs before authentication in FastAPI/Starlette, Express and most frameworks, so a
bare request tells a missing path (404) from an existing one (401/403/405/...). The probe:

- only sends GET requests, never a write method, with no credentials or request body;
- drops any cookie a response sets, never follows redirects, and pauses between requests;
- only targets loopback/private hosts unless the caller explicitly allows a remote host;
- first requests a path that cannot exist and refuses to conclude anything unless it gets 404
  (an auth wall or catch-all route would otherwise make every path look missing or present).
"""

from __future__ import annotations

import ipaddress
import secrets
import socket
import time
from dataclasses import replace
from typing import Any
from urllib.parse import urlsplit

import httpcore
import httpx

from app.adapters.base import RawCandidateFinding

_PROBED_RULES = frozenset({"DISP-004", "DISP-007"})
_PROBE_LIMIT = 200
_PAUSE_SECONDS = 0.02
_TIMEOUT_SECONDS = 3.0
_SEGMENT_PLACEHOLDER = "wythe-probe"
_EXISTS_CODES = frozenset({200, 201, 202, 204, 301, 302, 303, 307, 308, 400, 401, 403, 409, 422})
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


def _resolve_host_ips(host: str) -> list[ipaddress.IPv4Address | ipaddress.IPv6Address]:
    """Parse a literal IP or resolve DNS records for `host`."""
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


def _ip_is_local_or_private(ip: ipaddress.IPv4Address | ipaddress.IPv6Address) -> bool:
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


def _validate_and_resolve_probe_host(host: str, *, allow_remote: bool) -> tuple[bool, tuple[str, ...]]:
    """Validate target host and return `(is_local, pinned_ips)`."""
    if "%" in host:
        raise ValueError(f"--probe-url host '{host}' contains an unsupported IPv6 zone identifier")
    ips = _resolve_host_ips(host)
    for ip in ips:
        unwrapped = _iter_unwrapped_ips(ip)
        for addr in unwrapped:
            if _is_blocked_ip_single(addr):
                raise ValueError(
                    f"--probe-url host '{host}' resolves to a blocked metadata, reserved, or "
                    f"link-local, multicast, or unspecified address ({ip}) and cannot be probed"
                )
        if isinstance(ip, ipaddress.IPv6Address) and (
            ip.sixtofour is not None or ip.teredo is not None
        ):
            for addr in unwrapped:
                if isinstance(addr, ipaddress.IPv4Address) and any(
                    addr in net for net in _ALLOWED_LOCAL_V4_NETS
                ):
                    raise ValueError(
                        f"--probe-url host '{host}' tunnels a private/loopback IPv4 address "
                        f"via 6to4/Teredo ({ip}) and cannot be probed"
                    )
    is_local = bool(ips) and all(_ip_is_local_or_private(ip) for ip in ips)
    if not is_local and not allow_remote:
        raise ValueError(
            f"--probe-url host '{host}' is not loopback or private; "
            "pass --probe-allow-remote to probe it anyway"
        )
    return is_local, tuple(str(ip) for ip in ips)


def _validate_probe_host(host: str, *, allow_remote: bool) -> bool:
    """Validate target host and return True when the host is local/private."""
    is_local, _ = _validate_and_resolve_probe_host(host, allow_remote=allow_remote)
    return is_local


def _concrete_path(path: str) -> str:
    return path.replace("{param}", _SEGMENT_PLACEHOLDER)


def _join(base_url: str, path: str) -> str:
    cleaned_base = base_url.strip()
    base_auth_prefix = cleaned_base.split("?", 1)[0].split("#", 1)[0]
    if "\\" in base_auth_prefix:
        raise ValueError("--probe-url must not contain backslashes in URL authority")
    parts = urlsplit(cleaned_base)
    if parts.scheme.lower() not in ("http", "https") or not parts.hostname:
        raise ValueError("--probe-url must be an absolute http(s) URL")
    if parts.username is not None or parts.password is not None:
        raise ValueError("--probe-url must not include userinfo credentials")
    try:
        base_port = parts.port
    except ValueError as exc:
        raise ValueError("--probe-url has an invalid port") from exc
    host = parts.hostname.lower()
    netloc = f"[{host}]" if ":" in host and not host.startswith("[") else host
    if base_port is not None:
        netloc = f"{netloc}:{base_port}"
    base_canon = urlsplit(f"{parts.scheme.lower()}://{netloc}{parts.path}")

    raw_path = path.strip()
    if (
        not raw_path
        or not raw_path.startswith("/")
        or raw_path.startswith("//")
        or "\\" in raw_path
        or any(ord(ch) <= 0x20 or ord(ch) == 0x7F for ch in raw_path)
    ):
        raise ValueError(
            f"Invalid probe route_path '{path}': must start with a single '/' and contain no authority/control chars"
        )
    base_path = base_canon.path.rstrip("/")
    full = (
        raw_path
        if base_path and (raw_path == base_path or raw_path.startswith(base_path + "/"))
        else base_path + raw_path
    )
    if not full.startswith("/") or full.startswith("//"):
        raise ValueError(f"Invalid joined probe path '{full}'")
    joined_url = f"{base_canon.scheme}://{base_canon.netloc}{full}"
    joined = urlsplit(joined_url)
    if (
        (joined.scheme, joined.netloc, joined.hostname, joined.port)
        != (base_canon.scheme, base_canon.netloc, base_canon.hostname, base_canon.port)
        or joined.username is not None
        or joined.password is not None
        or not joined.path.startswith("/")
        or joined.path.startswith("//")
    ):
        raise ValueError(f"Probe route_path '{path}' attempted authority or port pivot")
    return joined_url


def _get_status(client: httpx.Client, url: str) -> int | None:
    try:
        with client.stream("GET", url, headers={"Accept-Encoding": "identity"}) as resp:
            return resp.status_code
    except httpx.HTTPError:
        return None
    finally:
        client.cookies.clear()


def _interpret(method: str, status: int | None) -> tuple[str, str]:
    """Return (plain-language verdict, kind) where kind is confirmed|likely|cleared|inconclusive."""
    if status is None:
        return "no answer (timeout or connection error); inconclusive.", "inconclusive"
    if method == "GET":
        if status == 404:
            return "GET returned 404; the path does not exist (confirmed).", "confirmed"
        if status == 405:
            return "GET returned 405; the path exists but not for GET (confirmed method mismatch).", "confirmed"
        if status in _EXISTS_CODES:
            return f"GET returned {status}; a route answers at this path, so the static matcher missed it.", "cleared"
        return f"GET returned {status}; inconclusive.", "inconclusive"
    if status == 404:
        likely = (
            f"GET on the same path returned 404 (the {method} itself was not sent). On FastAPI/Starlette, "
            "Django and Go 1.22+ that means no route exists at this path for any method; frameworks "
            "that answer 404 for a wrong method cannot tell."
        )
        return likely, "likely"
    if status == 405 or status in _EXISTS_CODES:
        unverified = (
            f"GET on the same path returned {status}; the path exists, but the {method} handler was not "
            "verified (the probe never sends writes)."
        )
        return unverified, "inconclusive"
    return f"GET on the same path returned {status}; inconclusive.", "inconclusive"


def apply_live_route_probe(
    findings: list[RawCandidateFinding],
    base_url: str,
    *,
    allow_remote: bool = False,
    client: httpx.Client | None = None,
) -> tuple[list[RawCandidateFinding], str]:
    """Probe each unbacked call once and annotate, confirm, or clear its finding.

    `base_url` is the URL the frontend's API paths are relative to (for example
    `http://127.0.0.1:8000`). Returns the adjusted findings and a one-line summary note.
    """
    cleaned = base_url.strip()
    authority_prefix = cleaned.split("?", 1)[0].split("#", 1)[0]
    if "\\" in authority_prefix:
        raise ValueError("--probe-url must not contain backslashes in URL authority")
    parts = urlsplit(cleaned)
    if parts.scheme not in ("http", "https") or not parts.hostname:
        raise ValueError("--probe-url must be an absolute http(s) URL")
    try:
        port = parts.port
    except ValueError as exc:
        raise ValueError("--probe-url has an invalid port") from exc
    host_l = parts.hostname.lower()
    netloc = f"[{host_l}]" if ":" in host_l and not host_l.startswith("[") else host_l
    if port is not None:
        netloc = f"{netloc}:{port}"
    sanitized_base = f"{parts.scheme.lower()}://{netloc}{parts.path}"
    is_local, pinned_ips = _validate_and_resolve_probe_host(host_l, allow_remote=allow_remote)

    targets = [f for f in findings if f.rule_code in _PROBED_RULES and f.http_path]
    if not targets:
        return findings, "Live route probe: no unbacked calls to check."

    own_client = client is None
    if client is not None:
        http = client
    else:
        if not pinned_ips:
            raise ValueError(f"--probe-url host '{host_l}' could not be resolved")
        transport = httpx.HTTPTransport()
        pool = getattr(transport, "_pool", None)
        if isinstance(pool, httpcore.ConnectionPool):
            pool._network_backend = _PinnedSyncBackend(pinned_ips)
        http = httpx.Client(
            transport=transport,
            timeout=_TIMEOUT_SECONDS,
            follow_redirects=False,
            trust_env=not is_local,
            headers={"User-Agent": "wythe-route-probe", "Accept-Encoding": "identity"},
        )
    results: dict[tuple[str, str], int | None] = {}
    try:
        control_status = _get_status(http, _join(sanitized_base, f"/__wythe_probe_absent_{secrets.token_hex(6)}"))
        if control_status != 404:
            answered = "no answer" if control_status is None else f"HTTP {control_status}"
            return findings, (
                f"Live route probe skipped: a path that cannot exist got {answered}, so a 404 would not "
                "prove anything (an auth layer, proxy, or catch-all route answers first)."
            )
        for f in targets:
            key = (f.http_method or "GET", f.http_path or "")
            if key in results or len(results) >= _PROBE_LIMIT:
                continue
            try:
                probe_target_url = _join(sanitized_base, _concrete_path(key[1]))
            except ValueError:
                results[key] = None
                continue
            results[key] = _get_status(http, probe_target_url)
            time.sleep(_PAUSE_SECONDS)
    finally:
        if own_client:
            http.close()

    counts = {"confirmed": 0, "likely": 0, "cleared": 0, "inconclusive": 0}
    adjusted: list[RawCandidateFinding] = []
    for f in findings:
        key = (f.http_method or "GET", f.http_path or "")
        if f.rule_code not in _PROBED_RULES or key not in results:
            adjusted.append(f)
            continue
        verdict, kind = _interpret(key[0], results[key])
        counts[kind] += 1
        if kind == "cleared":
            adjusted.append(
                replace(
                    f,
                    rule_code="DISP-006",
                    title=f"Frontend `{key[0]} {key[1]}` is answered by the running backend; static matching missed it",
                    detail=f"{f.detail} Live probe: {verdict}",
                    remediation="Check how this route is mounted (prefix, sub-app, or proxy) so static matching can see it.",
                )
            )
        else:
            adjusted.append(replace(f, detail=f"{f.detail} Live probe: {verdict}"))

    skipped = sum(1 for f in targets if (f.http_method or "GET", f.http_path or "") not in results)
    note = (
        f"Live route probe ({len(results)} GET request(s)): {counts['confirmed']} confirmed missing, "
        f"{counts['likely']} likely missing, {counts['cleared']} answered by a live route (moved to DISP-006), "
        f"{counts['inconclusive']} inconclusive"
        + (f"; {skipped} not probed (limit {_PROBE_LIMIT})." if skipped else ".")
    )
    return adjusted, note
