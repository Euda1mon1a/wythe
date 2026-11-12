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
from urllib.parse import urlsplit

import httpx

from app.adapters.base import RawCandidateFinding

_PROBED_RULES = frozenset({"DISP-004", "DISP-007"})
_PROBE_LIMIT = 200
_PAUSE_SECONDS = 0.02
_TIMEOUT_SECONDS = 3.0
_SEGMENT_PLACEHOLDER = "wythe-probe"
_EXISTS_CODES = frozenset({200, 201, 202, 204, 301, 302, 303, 307, 308, 400, 401, 403, 409, 422})
_CGNAT_NET = ipaddress.ip_network("100.64.0.0/10")


def _resolve_host_ips(host: str) -> set[ipaddress.IPv4Address | ipaddress.IPv6Address]:
    """Parse a literal IP or resolve DNS records for `host`."""
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


def _ip_is_local_or_private(ip: ipaddress.IPv4Address | ipaddress.IPv6Address) -> bool:
    if ip.is_link_local or ip.is_multicast or ip.is_unspecified:
        return False
    if ip.is_loopback or ip.is_private:
        return True
    return isinstance(ip, ipaddress.IPv4Address) and ip in _CGNAT_NET


def _validate_probe_host(host: str, *, allow_remote: bool) -> bool:
    """Validate target host and return True when the host is local/private.

    Link-local (e.g. 169.254.169.254 cloud metadata), multicast, and unspecified
    addresses are always rejected regardless of `allow_remote`.
    """
    ips = _resolve_host_ips(host)
    for ip in ips:
        if ip.is_link_local or ip.is_multicast or ip.is_unspecified:
            raise ValueError(
                f"--probe-url host '{host}' resolves to a link-local, multicast, or unspecified "
                f"address ({ip}) and cannot be probed"
            )
    if host == "localhost" or host.endswith(".localhost"):
        return True
    is_local = bool(ips) and all(_ip_is_local_or_private(ip) for ip in ips)
    if not is_local and not allow_remote:
        raise ValueError(
            f"--probe-url host '{host}' is not loopback or private; "
            "pass --probe-allow-remote to probe it anyway"
        )
    return is_local


def _concrete_path(path: str) -> str:
    return path.replace("{param}", _SEGMENT_PLACEHOLDER)


def _join(base_url: str, path: str) -> str:
    parts = urlsplit(base_url)
    base_path = parts.path.rstrip("/")
    full = path if base_path and (path == base_path or path.startswith(base_path + "/")) else base_path + path
    return f"{parts.scheme}://{parts.netloc}{full}"


def _get_status(client: httpx.Client, url: str) -> int | None:
    try:
        resp = client.get(url)
    except httpx.HTTPError:
        return None
    finally:
        client.cookies.clear()
    return resp.status_code


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
    parts = urlsplit(base_url)
    if parts.scheme not in ("http", "https") or not parts.hostname:
        raise ValueError("--probe-url must be an absolute http(s) URL")
    is_local = _validate_probe_host(parts.hostname, allow_remote=allow_remote)

    targets = [f for f in findings if f.rule_code in _PROBED_RULES and f.http_path]
    if not targets:
        return findings, "Live route probe: no unbacked calls to check."

    own_client = client is None
    http = client or httpx.Client(
        timeout=_TIMEOUT_SECONDS,
        follow_redirects=False,
        trust_env=not is_local,
        headers={"User-Agent": "wythe-route-probe"},
    )
    results: dict[tuple[str, str], int | None] = {}
    try:
        control_status = _get_status(http, _join(base_url, f"/__wythe_probe_absent_{secrets.token_hex(6)}"))
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
            results[key] = _get_status(http, _join(base_url, _concrete_path(key[1])))
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
