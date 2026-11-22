"""FastAPI application entry point for Wythe."""

from __future__ import annotations

import ipaddress
from collections.abc import AsyncIterator
from contextlib import asynccontextmanager
from pathlib import Path
from urllib.parse import urlparse

from fastapi import FastAPI, Request, Response
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse
from fastapi.staticfiles import StaticFiles

import app.models
from app import __version__
from app.api.routes import api_router
from app.core.config import Settings, load_settings
from app.db.base import Base
from app.db.seed import seed_catalog_if_needed
from app.db.session import build_engine, get_session_factory

_MUTATING_METHODS = frozenset({"POST", "PUT", "PATCH", "DELETE"})
_FORM_CSRF_CONTENT_TYPES = (
    "application/x-www-form-urlencoded",
    "multipart/form-data",
    "text/plain",
)
_SECURITY_HEADERS = {
    "X-Frame-Options": "DENY",
    "X-Content-Type-Options": "nosniff",
    "Content-Security-Policy": "frame-ancestors 'none'",
}


def _parse_host_header(raw_host: str) -> tuple[str, int | None] | None:
    val = raw_host.strip().lower()
    if not val or any(c.isspace() or ord(c) < 0x20 or ord(c) == 0x7F for c in val):
        return None
    if any(ch in val for ch in ("@", "/", "\\", "?", "#")):
        return None
    if val.startswith("["):
        end = val.find("]")
        if end <= 1:
            return None
        bare = val[1:end]
        if "%" in bare:
            return None
        try:
            ipaddress.IPv6Address(bare)
        except ValueError:
            return None
        rest = val[end + 1 :]
        if not rest:
            return (bare, None)
        if not rest.startswith(":"):
            return None
        port_part = rest[1:]
        if not port_part or not port_part.isascii() or not port_part.isdigit():
            return None
        port = int(port_part)
        if not (1 <= port <= 65535):
            return None
        return (bare, port)
    if val.count(":") == 1:
        host_part, port_part = val.rsplit(":", 1)
        if not host_part or not port_part or not port_part.isascii() or not port_part.isdigit():
            return None
        port = int(port_part)
        if not (1 <= port <= 65535):
            return None
        return (host_part, port)
    if ":" in val:
        if "%" in val:
            return None
        try:
            ipaddress.IPv6Address(val)
        except ValueError:
            return None
        return (val, None)
    return (val, None)


def _extract_host_only(raw_host: str) -> str:
    parsed = _parse_host_header(raw_host)
    return parsed[0] if parsed is not None else ""


def _host_matches_allowlist(host_only: str, allowed_hosts: tuple[str, ...]) -> bool:
    if not host_only:
        return False
    bare = host_only[1:-1] if host_only.startswith("[") and host_only.endswith("]") else host_only
    for pattern in allowed_hosts:
        pat = pattern.strip().lower()
        if not pat:
            continue
        pat_bare = pat[1:-1] if pat.startswith("[") and pat.endswith("]") else pat
        if bare == pat_bare or host_only == pat:
            return True
        if pat == "tailnet":
            if bare.endswith(".ts.net"):
                return True
            try:
                ip_obj = ipaddress.ip_address(bare)
                if ip_obj in ipaddress.ip_network("100.64.0.0/10"):
                    return True
            except ValueError:
                pass
        elif pat.startswith("*.") and bare.endswith(pat[1:]) and bare != pat[2:]:
            return True
        elif "/" in pat_bare:
            try:
                net = ipaddress.ip_network(pat_bare, strict=False)
                ip_obj = ipaddress.ip_address(bare)
                if ip_obj.version == net.version and ip_obj in net:
                    return True
            except ValueError:
                continue
    return False


def _normalize_origin_tuple(raw_origin: str) -> tuple[str, str, int] | None:
    clean = raw_origin.strip()
    if not clean or clean.lower() == "null":
        return None
    if any(c.isspace() or ord(c) < 0x20 or ord(c) == 0x7F for c in clean):
        return None
    try:
        parsed = urlparse(clean)
    except ValueError:
        return None
    scheme = (parsed.scheme or "").lower()
    if scheme not in ("http", "https") or not parsed.hostname:
        return None
    if parsed.username is not None or parsed.password is not None:
        return None
    if parsed.path not in ("", "/") or parsed.params or parsed.query or parsed.fragment:
        return None
    orig_host = parsed.hostname.lower()
    if orig_host.startswith("[") and orig_host.endswith("]"):
        orig_host = orig_host[1:-1]
    if "%" in orig_host or not orig_host:
        return None
    try:
        port = parsed.port
    except ValueError:
        return None
    if port is not None and not (1 <= port <= 65535):
        return None
    eff_port = port if port is not None else (80 if scheme == "http" else 443)
    return (scheme, orig_host, eff_port)


def _origin_is_trusted(
    origin: str,
    request_scheme: str,
    request_host_only: str,
    request_port: int | None,
    settings: Settings,
    *,
    is_testclient: bool,
) -> bool:
    clean = origin.strip()
    if not clean or clean.lower() == "null":
        return False
    orig_tuple = _normalize_origin_tuple(clean)
    if orig_tuple is None:
        return False
    if clean in settings.cors_origins:
        return True
    for allowed_origin in settings.cors_origins:
        if _normalize_origin_tuple(allowed_origin) == orig_tuple:
            return True
    req_scheme = (request_scheme or "http").lower()
    if req_scheme not in ("http", "https") or not request_host_only:
        return False
    req_eff_port = request_port if request_port is not None else (80 if req_scheme == "http" else 443)
    if orig_tuple != (req_scheme, request_host_only, req_eff_port):
        return False
    if is_testclient and orig_tuple[1] == "testserver":
        return True
    return _host_matches_allowlist(orig_tuple[1], settings.allowed_hosts)


def initialize_database(database_url: str | None = None) -> None:
    """Ensure tables exist and seed initial stack profiles, rules, and workspace targets."""
    settings = load_settings()
    resolved = database_url or settings.database_url
    engine = build_engine(resolved)
    Base.metadata.create_all(bind=engine)
    factory = get_session_factory(resolved)
    with factory() as session:
        seed_catalog_if_needed(session)


@asynccontextmanager
async def lifespan(_app: FastAPI) -> AsyncIterator[None]:
    initialize_database()
    yield


def create_app() -> FastAPI:
    settings = load_settings()
    application = FastAPI(
        title="Wythe API",
        version=__version__,
        description=(
            "Why -> Therefore: 3-tier architecture & lineage verifier. "
            "PostgreSQL holds truth, Backend manipulates truth, UI displays truth."
        ),
        lifespan=lifespan,
    )

    @application.middleware("http")
    async def browser_boundary_and_csrf_guard(request: Request, call_next) -> Response:
        live_settings = load_settings()
        eff_allowed = tuple(dict.fromkeys((*settings.allowed_hosts, *live_settings.allowed_hosts)))
        eff_cors = tuple(dict.fromkeys((*settings.cors_origins, *live_settings.cors_origins)))
        eff_settings = Settings(
            database_url=live_settings.database_url,
            api_host=live_settings.api_host,
            api_port=live_settings.api_port,
            cors_origins=eff_cors,
            state_dir=live_settings.state_dir,
            allowed_hosts=eff_allowed,
        )
        is_testclient = request.scope.get("client") == ("testclient", 50000)
        raw_host = request.headers.get("host", "")
        parsed_host = _parse_host_header(raw_host)
        host_only, host_port = parsed_host if parsed_host is not None else ("", None)
        host_ok = parsed_host is not None and (
            (is_testclient and host_only == "testserver")
            or _host_matches_allowlist(host_only, eff_settings.allowed_hosts)
        )
        if not host_ok:
            return JSONResponse(
                status_code=400,
                content={"detail": "Disallowed Host header; configure WYTHE_ALLOWED_HOSTS for Tailnet access."},
                headers=_SECURITY_HEADERS,
            )

        if request.method.upper() in _MUTATING_METHODS:
            sec_site = (request.headers.get("sec-fetch-site") or "").strip().lower()
            origin = (request.headers.get("origin") or "").strip()
            ctype = (request.headers.get("content-type") or "").strip().lower()
            has_client_hdr = bool((request.headers.get("x-wythe-client") or "").strip())

            if any(ctype.startswith(ft) for ft in _FORM_CSRF_CONTENT_TYPES):
                return JSONResponse(
                    status_code=403,
                    content={"detail": "Form/plain-text Content-Type is forbidden on mutating routes (CSRF protection)."},
                    headers=_SECURITY_HEADERS,
                )
            if sec_site and sec_site not in ("same-origin", "same-site", "none"):
                return JSONResponse(
                    status_code=403,
                    content={"detail": "Cross-site mutating request blocked (Sec-Fetch-Site)."},
                    headers=_SECURITY_HEADERS,
                )
            origin_verified = False
            if origin:
                origin_verified = _origin_is_trusted(
                    origin,
                    request.url.scheme.lower(),
                    host_only,
                    host_port,
                    eff_settings,
                    is_testclient=is_testclient,
                )
                if not origin_verified:
                    return JSONResponse(
                        status_code=403,
                        content={"detail": "Untrusted Origin header on mutating request."},
                        headers=_SECURITY_HEADERS,
                    )
            if sec_site == "same-site" and not (origin_verified or has_client_hdr):
                return JSONResponse(
                    status_code=403,
                    content={"detail": "Same-site cross-port request requires allowed Origin or X-Wythe-Client."},
                    headers=_SECURITY_HEADERS,
                )
            is_json_body = ctype.startswith("application/json")
            ua_low = (request.headers.get("user-agent") or "").strip().lower()
            looks_like_browser = bool(origin or sec_site or ua_low.startswith("mozilla/"))
            if looks_like_browser and not (
                has_client_hdr
                or origin_verified
                or sec_site == "same-origin"
                or is_json_body
            ):
                return JSONResponse(
                    status_code=403,
                    content={
                        "detail": "Browser mutating request requires verified same-origin/CORS Origin, X-Wythe-Client header, or application/json Content-Type."
                    },
                    headers=_SECURITY_HEADERS,
                )

        response = await call_next(request)
        response.headers.setdefault("X-Frame-Options", "DENY")
        response.headers.setdefault("X-Content-Type-Options", "nosniff")
        response.headers.setdefault("Content-Security-Policy", "frame-ancestors 'none'")
        return response

    application.add_middleware(
        CORSMiddleware,
        allow_origins=list(settings.cors_origins),
        allow_credentials=False,
        allow_methods=["GET", "POST", "PATCH", "DELETE", "OPTIONS"],
        allow_headers=["*"],
    )
    application.include_router(api_router, prefix="/api/v1")

    @application.get("/healthz")
    def healthcheck() -> dict[str, str]:
        return {"status": "ok", "version": __version__}

    ui_dist_dir = Path(__file__).resolve().parent / "ui_dist"
    if (ui_dist_dir / "index.html").is_file():
        application.mount(
            "/",
            StaticFiles(directory=str(ui_dist_dir), html=True),
            name="wythe-ui",
        )

    return application


app = create_app()
