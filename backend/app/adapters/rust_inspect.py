"""Syntax-level Rust source helpers for `axum`, `actix-web`, `Tauri`, `sqlx`, `Diesel`, & `SeaORM`."""

from __future__ import annotations

import re

from app.adapters.treesitter_engine import blank_comments_cst, extract_rust_routes_cst

_COMMENT_RE = re.compile(r"//[^\n]*|/\*[\s\S]*?\*/")
_NEST_SCOPE_RE = re.compile(
    r"""(?:\.nest|web::scope)\(\s*"(?P<prefix>/[^"]*)" """.strip()
)
_AXUM_ROUTE_START_RE = re.compile(r"""\.route\(\s*"(?P<path>/[^"]*)"\s*,""")
_AXUM_METHOD_RE = re.compile(r"""\b(?P<verb>get|post|put|patch|delete)\s*\(\s*(?P<fn>[A-Za-z_][\w:]*)""")
_ATTR_ROUTE_RE = re.compile(
    r"""#\[\s*(?:actix_web::|rocket::)?(?P<verb>get|post|put|patch|delete)\(\s*"(?P<path>/[^"]*)"[^)]*\)"""
)
_TAURI_CMD_RE = re.compile(
    r"""#\[\s*tauri::command[^\]]*\]\s*(?:pub(?:\([^)]*\))?\s+)?(?:async\s+)?fn\s+(?P<fn>[A-Za-z_]\w*)"""
)
_QUERY_FILE_RE = re.compile(
    r"""\bsqlx::query_file(?:_as|_scalar)?!\s*\(\s*(?:[A-Za-z_][\w:]*\s*,\s*)?"(?P<qfile>[^"]+)" """.strip()
)
_SQL_WRITE_RE = re.compile(
    r"""\b(?:INSERT\s+INTO|UPDATE|DELETE\s+FROM)\s+["`]?([A-Za-z_]\w*)["`]?""",
    re.IGNORECASE,
)
_SQL_READ_RE = re.compile(r"""\b(?:FROM|JOIN)\s+["`]?([A-Za-z_]\w*)["`]?""", re.IGNORECASE)
_DIESEL_WRITE_RE = re.compile(
    r"""\b(?:diesel::)?(?:insert_into|update|delete)\s*\(\s*(?:[\w]+::)*(?P<tbl>[A-Za-z_]\w*)::table\b"""
)
_DIESEL_READ_RE = re.compile(
    r"""\b(?P<tbl>[A-Za-z_]\w*)::table\s*\.\s*(?:select|filter|find|order|limit|first|load|get_result)"""
)
_SEAORM_WRITE_RE = re.compile(
    r"""\b(?P<ent>[A-Za-z_]\w*)::(?:Entity::(?:insert|update|delete)|ActiveModel\b)"""
)
_SEAORM_READ_RE = re.compile(r"""\b(?P<ent>[A-Za-z_]\w*)::Entity::find""")
_RUST_POLICY_RE = re.compile(
    r"""^[ \t]*(?:pub(?:\([^)]*\))?\s+)?(?:const|static)\s+(?P<name>[A-Z][A-Z0-9_]{3,})\s*:[^=]+=\s*(?P<val>[0-9_]+(?:\.[0-9_]+)?)\b""",
    re.MULTILINE,
)
_RUST_CLOCK_RE = re.compile(r"""\b(?:Utc::now|Local::now|SystemTime::now)\s*\(\s*\)""")
_USE_CRATE_RE = re.compile(r"""\buse\s+(?:crate|super)::(?P<path>[A-Za-z0-9_:{},\s*]+);""")
_QUALIFIED_CALL_RE = re.compile(r"""\b(?P<mod>[a-z_][a-z0-9_]*)::(?P<fn>[a-z_][a-z0-9_]*)\s*\(""")
_PLAIN_FN_DEF_RE = re.compile(
    r"""^[ \t]*pub(?:\([^)]*\))?\s+(?:async\s+)?fn\s+(?P<fn>[a-z_][a-z0-9_]*)\b""",
    re.MULTILINE,
)

_POLICY_MARKERS = (
    "CAPACITY",
    "WORKLOAD",
    "SHIFT_CAP",
    "DUTY_HOUR",
    "WORK_HOUR",
    "HOUR_LIMIT",
    "HOURS_LIMIT",
    "CALL_CAP",
    "SUPERVISION",
    "PENALTY",
    "WEEKLY_MAX",
    "THRESHOLD",
)
_TAURI_READ_PREFIXES = ("get_", "list_", "fetch_", "load_", "find_", "query_", "read_")


def strip_rust_comments(source: str) -> str:
    """Strip // and /* */ comments while preserving exact line numbers."""
    cst_cleaned = blank_comments_cst(source, "rust")
    if cst_cleaned is not None:
        return cst_cleaned
    return _COMMENT_RE.sub(lambda m: "\n" * m.group(0).count("\n"), source)


def normalize_rust_http_path(*parts: str) -> str:
    segs: list[str] = []
    for p in parts:
        s = p.strip()
        if not s or s == "/":
            continue
        segs.append(s.strip("/"))
    joined = "/" + "/".join(segs) if segs else "/"
    # Normalize `:id` (axum 0.7) and `<id>` / `<id:i64>` (rocket) to `{id}`
    joined = re.sub(r":([A-Za-z_]\w*)", r"{\1}", joined)
    return re.sub(r"<([A-Za-z_]\w*)(?::[^>]+)?>", r"{\1}", joined)


def compile_rust_route_regex(full_path: str) -> str:
    norm = full_path.rstrip("/") or "/"
    escaped = "" if norm == "/" else re.sub(r"\{[^/{}]+\}", r"[^/?#]+", norm)
    return rf"^(?:/api(?:/v\d+)?)?{escaped}/?$" if escaped else r"^(?:/api(?:/v\d+)?)?/?$"


def extract_rust_routes(cleaned_txt: str) -> list[tuple[str, str, int, set[str]]]:
    """Return `(http_method, full_path, lineno, handler_symbols)` for axum, actix-web, rocket, & Tauri."""
    cst_routes = extract_rust_routes_cst(cleaned_txt, normalize_rust_http_path)
    if cst_routes is not None:
        return cst_routes
    found: list[tuple[str, str, int, set[str]]] = []
    scopes = [m.group("prefix") for m in _NEST_SCOPE_RE.finditer(cleaned_txt)]
    default_prefix = scopes[0] if len(scopes) == 1 else ""

    for m in _AXUM_ROUTE_START_RE.finditer(cleaned_txt):
        subpath = m.group("path")
        lineno = cleaned_txt.count("\n", 0, m.start()) + 1
        pdepth = 1
        j = m.end()
        limit = min(len(cleaned_txt), m.end() + 300)
        while j < limit and pdepth > 0:
            if cleaned_txt[j] == "(":
                pdepth += 1
            elif cleaned_txt[j] == ")":
                pdepth -= 1
            j += 1
        arg_slice = cleaned_txt[m.end() : j]
        full_p = (
            normalize_rust_http_path(subpath)
            if subpath.startswith("/api")
            else normalize_rust_http_path(default_prefix, subpath)
        )
        for vm in _AXUM_METHOD_RE.finditer(arg_slice):
            verb = vm.group("verb").upper()
            fn_sym = vm.group("fn").split("::")[-1]
            found.append((verb, full_p, lineno, {fn_sym}))

    for am in _ATTR_ROUTE_RE.finditer(cleaned_txt):
        verb = am.group("verb").upper()
        subpath = am.group("path")
        lineno = cleaned_txt.count("\n", 0, am.start()) + 1
        full_p = (
            normalize_rust_http_path(subpath)
            if subpath.startswith("/api")
            else normalize_rust_http_path(default_prefix, subpath)
        )
        found.append((verb, full_p, lineno, set()))

    for tm in _TAURI_CMD_RE.finditer(cleaned_txt):
        cmd = tm.group("fn")
        lineno = cleaned_txt.count("\n", 0, tm.start()) + 1
        verb = "GET" if cmd.startswith(_TAURI_READ_PREFIXES) else "POST"
        found.append((verb, f"/tauri/{cmd}", lineno, {cmd}))

    return found
