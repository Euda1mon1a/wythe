"""Path-safe bounded readers, payload redaction, and OTLP/eBPF trace-to-Atlas correlation."""

from __future__ import annotations

import itertools
import json
import os
import re
import stat
from collections.abc import Mapping, Sequence
from dataclasses import asdict, dataclass, field, replace
from pathlib import Path, PurePosixPath
from typing import Any, Literal
from urllib.parse import urlsplit

MAX_WIRETAP_BYTES = 32 * 1024 * 1024  # 32 MiB passive read ceiling
MAX_NESTING_DEPTH = 64
MAX_JSON_INT_DIGITS = 64

NON_CERTIFICATION_NOTICE = (
    "Bounded passive runtime capture, heap, and listener occupancy evidence only — "
    "NOT an automated security audit, dead-code proof, taint proof, or reachability "
    "certification (see SECURITY.md). Target repository code was never executed."
)

_OS_ROOT_SYMLINK_PREFIXES: frozenset[tuple[str, str]] = frozenset(
    {("/", "var"), ("/", "tmp"), ("/", "etc")}
)
_SENSITIVE_KEY_TOKENS: tuple[str, ...] = (
    "authorization",
    "cookie",
    "set-cookie",
    "x-api-key",
    "api-key",
    "api_key",
    "apikey",
    "token",
    "secret",
    "password",
    "passwd",
    "credential",
    "bearer",
    "session_key",
    "session-id",
    "session_id",
    "sessionid",
    "x-session",
    "csrf",
    "xsrf",
    "private_key",
)
_HEADER_CONTAINER_KEYS: frozenset[str] = frozenset(
    {
        "headers",
        "http.headers",
        "request.headers",
        "response.headers",
        "http.request.headers",
        "http.response.headers",
        "l7.http.headers",
    }
)
_SAFE_HTTP_HEADER_NAMES: frozenset[str] = frozenset(
    {
        "accept",
        "accept-charset",
        "accept-encoding",
        "accept-language",
        "cache-control",
        "connection",
        "content-encoding",
        "content-language",
        "content-length",
        "content-type",
        "date",
        "etag",
        "expires",
        "grpc-encoding",
        "grpc-status",
        "host",
        ":authority",
        ":method",
        ":scheme",
        "last-modified",
        "method",
        "pragma",
        "retry-after",
        "server",
        "te",
        "transfer-encoding",
        "upgrade",
        "user-agent",
        "vary",
        "via",
    }
)
_CONN_SENSITIVE_KEY_TOKENS: tuple[str, ...] = (
    "password",
    "passwd",
    "pwd",
    "secret",
    "token",
    "apikey",
    "api_key",
    "api-key",
    "accesskey",
    "access_key",
    "accountkey",
    "sharedaccesskey",
    "sharedaccesssignature",
    "credential",
    "private_key",
    "user",
    "uid",
    "username",
)
_IDENTITY_EXACT_KEYS: frozenset[str] = frozenset(
    {
        "os.user",
        "process.owner",
        "db.user",
        "enduser.id",
        "enduser.name",
        "enduser.role",
        "user.name",
        "user.id",
        "user.email",
        "username",
    }
)
_CONN_STR_KEYS: frozenset[str] = frozenset(
    {"db.connection_string", "connection_string", "db.dsn", "dsn"}
)
_URL_SCRUB_KEYS: frozenset[str] = frozenset(
    {
        "url.full",
        "http.url",
        "http.target",
        "url",
        "path",
        "http.route",
        "url.path",
        "http.referer",
        "http.referrer",
        "referer",
        "referrer",
        "http.location",
        "location",
    }
)
_QUERY_ONLY_KEYS: frozenset[str] = frozenset({"url.query", "http.query", "query_string"})
_EMBEDDED_SQL_CLAUSE_RE = re.compile(
    r"\b(?:FROM|INTO|SET|VALUES|WHERE|TABLE|JOIN|ON)\b",
    re.IGNORECASE,
)
_PROC_IDENT_SEG = r'(?:[A-Za-z_][A-Za-z0-9_$]{0,127}|"[^"\r\n]{1,127}"|`[^`\r\n]{1,127}`|\[[^\]\r\n]{1,127}\])'
_EMBEDDED_CALL_RE = re.compile(
    r"\b(?:CALL|EXEC|EXECUTE)\b"
    rf"(?=\s*(?:\(|{_PROC_IDENT_SEG}(?:\s*\.\s*{_PROC_IDENT_SEG}){{0,3}}"
    r"\s*(?:\(|[EeNnXxBb]'|[Uu]&'|['\"$@0-9:+]|-[0-9]|[A-Za-z_@][A-Za-z0-9_]{0,63}\s*=)))",
    re.IGNORECASE,
)
_EMBEDDED_SET_RE = re.compile(
    r"\bSET\b(?=\s+(?:(?:SESSION|LOCAL|GLOBAL|PERSIST|ROLE|NAMES)\b|"
    rf"{_PROC_IDENT_SEG}(?:\s*\.\s*{_PROC_IDENT_SEG}){{0,3}}\s*(?:=|\bTO\b|\bFOR\b)))",
    re.IGNORECASE,
)
_EMBEDDED_DO_RE = re.compile(
    r"\bDO\b(?=\s+(?:LANGUAGE\s+[A-Za-z_][A-Za-z0-9_]{0,63}\s+)?\$(?:[A-Za-z_][A-Za-z0-9_]{0,63})?\$)",
    re.IGNORECASE,
)
_EMBEDDED_SELECT_FN_OR_LIT_RE = re.compile(
    r"\bSELECT\b(?=\s+(?:DISTINCT\s+)?"
    rf"(?:{_PROC_IDENT_SEG}(?:\s*\.\s*{_PROC_IDENT_SEG}){{0,2}}\s*\(|[EeNnXxBb]'|[Uu]&'|'|\$(?:[A-Za-z_][A-Za-z0-9_]{0,63})?\$))",
    re.IGNORECASE,
)
_EMBEDDED_SQL_CANDIDATE_RE = re.compile(
    r"\b(?:SELECT|INSERT|UPDATE|DELETE|MERGE|REPLACE|WITH|CREATE|ALTER|DROP|TRUNCATE|CALL|EXEC|EXECUTE|SET|DO)\b",
    re.IGNORECASE,
)
_COMPOUND_SCHEME_URI_RE = re.compile(
    r"^(?P<outer>(?:[A-Za-z][A-Za-z0-9+.-]*:)+)(?P<inner>[A-Za-z][A-Za-z0-9+.-]*://.*)$"
)
_PURE_URI_SCHEME_RE = re.compile(r"^[A-Za-z][A-Za-z0-9+.-]*://")
_INLINE_URI_TOKEN_RE = re.compile(
    r"(?<![A-Za-z0-9+.-])[A-Za-z][A-Za-z0-9+.-]*://[^\s\"'<>()\[\]{}]+"
)
_SAFE_QUERY_KEY_RE = re.compile(r"^[A-Za-z_][A-Za-z0-9_.\[\]-]{0,63}$")
_PATH_USERINFO_RE = re.compile(r"(?<![^/?#;@\s])[^/?#;:@\s]+:[^/?#@\s]+@")
_NON_SQL_DB_SYSTEMS: frozenset[str] = frozenset(
    {
        "redis",
        "valkey",
        "memcached",
        "dragonfly",
        "mongodb",
        "mongo",
        "dynamodb",
        "etcd",
        "consul",
        "zookeeper",
        "neo4j",
        "couchbase",
        "couchdb",
    }
)
_SAFE_SQL_SET_RHS_KEYWORDS: frozenset[str] = frozenset(
    {
        "DEFAULT",
        "NULL",
        "LOCAL",
        "SESSION",
        "GLOBAL",
        "ON",
        "OFF",
        "TRUE",
        "FALSE",
        "READ",
        "WRITE",
        "ONLY",
        "SERIALIZABLE",
        "REPEATABLE",
        "COMMITTED",
        "UNCOMMITTED",
        "PUBLIC",
        "UTC",
    }
)
_HTTP_SPAN_VERB_TARGET_RE = re.compile(
    r"^(?P<prefix>(?:HTTP\s+)?(?P<method>GET|POST|PUT|DELETE|PATCH|HEAD|OPTIONS|TRACE|CONNECT)\s+)(?P<target>\S+)(?P<rest>.*)$",
    re.IGNORECASE,
)
_RAW_BUFFER_KEY_TOKENS: tuple[str, ...] = (
    "raw_buffer",
    "raw_payload",
    "payload_bytes",
    "heap_bytes",
    "string_buffer",
    "request.body",
    "response.body",
    "http.body",
    "rpc.payload",
    "bind_values",
    "bind.values",
    "sql.params",
    "sql.values",
    "db.values",
    "query.parameter",
    "query.values",
)
_BEARER_INLINE_RE = re.compile(r"\b(Bearer|Basic)\s+[A-Za-z0-9._~+/-]+=*", re.IGNORECASE)
MAX_SQL_STATEMENT_CHARS = 65536
_SQL_OMITTED_MARKER = "[sql_statement_omitted_unparsed]"
_SAFE_SQL_IDENT_RE = re.compile(r"^[A-Za-z_][A-Za-z0-9_$]{0,127}$")
_STRICT_ANSI_DQ_IDENT_DIALECTS: frozenset[str] = frozenset(
    {
        "postgresql",
        "postgres",
        "pg",
        "oracle",
        "mssql",
        "sqlserver",
        "db2",
        "trino",
        "presto",
        "snowflake",
    }
)
_KNOWN_DQ_STRING_DIALECTS: frozenset[str] = frozenset(
    {"mysql", "mariadb", "sqlite", "sqlite3"}
)
_SQL_ATTR_KEYS: frozenset[str] = frozenset(
    {
        "db.statement",
        "db.sql.statement",
        "db.query.text",
        "db.query",
        "sql",
        "sql.query",
        "sql.statement",
        "query",
        "statement",
        "db.query.summary",
    }
)
_KV_PAIR_SCHEMA_KEYS: frozenset[str] = frozenset(
    {"key", "name", "value", "val", "values", "type"}
)
_SQL_BIND_KV_KEYS: frozenset[str] = frozenset(
    {
        "values",
        "bind_values",
        "bind.values",
        "sql.values",
        "db.values",
        "query.values",
        "sql.params",
        "query.parameter",
        "bind",
        "params",
        "parameters",
    }
)
_SQL_CONTEXT_ATTR_KEYS: frozenset[str] = _SQL_ATTR_KEYS | frozenset(
    {
        "db.system",
        "db.system.name",
        "db_system",
        "db.operation",
        "db.operation.name",
        "db.sql.table",
        "db.collection.name",
        "table",
    }
)
_RECOGNIZED_SQL_VERBS: frozenset[str] = frozenset(
    {
        "SELECT",
        "INSERT",
        "UPDATE",
        "DELETE",
        "WITH",
        "MERGE",
        "UPSERT",
        "REPLACE",
        "VALUES",
        "TABLE",
        "BEGIN",
        "START",
        "COMMIT",
        "END",
        "ROLLBACK",
        "SAVEPOINT",
        "RELEASE",
        "SET",
        "SHOW",
        "RESET",
        "EXPLAIN",
        "ANALYZE",
        "VACUUM",
        "PRAGMA",
        "USE",
        "DESCRIBE",
        "DESC",
        "CALL",
        "DO",
        "EXEC",
        "EXECUTE",
        "PREPARE",
        "DEALLOCATE",
        "DECLARE",
        "FETCH",
        "MOVE",
        "CLOSE",
        "LISTEN",
        "NOTIFY",
        "UNLISTEN",
        "LOCK",
        "UNLOCK",
        "COPY",
        "TRUNCATE",
        "COMMENT",
        "CREATE",
        "ALTER",
        "DROP",
        "GRANT",
        "REVOKE",
        "REINDEX",
        "REFRESH",
    }
)
_SQL_TABLE_PREPOSITIONS: frozenset[str] = frozenset({"FROM", "INTO", "UPDATE", "JOIN", "TABLE"})
_SQL_NON_TABLE_KEYWORDS: frozenset[str] = _RECOGNIZED_SQL_VERBS | frozenset(
    {
        "ONLY",
        "LATERAL",
        "WHERE",
        "GROUP",
        "ORDER",
        "HAVING",
        "LIMIT",
        "OFFSET",
        "AS",
        "ON",
        "USING",
        "AND",
        "OR",
        "NOT",
        "IN",
        "IS",
        "NULL",
        "TRUE",
        "FALSE",
        "CASE",
        "WHEN",
        "THEN",
        "ELSE",
        "INNER",
        "LEFT",
        "RIGHT",
        "FULL",
        "OUTER",
        "CROSS",
        "NATURAL",
        "RETURNING",
        "CONFLICT",
        "NOTHING",
    }
)
_UNARY_SIGN_PREV_TOKENS: frozenset[str] = frozenset(
    {
        "",
        "(",
        ",",
        "[",
        "=",
        "!=",
        "<>",
        "<",
        ">",
        "<=",
        ">=",
        "+",
        "-",
        "*",
        "/",
        "%",
        "::",
        "AND",
        "OR",
        "NOT",
        "WHERE",
        "HAVING",
        "ON",
        "SET",
        "VALUES",
        "IN",
        "LIMIT",
        "OFFSET",
        "BETWEEN",
        "BETWEEN_AND",
        "SELECT",
        "RETURN",
        "RETURNING",
        "CASE",
        "WHEN",
        "THEN",
        "ELSE",
        "BY",
        "TO",
        "DEFAULT",
    }
)
_VALUE_PREV_TOKENS: frozenset[str] = frozenset(
    {
        "=",
        "!=",
        "<>",
        "<",
        ">",
        "<=",
        ">=",
        "LIKE",
        "ILIKE",
        "RLIKE",
        "REGEXP",
        "SIMILAR",
        "IS",
        "IN",
        "VALUES",
        "BETWEEN",
        "BETWEEN_AND",
        "LIMIT",
        "OFFSET",
        "DEFAULT",
        "THEN",
        "ELSE",
    }
)


def _check_safe_path_segments(path_obj: Path, raw_label: str) -> None:
    anchor = path_obj.anchor
    for part in path_obj.parts:
        if part == anchor or part in ("", "."):
            continue
        if "\x00" in part:
            raise ValueError(f"Wiretap artifact path '{raw_label}' must not contain NUL bytes.")
        if len(part.encode("utf-8", errors="surrogateescape")) > 255:
            raise ValueError(f"Wiretap artifact path segment exceeds 255 bytes in '{raw_label}'.")


def _check_absolute_non_symlink_components(abs_path: Path, raw_label: str) -> None:
    _check_safe_path_segments(abs_path, raw_label)
    parts = abs_path.parts
    if ".." in parts:
        raise ValueError(f"Path traversal segment '..' is forbidden in '{raw_label}'.")
    try:
        for k in range(2, len(parts) + 1):
            if k == 2 and parts[:2] in _OS_ROOT_SYMLINK_PREFIXES and len(parts) > 2:
                continue
            if Path(*parts[:k]).is_symlink():
                raise ValueError(f"Refusing symlinked path component in '{raw_label}'.")
        if len(parts) >= 2 and parts[:2] in _OS_ROOT_SYMLINK_PREFIXES:
            walk = Path(*parts[:2]).resolve()
            for sub in parts[2:]:
                if sub in ("", "."):
                    continue
                walk = walk / sub
                if walk.is_symlink():
                    raise ValueError(f"Refusing symlinked path component in '{raw_label}'.")
    except OSError as exc:
        raise ValueError(f"Invalid wiretap path '{raw_label}': {exc}") from exc


def validate_non_symlink_path(
    raw_path: Path | str,
    *,
    repo_root: Path | None = None,
    allow_external: bool = False,
) -> Path:
    """Validate every path component before `.resolve()`, rejecting symlinks fail-closed."""
    raw_str = str(raw_path).strip()
    if not raw_str or "\x00" in raw_str:
        raise ValueError("Wiretap artifact path must be a non-empty string without NUL bytes.")
    cand = Path(raw_str).expanduser() if raw_str.startswith("~") else Path(raw_str)
    _check_safe_path_segments(cand, str(raw_path))
    if ".." in cand.parts:
        raise ValueError(f"Path traversal segment '..' is forbidden in '{raw_path}'.")
    try:
        if cand.is_symlink():
            raise ValueError(f"Refusing symlinked artifact path: '{raw_path}'.")

        if not cand.is_absolute():
            base_raw = repo_root if repo_root is not None else Path.cwd()
            _check_safe_path_segments(base_raw, str(base_raw))
            if base_raw.is_absolute():
                _check_absolute_non_symlink_components(base_raw, str(base_raw))
            base_dir = base_raw.resolve()
            cur = base_dir
            for part in cand.parts:
                if part in ("", "."):
                    continue
                cur = cur / part
                if cur.is_symlink():
                    raise ValueError(f"Refusing symlinked path component in '{raw_path}'.")
            resolved = cur.resolve()
            if repo_root is not None and not resolved.is_relative_to(base_dir):
                raise ValueError(f"Relative wiretap path '{raw_path}' escapes repository root.")
            cand = cur
        else:
            _check_absolute_non_symlink_components(cand, str(raw_path))
            if repo_root is not None:
                _check_safe_path_segments(repo_root, str(repo_root))
                real_root = repo_root.resolve()
                if not allow_external and not cand.resolve().is_relative_to(real_root):
                    raise ValueError(f"Wiretap artifact path '{raw_path}' escapes repository root.")
                for k in range(1, len(cand.parts) + 1):
                    pref = Path(*cand.parts[:k])
                    if pref.exists() and pref.resolve() == real_root:
                        walk = real_root
                        for part in cand.parts[k:]:
                            if part in ("", "."):
                                continue
                            walk = walk / part
                            if walk.is_symlink():
                                raise ValueError(f"Refusing symlinked path component in '{raw_path}'.")
                        break

        if cand.is_symlink() or not cand.exists():
            raise ValueError(f"Wiretap artifact '{raw_path}' must exist and must not be a symlink.")
    except OSError as exc:
        raise ValueError(f"Invalid wiretap artifact path '{raw_path}': {exc}") from exc
    return cand


def read_bounded_regular_bytes(
    raw_path: Path | str,
    *,
    repo_root: Path | None = None,
    allow_external: bool = False,
    max_bytes: int = MAX_WIRETAP_BYTES,
) -> tuple[Path, bytes]:
    """Read `<= max_bytes` (default 32 MiB) from a regular non-symlink file via `O_NOFOLLOW`."""
    cand = validate_non_symlink_path(
        raw_path, repo_root=repo_root, allow_external=allow_external
    )
    flags = os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0) | getattr(os, "O_NONBLOCK", 0)
    try:
        fd = os.open(cand, flags)
    except OSError as exc:
        raise ValueError(f"Cannot safely open wiretap artifact '{raw_path}': {exc}") from exc
    try:
        st = os.fstat(fd)
        if not stat.S_ISREG(st.st_mode):
            raise ValueError(f"Wiretap artifact '{raw_path}' must be a regular file.")
        if st.st_size > max_bytes:
            raise ValueError(
                f"Wiretap artifact '{raw_path}' ({st.st_size} bytes) exceeds {max_bytes}-byte limit."
            )
        chunks: list[bytes] = []
        rem = max_bytes + 1
        while rem > 0:
            blk = os.read(fd, min(65536, rem))
            if not blk:
                break
            chunks.append(blk)
            rem -= len(blk)
        data = b"".join(chunks)
        if len(data) > max_bytes:
            raise ValueError(f"Wiretap artifact '{raw_path}' exceeds {max_bytes}-byte limit.")
    finally:
        os.close(fd)
    return cand.resolve(), data


def ensure_json_depth_bounded(text: str, *, max_depth: int = MAX_NESTING_DEPTH) -> None:
    """Scan JSON text in O(N) time and reject bracket/brace nesting exceeding `max_depth`."""
    depth = 0
    in_str = False
    esc = False
    for ch in text:
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
                raise ValueError(
                    f"Structured wiretap payload exceeds maximum nesting depth ({max_depth})."
                )
        elif ch in "}]":
            depth = max(0, depth - 1)


def _parse_bounded_json_int(
    raw_digits: str,
    *,
    max_digits: int = MAX_JSON_INT_DIGITS,
) -> int:
    s = raw_digits.strip()
    digits = s.removeprefix("-")
    if not digits or not digits.isascii() or not digits.isdigit() or len(digits) > max_digits:
        return 0
    return int(s)


def read_bounded_json(
    raw_path: Path | str,
    *,
    repo_root: Path | None = None,
    allow_external: bool = False,
    max_bytes: int = MAX_WIRETAP_BYTES,
    max_depth: int = MAX_NESTING_DEPTH,
) -> tuple[Path, Any]:
    """Read and parse a JSON artifact enforcing `<= 32 MiB` and `depth <= 64`."""
    resolved, raw = read_bounded_regular_bytes(
        raw_path, repo_root=repo_root, allow_external=allow_external, max_bytes=max_bytes
    )
    text = raw.decode("utf-8-sig")
    if "\x00" in text:
        raise ValueError(f"Refusing JSON artifact '{raw_path}' containing NUL bytes.")
    ensure_json_depth_bounded(text, max_depth=max_depth)
    return resolved, json.loads(text, parse_int=_parse_bounded_json_int)


def _is_dollar_tag_start(ch: str) -> bool:
    return ("a" <= ch <= "z") or ("A" <= ch <= "Z") or ch == "_" or ord(ch) >= 0x80


def _is_dollar_tag_cont(ch: str) -> bool:
    return _is_dollar_tag_start(ch) or ("0" <= ch <= "9")


def _is_hex_char(ch: str) -> bool:
    return ("0" <= ch <= "9") or ("a" <= ch <= "f") or ("A" <= ch <= "F")


def _matches_unquoted_uuid(raw_sql: str, pos: int, n: int) -> bool:
    if pos + 36 > n or (pos + 36 < n and _is_dollar_tag_cont(raw_sql[pos + 36])):
        return False
    if (
        raw_sql[pos + 8] != "-"
        or raw_sql[pos + 13] != "-"
        or raw_sql[pos + 18] != "-"
        or raw_sql[pos + 23] != "-"
    ):
        return False
    for offset in range(36):
        if offset in (8, 13, 18, 23):
            continue
        if not _is_hex_char(raw_sql[pos + offset]):
            return False
    return True


def _sanitize_sql_op_and_table(
    op: str,
    tbl: str,
    *,
    allow_quoted_ident: bool = True,
) -> tuple[str, str]:
    clean_op = op.strip().upper()
    if clean_op not in _RECOGNIZED_SQL_VERBS:
        clean_op = ""
    stripped_tbl = tbl.strip()
    if not stripped_tbl or any(tok in stripped_tbl for tok in ("'", "\\", ";", "--", "/*", "#")):
        return clean_op, ""
    if not allow_quoted_ident and any(q in stripped_tbl for q in ('"', "`", "[", "]")):
        return clean_op, ""
    raw_tbl = stripped_tbl.strip('"').strip("`").strip("[]")
    if "." in raw_tbl:
        raw_tbl = raw_tbl.rpartition(".")[2]
    clean_tbl = raw_tbl.strip().strip('"').strip("`").strip("[]")
    if not _SAFE_SQL_IDENT_RE.match(clean_tbl) or clean_tbl.upper() in _SQL_NON_TABLE_KEYWORDS:
        clean_tbl = ""
    return clean_op, clean_tbl


def _format_omitted_sql(
    op: str,
    tbl: str,
    *,
    allow_quoted_ident: bool = True,
) -> str:
    c_op, c_tbl = _sanitize_sql_op_and_table(op, tbl, allow_quoted_ident=allow_quoted_ident)
    prefix = " ".join(part for part in (c_op, c_tbl) if part)
    return f"{prefix} {_SQL_OMITTED_MARKER}" if prefix else _SQL_OMITTED_MARKER


def _consume_single_quoted(
    raw_sql: str,
    quote_idx: int,
    n: int,
    *,
    allow_backslash_escape: bool = False,
    fail_on_backslash_before_quote: bool = False,
) -> int | None:
    j = quote_idx + 1
    while j < n:
        ch = raw_sql[j]
        if ch == "\\":
            if allow_backslash_escape:
                if j + 1 >= n:
                    return None
                j += 2
                continue
            bs_start = j
            while j < n and raw_sql[j] == "\\":
                j += 1
            bs_len = j - bs_start
            if j >= n:
                return None
            if raw_sql[j] == "'":
                if (
                    fail_on_backslash_before_quote
                    or (bs_len % 2) == 1
                    or (j + 1 < n and raw_sql[j + 1] == "'")
                ):
                    return None
                return j + 1
            continue
        if ch == "'":
            if j + 1 < n and raw_sql[j + 1] == "'":
                j += 2
                continue
            return j + 1
        j += 1
    return None


def _consume_numeric_literal(raw_sql: str, pos: int, n: int) -> int | None:
    if raw_sql[pos] == "0" and pos + 1 < n and raw_sql[pos + 1] in "xXbBoO":
        base_ch = raw_sql[pos + 1].lower()
        j = pos + 2
        digit_seen = False
        while j < n:
            c = raw_sql[j]
            if c == "_":
                j += 1
                continue
            if base_ch == "x" and _is_hex_char(c):
                digit_seen = True
                j += 1
                continue
            if base_ch == "b" and c in ("0", "1"):
                digit_seen = True
                j += 1
                continue
            if base_ch == "o" and "0" <= c <= "7":
                digit_seen = True
                j += 1
                continue
            break
        if not digit_seen or (j < n and _is_dollar_tag_cont(raw_sql[j])):
            return None
        return j

    j = pos
    while j < n and (("0" <= raw_sql[j] <= "9") or raw_sql[j] == "_"):
        j += 1
    if j < n and raw_sql[j] == "." and not (j + 1 < n and raw_sql[j + 1] == "."):
        j += 1
        while j < n and (("0" <= raw_sql[j] <= "9") or raw_sql[j] == "_"):
            j += 1
    if j < n and raw_sql[j] in ("e", "E"):
        exp_j = j + 1
        if exp_j < n and raw_sql[exp_j] in ("+", "-"):
            exp_j += 1
        exp_digits = 0
        while exp_j < n and (("0" <= raw_sql[exp_j] <= "9") or raw_sql[exp_j] == "_"):
            if "0" <= raw_sql[exp_j] <= "9":
                exp_digits += 1
            exp_j += 1
        if exp_digits == 0:
            return None
        j = exp_j
    if j < n and _is_dollar_tag_cont(raw_sql[j]):
        return None
    return j


def _scan_sql_statement(
    raw_sql: str,
    *,
    db_system: str = "",
    explicit_op: str = "",
    explicit_table: str = "",
    max_chars: int = MAX_SQL_STATEMENT_CHARS,
) -> tuple[str, bool, str, str]:
    """Single-pass lexical SQL redactor/normalizer failing closed on ambiguous or unclosed syntax."""
    db_low = db_system.strip().lower()
    is_mysql = db_low in ("mysql", "mariadb")
    uses_dq_strings = db_low in _KNOWN_DQ_STRING_DIALECTS
    is_ambiguous_dialect = db_low not in (
        _STRICT_ANSI_DQ_IDENT_DIALECTS | _KNOWN_DQ_STRING_DIALECTS
    )
    allow_quoted_tbl = not is_ambiguous_dialect

    if not raw_sql or not raw_sql.strip():
        c_op, c_tbl = _sanitize_sql_op_and_table(
            explicit_op, explicit_table, allow_quoted_ident=allow_quoted_tbl
        )
        return "", False, c_op, c_tbl

    detected_op = ""
    detected_tbl = ""

    def _fail() -> tuple[str, bool, str, str]:
        f_op, f_tbl = _sanitize_sql_op_and_table(
            explicit_op or detected_op,
            explicit_table or detected_tbl,
            allow_quoted_ident=allow_quoted_tbl,
        )
        return _format_omitted_sql(f_op, f_tbl, allow_quoted_ident=allow_quoted_tbl), True, f_op, f_tbl

    if (
        db_low in _NON_SQL_DB_SYSTEMS
        or len(raw_sql) > max_chars
        or any((ord(c) < 32 and c not in ("\t", "\n", "\r")) or ord(c) == 0x7F for c in raw_sql)
    ):
        return _fail()

    out: list[str] = []
    changed = False
    need_stmt_verb = True
    expecting_table = False
    table_dot_chain = False
    in_values_list = False
    between_paren_depths: set[int] = set()
    prev_sig_tok = ""
    paren_depth = 0
    bracket_depth = 0
    paren_clause_stack: list[str] = []
    i = 0
    n = len(raw_sql)

    def _in_table_clause() -> bool:
        return expecting_table or table_dot_chain or prev_sig_tok in _SQL_TABLE_PREPOSITIONS

    def _append_space() -> None:
        if out and out[-1] not in (" ", "(", "["):
            out.append(" ")

    def _record_ident(ident_raw: str) -> None:
        nonlocal detected_tbl, expecting_table, table_dot_chain
        if expecting_table and ident_raw.upper() not in _SQL_NON_TABLE_KEYWORDS:
            detected_tbl = ident_raw
            expecting_table = False
            table_dot_chain = True
        elif table_dot_chain and prev_sig_tok == ".":
            detected_tbl = ident_raw
        else:
            expecting_table = False
            table_dot_chain = False

    while i < n:
        ch = raw_sql[i]
        if ch in (" ", "\t", "\n", "\r"):
            _append_space()
            i += 1
            continue

        # Line comments: `-- ...` or MySQL `# ...`; fail closed on `#` when dialect is ambiguous/SQLite
        if (ch == "-" and i + 1 < n and raw_sql[i + 1] == "-") or (ch == "#" and is_mysql):
            changed = True
            _append_space()
            i += 2 if ch == "-" else 1
            while i < n and raw_sql[i] not in ("\n", "\r"):
                i += 1
            continue
        if ch == "#" and (is_ambiguous_dialect or db_low in ("sqlite", "sqlite3")):
            return _fail()

        # Block comments: `/* ... */` including nested PostgreSQL comments; stray `*/` fails closed
        if ch == "*" and i + 1 < n and raw_sql[i + 1] == "/":
            return _fail()
        if ch == "/" and i + 1 < n and raw_sql[i + 1] == "*":
            changed = True
            _append_space()
            depth = 1
            i += 2
            while i < n and depth > 0:
                if raw_sql[i] == "/" and i + 1 < n and raw_sql[i + 1] == "*":
                    depth += 1
                    i += 2
                elif raw_sql[i] == "*" and i + 1 < n and raw_sql[i + 1] == "/":
                    depth -= 1
                    i += 2
                else:
                    i += 1
            if depth != 0:
                return _fail()
            continue

        # Dollar-quoted PostgreSQL literals (`$$...$$`, `$tag$...$tag$`), `$1` params & `$99.5` money
        if ch == "$":
            if i + 1 < n and "0" <= raw_sql[i + 1] <= "9":
                j = i + 2
                while j < n and "0" <= raw_sql[j] <= "9":
                    j += 1
                if j < n and (raw_sql[j] == "$" or _is_dollar_tag_start(raw_sql[j])):
                    return _fail()
                if j < n and raw_sql[j] == "." and j + 1 < n and "0" <= raw_sql[j + 1] <= "9":
                    end_cur = _consume_numeric_literal(raw_sql, i + 1, n)
                    if end_cur is None:
                        return _fail()
                    changed = True
                    out.append("?")
                    prev_sig_tok = "LIT"
                    expecting_table = False
                    table_dot_chain = False
                    i = end_cur
                    continue
                digits = raw_sql[i + 1 : j]
                if raw_sql[i + 1] != "0" and len(digits) <= 5 and 1 <= int(digits) <= 65535:
                    out.append(raw_sql[i:j])
                    prev_sig_tok = "PARAM"
                else:
                    changed = True
                    out.append("?")
                    prev_sig_tok = "LIT"
                expecting_table = False
                table_dot_chain = False
                i = j
                continue
            if i + 1 < n and raw_sql[i + 1] == "$":
                close_idx = raw_sql.find("$$", i + 2)
                if close_idx == -1:
                    return _fail()
                changed = True
                out.append("'$REDACTED$'")
                prev_sig_tok = "LIT"
                expecting_table = False
                table_dot_chain = False
                i = close_idx + 2
                continue
            if i + 1 < n and _is_dollar_tag_start(raw_sql[i + 1]):
                j = i + 2
                while j < n and _is_dollar_tag_cont(raw_sql[j]):
                    j += 1
                if j >= n or raw_sql[j] != "$":
                    return _fail()
                delim = raw_sql[i : j + 1]
                close_idx = raw_sql.find(delim, j + 1)
                if close_idx == -1:
                    return _fail()
                changed = True
                out.append("'$REDACTED$'")
                prev_sig_tok = "LIT"
                expecting_table = False
                table_dot_chain = False
                i = close_idx + len(delim)
                continue
            return _fail()

        # Single-quoted & prefixed string/hex/bit/unicode literals (`'...'`, `E'...'`, `U&'...'`, etc.)
        if ch in ("U", "u") and i + 2 < n and raw_sql[i + 1] == "&" and raw_sql[i + 2] == '"':
            return _fail()
        if ch == "'" or (
            ch in ("U", "u") and i + 2 < n and raw_sql[i + 1] == "&" and raw_sql[i + 2] == "'"
        ) or (ch in "EeNnXxBb" and i + 1 < n and raw_sql[i + 1] == "'"):
            is_pg_escape_str = ch in ("E", "e") and i + 1 < n and raw_sql[i + 1] == "'"
            if is_pg_escape_str and db_low in ("sqlite", "sqlite3", "mssql", "sqlserver"):
                return _fail()
            q_pos = i if ch == "'" else (i + 2 if ch in ("U", "u") else i + 1)
            end_q = _consume_single_quoted(
                raw_sql,
                q_pos,
                n,
                allow_backslash_escape=(
                    is_pg_escape_str and db_low in ("postgresql", "postgres", "pg")
                ),
                fail_on_backslash_before_quote=is_ambiguous_dialect,
            )
            if end_q is None:
                return _fail()
            changed = True
            out.append("'?'")
            prev_sig_tok = "LIT"
            expecting_table = False
            table_dot_chain = False
            i = end_q
            continue

        # Double-quoted identifiers (`"ident"`) & MySQL/SQLite/ambiguous/value-position `"..."` literals
        if ch == '"':
            j = i + 1
            closed_end: int | None = None
            while j < n:
                c = raw_sql[j]
                if c == "\\":
                    if not is_mysql:
                        if _in_table_clause():
                            detected_tbl = ""
                        return _fail()
                    bs_start = j
                    while j < n and raw_sql[j] == "\\":
                        j += 1
                    bs_len = j - bs_start
                    if j >= n:
                        if _in_table_clause():
                            detected_tbl = ""
                        return _fail()
                    if raw_sql[j] == '"':
                        if (bs_len % 2) == 1 or (j + 1 < n and raw_sql[j + 1] == '"'):
                            if _in_table_clause():
                                detected_tbl = ""
                            return _fail()
                        closed_end = j + 1
                        break
                    continue
                if c == '"':
                    if j + 1 < n and raw_sql[j + 1] == '"':
                        j += 2
                        continue
                    closed_end = j + 1
                    break
                j += 1
            if closed_end is None:
                if _in_table_clause():
                    detected_tbl = ""
                return _fail()
            if is_ambiguous_dialect and _in_table_clause():
                detected_tbl = ""
                return _fail()
            peek = closed_end
            while peek < n and raw_sql[peek] in (" ", "\t", "\n", "\r"):
                peek += 1
            next_ch = raw_sql[peek] if peek < n else ""
            in_val_paren = ("VALUES" in paren_clause_stack) or ("IN" in paren_clause_stack)
            in_val_pos = in_val_paren or (prev_sig_tok in _VALUE_PREV_TOKENS and next_ch != ".")
            keep_ident = (
                False
                if is_ambiguous_dialect
                else (
                    (prev_sig_tok in _SQL_TABLE_PREPOSITIONS or prev_sig_tok == "." or next_ch == ".")
                    and not in_val_paren
                    and (not uses_dq_strings or (prev_sig_tok in _SQL_TABLE_PREPOSITIONS and next_ch != "."))
                    and not in_val_pos
                )
            )
            if keep_ident:
                inner_ident = raw_sql[i + 1 : closed_end - 1].replace('""', '"')
                _record_ident(inner_ident)
                out.append(raw_sql[i:closed_end])
                prev_sig_tok = "IDENT"
            else:
                changed = True
                out.append("'?'")
                prev_sig_tok = "LIT"
                expecting_table = False
                table_dot_chain = False
            i = closed_end
            continue

        # Backtick quoted identifiers (`` `ident` ``)
        if ch == "`":
            j = i + 1
            closed_bt: int | None = None
            while j < n:
                if raw_sql[j] == "\\":
                    if _in_table_clause():
                        detected_tbl = ""
                    return _fail()
                if raw_sql[j] == "`":
                    if j + 1 < n and raw_sql[j + 1] == "`":
                        j += 2
                        continue
                    closed_bt = j + 1
                    break
                j += 1
            if closed_bt is None:
                if _in_table_clause():
                    detected_tbl = ""
                return _fail()
            if is_ambiguous_dialect:
                if _in_table_clause():
                    detected_tbl = ""
                    return _fail()
                changed = True
                out.append("'?'")
                prev_sig_tok = "LIT"
                expecting_table = False
                table_dot_chain = False
                i = closed_bt
                continue
            _record_ident(raw_sql[i + 1 : closed_bt - 1].replace("``", "`"))
            out.append(raw_sql[i:closed_bt])
            prev_sig_tok = "IDENT"
            i = closed_bt
            continue

        # Bracket quoted identifiers (`[ident]`) vs array constructors/subscripts (`ARRAY[...]`, `col[...]`)
        if ch == "[":
            if prev_sig_tok not in ("IDENT", ")", "]", "ARRAY"):
                close_b = raw_sql.find("]", i + 1)
                if close_b == -1:
                    if _in_table_clause():
                        detected_tbl = ""
                    return _fail()
                if is_ambiguous_dialect:
                    if _in_table_clause():
                        detected_tbl = ""
                    return _fail()
                inner_b = raw_sql[i + 1 : close_b]
                if _SAFE_SQL_IDENT_RE.match(inner_b):
                    _record_ident(inner_b)
                    out.append(raw_sql[i : close_b + 1])
                    prev_sig_tok = "IDENT"
                    i = close_b + 1
                    continue
            bracket_depth += 1
            out.append("[")
            prev_sig_tok = "["
            expecting_table = False
            table_dot_chain = False
            i += 1
            continue
        if ch == "]":
            if bracket_depth <= 0:
                return _fail()
            bracket_depth -= 1
            out.append("]")
            prev_sig_tok = "]"
            expecting_table = False
            table_dot_chain = False
            i += 1
            continue

        # Unquoted UUID literals (`550e8400-e29b-41d4-a716-446655440000`)
        if _is_hex_char(ch) and _matches_unquoted_uuid(raw_sql, i, n):
            changed = True
            out.append("?")
            prev_sig_tok = "LIT"
            expecting_table = False
            table_dot_chain = False
            i += 36
            continue

        # Standalone signed/unsigned numeric & hex/bin/oct literals (`987654321`, `-42`, `1.23e-4`, `0xdeadbeef`)
        is_unary_signed_num = (
            ch in ("+", "-")
            and prev_sig_tok in _UNARY_SIGN_PREV_TOKENS
            and i + 1 < n
            and (
                "0" <= raw_sql[i + 1] <= "9"
                or (raw_sql[i + 1] == "." and i + 2 < n and "0" <= raw_sql[i + 2] <= "9")
            )
        )
        is_unsigned_num = ("0" <= ch <= "9") or (
            ch == "." and i + 1 < n and "0" <= raw_sql[i + 1] <= "9"
        )
        if is_unary_signed_num or is_unsigned_num:
            num_start = i + 1 if is_unary_signed_num else i
            end_num = _consume_numeric_literal(raw_sql, num_start, n)
            if end_num is None:
                return _fail()
            changed = True
            out.append("?")
            prev_sig_tok = "LIT"
            expecting_table = False
            table_dot_chain = False
            i = end_num
            continue

        # Keywords, boolean literals (`TRUE`/`FALSE`), MySQL `_charset'...'`, and identifiers
        if _is_dollar_tag_start(ch):
            j = i + 1
            while j < n and _is_dollar_tag_cont(raw_sql[j]):
                j += 1
            tok = raw_sql[i:j]
            if j < n and raw_sql[j] in ("'", '"'):
                if ch == "_" and raw_sql[j] == "'":
                    end_cs = _consume_single_quoted(
                        raw_sql,
                        j,
                        n,
                        allow_backslash_escape=False,
                        fail_on_backslash_before_quote=is_ambiguous_dialect,
                    )
                    if end_cs is None:
                        return _fail()
                    changed = True
                    out.append("'?'")
                    prev_sig_tok = "LIT"
                    expecting_table = False
                    table_dot_chain = False
                    i = end_cs
                    continue
                return _fail()
            tok_up = tok.upper()
            if need_stmt_verb:
                if tok_up not in _RECOGNIZED_SQL_VERBS:
                    return _fail()
                if tok_up == "SET" and _EMBEDDED_SET_RE.match(raw_sql, i) is None:
                    return _fail()
                if not detected_op:
                    detected_op = tok_up
                need_stmt_verb = False
            elif (
                detected_op == "SET"
                and paren_depth == 0
                and prev_sig_tok in ("=", "TO")
                and tok_up not in _SAFE_SQL_SET_RHS_KEYWORDS
            ):
                k_end = j
                while k_end < n and raw_sql[k_end] in (".", "-", "/", "+"):
                    k_end += 1
                    while k_end < n and (
                        _is_dollar_tag_cont(raw_sql[k_end]) or raw_sql[k_end] == "="
                    ):
                        k_end += 1
                changed = True
                out.append("?")
                prev_sig_tok = "LIT"
                expecting_table = False
                table_dot_chain = False
                i = k_end
                continue
            if tok_up in ("TRUE", "FALSE") and prev_sig_tok != ".":
                changed = True
                out.append("?")
                prev_sig_tok = "LIT"
                expecting_table = False
                table_dot_chain = False
                i = j
                continue
            if tok_up == "BETWEEN":
                between_paren_depths.add(paren_depth)
            elif tok_up == "AND" and paren_depth in between_paren_depths:
                between_paren_depths.discard(paren_depth)
                out.append(tok)
                prev_sig_tok = "BETWEEN_AND"
                expecting_table = False
                table_dot_chain = False
                i = j
                continue
            elif tok_up in ("WHERE", "GROUP", "ORDER", "HAVING", "LIMIT", "OFFSET", "UNION"):
                between_paren_depths.discard(paren_depth)
            if tok_up == "SELECT" and paren_clause_stack and paren_clause_stack[-1] == "IN":
                paren_clause_stack[-1] = "SUBQUERY"
            if tok_up == "VALUES":
                in_values_list = True
            elif paren_depth == 0 and tok_up in ("ON", "RETURNING", "WHERE", "SET", "DO"):
                in_values_list = False
            if tok_up in _SQL_TABLE_PREPOSITIONS:
                if not detected_tbl:
                    expecting_table = True
                table_dot_chain = False
                out.append(tok)
                prev_sig_tok = tok_up
            elif expecting_table and tok_up == "ONLY":
                out.append(tok)
                prev_sig_tok = tok_up
            else:
                _record_ident(tok)
                out.append(tok)
                prev_sig_tok = tok_up if tok_up in _SQL_NON_TABLE_KEYWORDS or tok_up in _VALUE_PREV_TOKENS or tok_up == "ARRAY" else "IDENT"
            i = j
            continue

        # Bind parameters `:param` vs PostgreSQL `::` cast
        if ch == ":":
            if i + 1 < n and raw_sql[i + 1] == ":":
                out.append("::")
                prev_sig_tok = "::"
                expecting_table = False
                table_dot_chain = False
                i += 2
                continue
            if i + 1 < n and _is_dollar_tag_start(raw_sql[i + 1]):
                j = i + 2
                while j < n and _is_dollar_tag_cont(raw_sql[j]):
                    j += 1
                out.append(raw_sql[i:j])
                prev_sig_tok = "PARAM"
                expecting_table = False
                table_dot_chain = False
                i = j
                continue
            out.append(":")
            prev_sig_tok = ":"
            i += 1
            continue

        if ch == "(":
            paren_depth += 1
            top_ctx = paren_clause_stack[-1] if paren_clause_stack else ""
            if prev_sig_tok == "IN":
                paren_clause_stack.append("IN")
            elif in_values_list and paren_depth == 1:
                paren_clause_stack.append("VALUES")
            elif top_ctx in ("VALUES", "IN"):
                paren_clause_stack.append(top_ctx)
            else:
                paren_clause_stack.append("")
            out.append("(")
            prev_sig_tok = "("
            expecting_table = False
            table_dot_chain = False
            i += 1
            continue
        if ch == ")":
            if paren_depth <= 0:
                return _fail()
            between_paren_depths.discard(paren_depth)
            paren_depth -= 1
            paren_clause_stack.pop()
            out.append(")")
            prev_sig_tok = ")"
            expecting_table = False
            table_dot_chain = False
            i += 1
            continue
        if ch == ";":
            in_values_list = False
            between_paren_depths.clear()
            need_stmt_verb = True
            expecting_table = False
            table_dot_chain = False
            prev_sig_tok = ";"
            out.append(";")
            i += 1
            continue
        if ch == ".":
            out.append(".")
            prev_sig_tok = "."
            i += 1
            continue
        if ch in ("\\", "{", "}"):
            return _fail()
        if ch in ("=", "!", "<", ">"):
            two = raw_sql[i : i + 2]
            if two in ("!=", "<>", "<=", ">="):
                out.append(two)
                prev_sig_tok = two
                expecting_table = False
                table_dot_chain = False
                i += 2
                continue
            out.append(ch)
            prev_sig_tok = ch
            expecting_table = False
            table_dot_chain = False
            i += 1
            continue
        if ch in (",", "?", "+", "-", "*", "/", "%", "~", "|", "&", "^", "@", "#"):
            out.append(ch)
            prev_sig_tok = ch
            expecting_table = False
            table_dot_chain = False
            i += 1
            continue
        return _fail()

    if paren_depth != 0 or bracket_depth != 0 or not detected_op:
        return _fail()
    if need_stmt_verb and prev_sig_tok != ";":
        return _fail()

    c_op, c_tbl = _sanitize_sql_op_and_table(
        explicit_op or detected_op,
        explicit_table or detected_tbl,
        allow_quoted_ident=allow_quoted_tbl,
    )
    normalized = "".join(out).strip()
    if normalized != raw_sql:
        changed = True
    return normalized[:512], changed, c_op, c_tbl


def _redact_sql_statement(
    raw_sql: str,
    *,
    db_system: str = "",
    explicit_op: str = "",
    explicit_table: str = "",
    max_chars: int = MAX_SQL_STATEMENT_CHARS,
) -> tuple[str, bool]:
    """Bounded single-pass lexical SQL normalizer/redactor covering PG, MySQL, SQLite, & ANSI."""
    redacted, changed, _op, _tbl = _scan_sql_statement(
        raw_sql,
        db_system=db_system,
        explicit_op=explicit_op,
        explicit_table=explicit_table,
        max_chars=max_chars,
    )
    return redacted, changed


def redact_sql_statement(
    raw_sql: str,
    *,
    db_system: str = "",
    explicit_op: str = "",
    explicit_table: str = "",
) -> tuple[str, bool]:
    """Public wrapper around `_redact_sql_statement` preserving `(redacted_sql, was_redacted)`."""
    return _redact_sql_statement(
        raw_sql,
        db_system=db_system,
        explicit_op=explicit_op,
        explicit_table=explicit_table,
    )


def redact_url_target(raw_url: str) -> tuple[str, str, bool]:
    """Return `(clean_path, redacted_url, was_redacted)` stripping credentials and query values."""
    if not raw_url:
        return "", "", False
    s = raw_url.strip()
    if not s:
        return "", "", False
    outer_scheme = ""
    m_comp = _COMPOUND_SCHEME_URI_RE.match(s)
    if m_comp is not None:
        outer_scheme = m_comp.group("outer")
        s = m_comp.group("inner")
    schemeless_host = False
    if "://" not in s and not s.startswith(("/", "?")):
        head = re.split(r"[/?#]", s, maxsplit=1)[0]
        if "@" in head:
            schemeless_host = True
            s = "//" + s
    try:
        parsed = urlsplit(s)
    except ValueError:
        return "", "[REDACTED]", True
    raw_path = parsed.path
    redacted = bool(parsed.fragment)
    if ";" in raw_path:
        p_head, _, semi_tail = raw_path.partition(";")
        semi_parts: list[str] = []
        for mseg in semi_tail.split(";")[:32]:
            if not mseg:
                continue
            mk, msep, mv = mseg.partition("=")
            if msep and mk and mv and mv.strip("=") and _SAFE_QUERY_KEY_RE.match(mk):
                semi_parts.append(f";{mk}=[REDACTED]")
            else:
                semi_parts.append(";[REDACTED]")
        redacted = True
        clean_path = p_head or "/"
        display_path = (p_head or "/") + "".join(semi_parts)
    else:
        clean_path = raw_path or "/"
        display_path = clean_path
    if "@" in display_path:
        new_dp = _PATH_USERINFO_RE.sub("[REDACTED]@", display_path)
        if new_dp != display_path:
            display_path = new_dp
            clean_path = _PATH_USERINFO_RE.sub("[REDACTED]@", clean_path)
            redacted = True
    host_part = parsed.hostname or ""
    if ":" in host_part and not host_part.startswith("["):
        host_part = f"[{host_part}]"
    try:
        port_val = parsed.port
    except ValueError:
        port_val = None
        redacted = True
    if port_val is not None:
        host_part = f"{host_part}:{port_val}"
    if parsed.username or parsed.password or schemeless_host:
        redacted = True
    q_parts: list[str] = []
    if parsed.query:
        if ";" in parsed.query:
            redacted = True
        raw_segs = re.split(r"[&;]", parsed.query)
        if len(raw_segs) > 32:
            redacted = True
        for seg in raw_segs[:32]:
            if not seg:
                redacted = True
                continue
            k, sep, v = seg.partition("=")
            if sep and k and v and v.strip("=") and _SAFE_QUERY_KEY_RE.match(k):
                redacted = True
                q_parts.append(f"{k}=[REDACTED]")
            else:
                redacted = True
                q_parts.append("[REDACTED]")
    if parsed.scheme and host_part:
        prefix = f"{outer_scheme}{parsed.scheme}://{host_part}"
        eff_path = display_path
    elif schemeless_host and host_part:
        prefix = f"{outer_scheme}{host_part}"
        eff_path = display_path if raw_path else ""
    elif s.startswith("//") and host_part:
        prefix = f"{outer_scheme}//{host_part}"
        eff_path = display_path
    else:
        prefix = outer_scheme
        eff_path = display_path
    q_str = f"?{'&'.join(q_parts)}" if q_parts else ""
    return clean_path, f"{prefix}{eff_path}{q_str}", redacted


def _scrub_semicolon_conn_pairs(raw_semi: str) -> tuple[str, bool]:
    changed = False
    out_segs: list[str] = []
    for seg in raw_semi.split(";")[:64]:
        s_seg = seg.strip()
        if not s_seg:
            out_segs.append("")
            continue
        if "=" not in s_seg:
            if "@" in s_seg or any(t in s_seg.lower() for t in _CONN_SENSITIVE_KEY_TOKENS):
                out_segs.append("[REDACTED]")
                changed = True
            else:
                out_segs.append(s_seg)
            continue
        k_raw, _, v_raw = s_seg.partition("=")
        k_norm = re.sub(r"\s+", "", k_raw.strip().lower())
        if any(tok in k_norm for tok in _CONN_SENSITIVE_KEY_TOKENS):
            out_segs.append(f"{k_raw.strip()}=[REDACTED]")
            changed = True
        elif "://" in v_raw or "?" in v_raw or "@" in v_raw:
            _p, red_v, was_u = redact_url_target(v_raw.strip())
            out_segs.append(f"{k_raw.strip()}={red_v}")
            if was_u or red_v != v_raw.strip():
                changed = True
        else:
            out_segs.append(s_seg)
    return ";".join(out_segs), changed


_UNREDACTED_CONN_KV_RE = re.compile(
    r"\b(?:password|passwd|pwd|secret|token|apikey|api_key|api-key|accesskey|accountkey|sharedaccesskey|sharedaccesssignature|credential)\s*=\s*(?!\[REDACTED\])[^\s;&]+",
    re.IGNORECASE,
)


def _redact_connection_string(val_s: str) -> tuple[str, int]:
    s = val_s.strip()
    if not s:
        return "", 0
    is_uri = bool(_PURE_URI_SCHEME_RE.match(s) or _COMPOUND_SCHEME_URI_RE.match(s))
    if is_uri:
        q_pos = s.find("?")
        semi_pos = s.find(";")
        if semi_pos != -1 and (q_pos == -1 or semi_pos < q_pos):
            uri_head = s[:semi_pos]
            semi_body = s[semi_pos + 1 : q_pos] if q_pos != -1 else s[semi_pos + 1 :]
            q_tail = s[q_pos:] if q_pos != -1 else ""
            _p1, sc_head, w_head = redact_url_target(uri_head)
            if sc_head.endswith("/") and not uri_head.endswith("/"):
                sc_head = sc_head[:-1]
            sc_semi, w_semi = _scrub_semicolon_conn_pairs(semi_body)
            sc_q = ""
            w_q = False
            if q_tail:
                _p2, red_q_full, w_q = redact_url_target("https://x/" + q_tail)
                q_after = red_q_full.partition("?")[2]
                sc_q = f"?{q_after}" if q_after else ""
            combined = f"{sc_head};{sc_semi}{sc_q}" if sc_semi else f"{sc_head}{sc_q}"
            was_red = w_head or w_semi or w_q or (combined != s)
        else:
            _p, combined, was_red = redact_url_target(s)
            if ";" in combined:
                head_c, sep_c, tail_c = combined.partition(";")
                sc_tail, w_t = _scrub_semicolon_conn_pairs(tail_c)
                combined = f"{head_c}{sep_c}{sc_tail}"
                was_red = was_red or w_t
        if "@" in combined or _UNREDACTED_CONN_KV_RE.search(combined):
            return "[REDACTED]", 1
        return combined[:512], (1 if (was_red or combined != val_s) else 0)

    if ";" in s and "=" in s:
        sc_semi, w_semi = _scrub_semicolon_conn_pairs(s)
        if "@" in sc_semi or _UNREDACTED_CONN_KV_RE.search(sc_semi):
            return "[REDACTED]", 1
        return sc_semi[:512], (1 if (w_semi or sc_semi != val_s) else 0)

    return "[REDACTED]", 1


def _looks_like_inline_sql_at(text: str, start: int = 0) -> tuple[bool, int]:
    n = len(text)
    idx = start
    while idx < n:
        ch = text[idx]
        if ch in (" ", "\t", "\n", "\r", "("):
            idx += 1
            continue
        if ch == "-" and idx + 1 < n and text[idx + 1] == "-":
            nl = text.find("\n", idx + 2)
            if nl == -1:
                return False, n
            idx = nl + 1
            continue
        if ch == "/" and idx + 1 < n and text[idx + 1] == "*":
            end_c = text.find("*/", idx + 2)
            if end_c == -1:
                return True, n
            idx = end_c + 2
            continue
        break
    v_end = idx
    while v_end < n and ("A" <= text[v_end] <= "Z" or "a" <= text[v_end] <= "z"):
        v_end += 1
    if v_end == idx or v_end >= n:
        return False, max(start + 1, v_end)
    verb = text[idx:v_end].upper()
    if verb not in _RECOGNIZED_SQL_VERBS or text[v_end] not in (
        " ",
        "\t",
        "\n",
        "\r",
        "'",
        '"',
        "`",
        "[",
        "(",
        "*",
        "$",
        "/",
        "-",
        "#",
    ):
        return False, v_end
    r_idx = v_end
    while r_idx < n and text[r_idx] in (" ", "\t", "\n", "\r"):
        r_idx += 1
    if r_idx < n:
        if text[r_idx] == "/" and not (r_idx + 1 < n and text[r_idx + 1] == "*"):
            return False, r_idx + 1
        low_prefix = text[r_idx : r_idx + 8].lower()
        if low_prefix.startswith(("http://", "https://")):
            return False, r_idx + 7
    return True, v_end


def _looks_like_inline_sql(text: str) -> bool:
    return _looks_like_inline_sql_at(text, 0)[0]


def _scrub_embedded_sql(
    text: str,
    *,
    db_system: str,
    explicit_op: str,
    explicit_table: str,
) -> tuple[str, bool]:
    last_clause_start = -1
    for m_clause in _EMBEDDED_SQL_CLAUSE_RE.finditer(text):
        last_clause_start = m_clause.start()
    has_standalone = (
        _EMBEDDED_CALL_RE.search(text) is not None
        or _EMBEDDED_SET_RE.search(text) is not None
        or _EMBEDDED_DO_RE.search(text) is not None
        or _EMBEDDED_SELECT_FN_OR_LIT_RE.search(text) is not None
    )
    if last_clause_start == -1 and not has_standalone:
        return text, False

    cursor = 0
    n = len(text)
    while cursor < n:
        match = _EMBEDDED_SQL_CANDIDATE_RE.search(text, cursor)
        if match is None:
            break
        m_start = match.start()
        verb = match.group(0).upper()
        cursor = match.end()
        if verb in ("CALL", "EXEC", "EXECUTE"):
            if _EMBEDDED_CALL_RE.match(text, m_start) is None:
                continue
        elif verb == "SET":
            if _EMBEDDED_SET_RE.match(text, m_start) is None:
                continue
        elif verb == "DO":
            if _EMBEDDED_DO_RE.match(text, m_start) is None:
                continue
        elif verb == "SELECT":
            if m_start >= last_clause_start and _EMBEDDED_SELECT_FN_OR_LIT_RE.match(text, m_start) is None:
                continue
        elif m_start >= last_clause_start:
            continue

        ok, adv = _looks_like_inline_sql_at(text, m_start)
        cursor = max(cursor, adv)
        if not ok:
            continue
        tail = text[m_start:]
        red_tail, was_sql = _redact_sql_statement(
            tail,
            db_system=db_system,
            explicit_op=explicit_op,
            explicit_table=explicit_table,
        )
        if was_sql:
            return text[:m_start] + red_tail, True
        break
    return text, False


def _str_looks_like_sql(val: Any) -> bool:
    if not isinstance(val, str):
        return False
    s = val.strip()
    if not s:
        return False
    if _looks_like_inline_sql(s):
        return True
    if len(s) <= MAX_SQL_STATEMENT_CHARS:
        _red, was_emb = _scrub_embedded_sql(
            s, db_system="", explicit_op="", explicit_table=""
        )
        return was_emb
    return False


def _safe_str(val: Any) -> str:
    if val is None:
        return ""
    if isinstance(val, str):
        return val
    if isinstance(val, int) and not isinstance(val, bool) and val.bit_length() > 4096:
        return ""
    try:
        return str(val)
    except ValueError:
        return ""


def _sequence_has_sql_kv_context(items: Sequence[Any]) -> bool:
    for elem in items:
        if not isinstance(elem, Mapping):
            continue
        elem_low = {_safe_str(ek).strip().lower(): ev for ek, ev in elem.items()}
        raw_k = (
            elem_low.get("key")
            if isinstance(elem_low.get("key"), str)
            else (
                elem_low.get("name")
                if isinstance(elem_low.get("name"), str)
                else elem_low.get("k")
            )
        )
        if not isinstance(raw_k, str):
            continue
        k_low = raw_k.strip().lower()
        if k_low in _SQL_CONTEXT_ATTR_KEYS or k_low.startswith(("db.", "sql.")):
            return True
    return False


def redact_attributes(
    raw_attrs: Mapping[str, Any],
    *,
    inherited_db_system: str = "",
    inherited_op: str = "",
    inherited_table: str = "",
    inherited_sql_context: bool = False,
    _depth: int = 0,
) -> tuple[dict[str, object], int]:
    """Redact auth/cookie headers, SQL bind/literal values, URL query values, and raw buffers."""
    if _depth > 16:
        return {_safe_str(rk).strip(): "[REDACTED_NESTED]" for rk in list(raw_attrs)[:64]}, 1
    cleaned: dict[str, object] = {}
    redacted_count = 0
    key_map = {_safe_str(rk).strip().lower(): raw_attrs[rk] for rk in raw_attrs}
    keys_low = set(key_map)
    l7_raw = key_map.get("l7")
    local_sql_context = bool(
        key_map.get("db.system")
        or key_map.get("db.system.name")
        or key_map.get("db_system")
        or key_map.get("db.operation")
        or key_map.get("db.operation.name")
        or key_map.get("db.sql.table")
        or key_map.get("db.collection.name")
        or key_map.get("table")
        or isinstance(key_map.get("db"), Mapping)
        or (
            isinstance(l7_raw, Mapping)
            and (isinstance(l7_raw.get("sql"), Mapping) or isinstance(l7_raw.get("db"), Mapping))
        )
        or any(rk in _SQL_ATTR_KEYS for rk in keys_low)
        or _str_looks_like_sql(key_map.get("name"))
        or _str_looks_like_sql(key_map.get("key"))
    )
    has_sql_context = bool(inherited_sql_context or local_sql_context)
    has_val_field = any(vf in keys_low for vf in ("value", "val", "values", "v"))
    has_key_str = isinstance(key_map.get("key"), str)
    has_name_str = isinstance(key_map.get("name"), str)
    has_k_str = isinstance(key_map.get("k"), str)
    is_kv_candidate = bool(keys_low) and has_val_field and (has_key_str or has_name_str or has_k_str)
    is_kv_pair = (
        (not local_sql_context)
        and has_val_field
        and (has_key_str or has_k_str or (has_name_str and not has_sql_context))
    )
    db_sys_hint = _safe_str(
        key_map.get("db.system")
        or key_map.get("db.system.name")
        or key_map.get("db_system")
        or inherited_db_system
        or ""
    ).strip()
    db_low_hint = db_sys_hint.lower()
    allow_quoted_tbl_hint = db_low_hint in (
        _STRICT_ANSI_DQ_IDENT_DIALECTS | _KNOWN_DQ_STRING_DIALECTS
    )
    op_hint = _safe_str(
        key_map.get("db.operation")
        or key_map.get("db.operation.name")
        or inherited_op
        or ""
    ).strip()
    tbl_hint = _safe_str(
        key_map.get("db.sql.table")
        or key_map.get("db.collection.name")
        or key_map.get("table")
        or inherited_table
        or ""
    ).strip()

    def _is_conn_str_key(k_low: str) -> bool:
        return (
            k_low in _CONN_STR_KEYS
            or "connection_string" in k_low
            or "conn_str" in k_low
            or k_low.endswith((".dsn", "_dsn"))
            or k_low == "dsn"
            or (
                k_low.endswith((".uri", "_uri", ".url", "_url"))
                and any(
                     pfx in k_low
                    for pfx in (
                        "db",
                        "sql",
                        "jdbc",
                        "redis",
                        "mongo",
                        "amqp",
                        "kafka",
                        "broker",
                        "database",
                        "cache",
                    )
                )
            )
        )

    def _is_sensitive_key(k_low: str) -> bool:
        return (
            k_low in _IDENTITY_EXACT_KEYS
            or k_low.startswith(
                ("enduser.", "http.request.header.", "http.response.header.", "rpc.metadata.")
            )
            or any(tok in k_low for tok in _SENSITIVE_KEY_TOKENS)
        )

    def _is_headers_container_key(k_low: str) -> bool:
        return k_low in _HEADER_CONTAINER_KEYS or k_low.endswith(".headers")

    def _scrub_str(k_low: str, val_s: str) -> tuple[str, int]:
        cnt = 0
        if _is_conn_str_key(k_low):
            return _redact_connection_string(val_s)
        if k_low in _QUERY_ONLY_KEYS:
            if not val_s.strip():
                return "", 0
            _p, red_q, _ = redact_url_target("https://x/?" + val_s.lstrip("?"))
            q_tail = red_q.partition("?")[2]
            return (q_tail or "[REDACTED]")[:512], 1
        is_url_key = k_low in _URL_SCRUB_KEYS
        m_http_verb = None if is_url_key else _HTTP_SPAN_VERB_TARGET_RE.match(val_s.strip())
        if m_http_verb is not None:
            v_tgt = m_http_verb.group("target")
            if (
                v_tgt.startswith("/")
                or "://" in v_tgt
                or ("@" in v_tgt and "/" in v_tgt)
            ) and ("?" in v_tgt or "@" in v_tgt or "://" in v_tgt or ";" in v_tgt or "#" in v_tgt):
                _p, red_vt, was_vt = redact_url_target(v_tgt)
                if was_vt or (red_vt and red_vt != v_tgt):
                    lead_ws = val_s[: len(val_s) - len(val_s.lstrip())]
                    val_s = f"{lead_ws}{m_http_verb.group('prefix')}{red_vt}{m_http_verb.group('rest')}"
                    cnt += 1
        if k_low in ("db.sql.table", "db.collection.name", "table"):
            _op_chk, safe_tbl = _sanitize_sql_op_and_table(
                "SELECT", val_s, allow_quoted_ident=allow_quoted_tbl_hint
            )
            if not safe_tbl:
                return "[REDACTED]", 1
            if safe_tbl != val_s.strip():
                cnt += 1
            val_s = safe_tbl
        elif k_low in _SQL_ATTR_KEYS or (not is_url_key and _looks_like_inline_sql(val_s)):
            val_s, was_sql = _redact_sql_statement(
                val_s,
                db_system=db_sys_hint,
                explicit_op=op_hint,
                explicit_table=tbl_hint,
            )
            if was_sql:
                cnt += 1
        elif not is_url_key:
            val_s, was_emb_sql = _scrub_embedded_sql(
                val_s,
                db_system=db_sys_hint,
                explicit_op=op_hint,
                explicit_table=tbl_hint,
            )
            if was_emb_sql:
                cnt += 1
        if is_url_key and (
            "?" in val_s or "@" in val_s or "://" in val_s or ";" in val_s or "#" in val_s
        ):
            _p, new_u, was_u = redact_url_target(val_s)
            if was_u or (new_u and new_u != val_s):
                val_s = new_u
                cnt += 1
        elif not is_url_key:
            s_trim = val_s.strip()
            if (
                s_trim.startswith("/")
                and " " not in s_trim
                and any(ch in s_trim for ch in ("?", "#", "@", ";"))
            ):
                _p, new_rel, was_rel = redact_url_target(s_trim)
                if was_rel or (new_rel and new_rel != s_trim):
                    val_s = new_rel
                    cnt += 1
            elif "://" in val_s:
                uri_hits = 0

                def _sub_inline_uri(match: re.Match[str]) -> str:
                    nonlocal uri_hits
                    raw_tok = match.group(0)
                    trail = ""
                    while raw_tok and raw_tok[-1] in (",", ".", ";", ":"):
                        trail = raw_tok[-1] + trail
                        raw_tok = raw_tok[:-1]
                    _up, red_tok, was_tok = redact_url_target(raw_tok)
                    if was_tok or (red_tok and red_tok != raw_tok):
                        uri_hits += 1
                        return f"{red_tok}{trail}"
                    return match.group(0)

                val_s = _INLINE_URI_TOKEN_RE.sub(_sub_inline_uri, val_s)
                cnt += uri_hits
        scrubbed = _BEARER_INLINE_RE.sub(r"\1 [REDACTED]", val_s)
        if scrubbed != val_s:
            cnt += 1
        return scrubbed[:512], cnt

    def _scrub_headers_container(raw_hdrs: Any, depth: int) -> tuple[object, int]:
        if depth > 16:
            return "[REDACTED_NESTED]", 1
        if isinstance(raw_hdrs, Mapping):
            h_out: dict[str, object] = {}
            h_cnt = 0
            for raw_hk, raw_hv in list(raw_hdrs.items())[:64]:
                hk = _safe_str(raw_hk).strip()
                hk_low = hk.lower()
                if hk_low in _SAFE_HTTP_HEADER_NAMES:
                    sc_hv, c_hv = _scrub_value(hk_low, raw_hv, depth + 1)
                    h_out[hk] = sc_hv
                    h_cnt += c_hv
                elif isinstance(raw_hv, Sequence) and not isinstance(
                    raw_hv, (str, bytes, bytearray)
                ):
                    vals = list(raw_hv)[:64]
                    h_out[hk] = ["[REDACTED]" for _ in vals]
                    h_cnt += max(1, len(vals))
                elif raw_hv is not None:
                    h_out[hk] = "[REDACTED]"
                    h_cnt += 1
                else:
                    h_out[hk] = None
            return h_out, h_cnt
        if isinstance(raw_hdrs, Sequence) and not isinstance(raw_hdrs, (str, bytes, bytearray)):
            l_out: list[object] = []
            l_cnt = 0
            for elem in list(raw_hdrs)[:64]:
                if isinstance(elem, Mapping):
                    elem_low_keys = {_safe_str(ek).strip().lower() for ek in elem}
                    has_kv_shape = any(cand in elem_low_keys for cand in ("key", "name", "k")) and any(
                        vcand in elem_low_keys for vcand in ("value", "val", "values", "v")
                    )
                    if not has_kv_shape:
                        sub_hdr_map, sub_hdr_c = _scrub_headers_container(elem, depth + 1)
                        l_out.append(sub_hdr_map)
                        l_cnt += sub_hdr_c
                        continue
                    sub_clean, sub_c = redact_attributes(
                        elem,
                        inherited_db_system=db_sys_hint,
                        inherited_op=op_hint,
                        inherited_table=tbl_hint,
                        inherited_sql_context=has_sql_context,
                        _depth=depth + 1,
                    )
                    low_keys = {k.lower(): k for k in sub_clean}
                    kf = next(
                        (
                            low_keys[cand]
                            for cand in ("key", "name", "k")
                            if cand in low_keys and isinstance(sub_clean[low_keys[cand]], str)
                        ),
                        None,
                    )
                    if kf is not None:
                        hdr_name = str(sub_clean[kf]).strip().lower()
                        if hdr_name not in _SAFE_HTTP_HEADER_NAMES:
                            for vf_cand in ("value", "val", "values", "v"):
                                vf = low_keys.get(vf_cand)
                                if vf is None:
                                    continue
                                cur_v = sub_clean[vf]
                                if isinstance(cur_v, list):
                                    already = all(x == "[REDACTED]" for x in cur_v) and bool(cur_v)
                                    sub_clean[vf] = ["[REDACTED]" for _ in cur_v]
                                    if not already:
                                        sub_c += max(1, len(cur_v))
                                elif cur_v is not None and cur_v != "[REDACTED]":
                                    sub_clean[vf] = "[REDACTED]"
                                    sub_c += 1
                    l_out.append(sub_clean)
                    l_cnt += sub_c
                elif (
                    isinstance(elem, Sequence)
                    and not isinstance(elem, (str, bytes, bytearray))
                    and len(elem) == 2
                ):
                    raw_hk, raw_hv = elem[0], elem[1]
                    hk_s = (
                        raw_hk.decode("utf-8", errors="replace")
                        if isinstance(raw_hk, (bytes, bytearray))
                        else _safe_str(raw_hk)
                    ).strip()
                    hk_low = hk_s.lower()
                    if hk_low in _SAFE_HTTP_HEADER_NAMES:
                        hv_norm = (
                            raw_hv.decode("utf-8", errors="replace")
                            if isinstance(raw_hv, (bytes, bytearray))
                            else raw_hv
                        )
                        sc_hv, c_hv = _scrub_value(hk_low, hv_norm, depth + 1)
                        l_out.append([hk_s, sc_hv])
                        l_cnt += c_hv
                    else:
                        l_out.append([hk_s, "[REDACTED]"])
                        l_cnt += 1
                elif isinstance(elem, str) and ":" in elem:
                    hk_part, _, hv_part = elem.partition(":")
                    hk_s = hk_part.strip()
                    if hk_s.lower() not in _SAFE_HTTP_HEADER_NAMES:
                        l_out.append(f"{hk_s}: [REDACTED]")
                        l_cnt += 1
                    else:
                        sc_s, sc_c = _scrub_str(hk_s.lower(), hv_part.strip())
                        l_out.append(f"{hk_s}: {sc_s}")
                        l_cnt += sc_c
                else:
                    sc_el, el_c = _scrub_value("http.request.header.item", elem, depth + 1)
                    l_out.append(sc_el)
                    l_cnt += el_c
            return l_out, l_cnt
        if raw_hdrs is not None:
            return "[REDACTED]", 1
        return None, 0

    def _scrub_kv_pair_mapping(sub_map: dict[str, object]) -> tuple[dict[str, object], int]:
        extra = 0
        low_to_orig = {k.lower(): k for k in sub_map}
        key_field = next(
            (
                low_to_orig[cand]
                for cand in ("key", "name", "k")
                if cand in low_to_orig and isinstance(sub_map.get(low_to_orig[cand]), str)
            ),
            None,
        )
        if not key_field or not isinstance(sub_map.get(key_field), str):
            return sub_map, extra
        pair_k = str(sub_map[key_field]).strip().lower()
        is_sql_bind_pair = bool(has_sql_context and pair_k in _SQL_BIND_KV_KEYS)
        for val_field in list(sub_map):
            if val_field.lower() not in ("value", "val", "values", "v"):
                continue
            raw_pair_v = sub_map[val_field]
            is_seq = isinstance(raw_pair_v, Sequence) and not isinstance(
                raw_pair_v, (str, bytes, bytearray)
            )
            if _is_headers_container_key(pair_k):
                sc_hdr, hdr_cnt = _scrub_headers_container(raw_pair_v, _depth + 1)
                sub_map[val_field] = sc_hdr
                extra += hdr_cnt
            elif any(tok in pair_k for tok in _RAW_BUFFER_KEY_TOKENS) or is_sql_bind_pair:
                if is_seq:
                    vals = list(raw_pair_v)[:64]
                    already_buf = all(x == "[REDACTED_BUFFER]" for x in vals) and bool(vals)
                    sub_map[val_field] = ["[REDACTED_BUFFER]" for _ in vals]
                    if not already_buf:
                        extra += len(vals)
                elif raw_pair_v is not None:
                    if raw_pair_v != "[REDACTED_BUFFER]":
                        extra += 1
                    sub_map[val_field] = "[REDACTED_BUFFER]"
            elif _is_sensitive_key(pair_k):
                if is_seq:
                    vals = list(raw_pair_v)[:64]
                    already_red = all(x == "[REDACTED]" for x in vals) and bool(vals)
                    sub_map[val_field] = ["[REDACTED]" for _ in vals]
                    if not already_red:
                        extra += len(vals)
                elif raw_pair_v is not None:
                    if raw_pair_v != "[REDACTED]":
                        extra += 1
                    sub_map[val_field] = "[REDACTED]"
            elif is_seq:
                vals = list(raw_pair_v)[:64]
                if vals:
                    sc_pv, pv_cnt = _scrub_value(pair_k, vals, _depth + 1)
                    sub_map[val_field] = sc_pv
                    extra += pv_cnt
            elif raw_pair_v is not None:
                sc_pv, pv_cnt = _scrub_value(pair_k, raw_pair_v, _depth + 1)
                sub_map[val_field] = sc_pv
                extra += pv_cnt
        return sub_map, extra

    _OTLP_ANYVALUE_KEYS = frozenset(
        {
            "stringvalue",
            "string_value",
            "intvalue",
            "int_value",
            "doublevalue",
            "double_value",
            "boolvalue",
            "bool_value",
            "bytesvalue",
            "bytes_value",
            "arrayvalue",
            "array_value",
            "kvlistvalue",
            "kvlist_value",
        }
    )

    def _scrub_value(
        k_low: str, raw_v: Any, depth: int = 0, *, seq_sql_context: bool = False
    ) -> tuple[object, int]:
        if depth > 16:
            return "[REDACTED_NESTED]", 1
        if isinstance(raw_v, Mapping):
            raw_v_low_keys = {_safe_str(mk).strip().lower(): mk for mk in raw_v}
            if raw_v_low_keys and set(raw_v_low_keys) <= _OTLP_ANYVALUE_KEYS:
                av_out: dict[str, object] = {}
                av_cnt = 0
                for low_ak, orig_ak in raw_v_low_keys.items():
                    ak_str = _safe_str(orig_ak)
                    inner_v = raw_v[orig_ak]
                    if low_ak in ("bytesvalue", "bytes_value"):
                        av_out[ak_str] = "[REDACTED_BUFFER]"
                        av_cnt += 1
                    elif low_ak in ("stringvalue", "string_value"):
                        if _is_sensitive_key(k_low):
                            av_out[ak_str] = "[REDACTED]"
                            av_cnt += 1
                        else:
                            sc_sv, c_sv = _scrub_value(
                                k_low, _safe_str(inner_v), depth + 1, seq_sql_context=seq_sql_context
                            )
                            av_out[ak_str] = sc_sv
                            av_cnt += c_sv
                    elif low_ak in ("arrayvalue", "array_value") and isinstance(inner_v, Mapping):
                        arr_vals = inner_v.get("values", [])
                        sc_arr, c_arr = _scrub_value(
                            k_low, arr_vals, depth + 1, seq_sql_context=seq_sql_context
                        )
                        av_out[ak_str] = {**{_safe_str(ik): iv for ik, iv in inner_v.items()}, "values": sc_arr}
                        av_cnt += c_arr
                    elif low_ak in ("kvlistvalue", "kvlist_value") and isinstance(inner_v, Mapping):
                        kv_vals = inner_v.get("values", [])
                        if _is_headers_container_key(k_low):
                            sc_kv, c_kv = _scrub_headers_container(kv_vals, depth + 1)
                        else:
                            sc_kv, c_kv = _scrub_value(
                                k_low, kv_vals, depth + 1, seq_sql_context=seq_sql_context
                            )
                        av_out[ak_str] = {**{_safe_str(ik): iv for ik, iv in inner_v.items()}, "values": sc_kv}
                        av_cnt += c_kv
                    else:
                        av_out[ak_str] = inner_v
                return av_out, av_cnt
            sub_map, sub_cnt = redact_attributes(
                raw_v,
                inherited_db_system=db_sys_hint,
                inherited_op=op_hint,
                inherited_table=tbl_hint,
                inherited_sql_context=(
                    has_sql_context
                    or seq_sql_context
                    or k_low in ("sql", "db")
                    or k_low in _SQL_ATTR_KEYS
                ),
                _depth=depth + 1,
            )
            return sub_map, sub_cnt
        if isinstance(raw_v, (bytes, bytearray)):
            return "[REDACTED_BUFFER]", 1
        if isinstance(raw_v, str):
            return _scrub_str(k_low, raw_v)
        if isinstance(raw_v, Sequence) and not isinstance(raw_v, (str, bytes, bytearray)):
            seq_items = list(raw_v)[:64]
            seq_has_sql_kv = (
                has_sql_context
                or seq_sql_context
                or k_low in ("sql", "db")
                or k_low in _SQL_ATTR_KEYS
                or _sequence_has_sql_kv_context(seq_items)
            )
            seq_out: list[object] = []
            seq_cnt = 0
            for elem in seq_items:
                if (
                    isinstance(elem, Sequence)
                    and not isinstance(elem, (str, bytes, bytearray))
                    and len(elem) == 2
                    and isinstance(elem[0], (str, bytes, bytearray))
                ):
                    ek_s = (
                        elem[0].decode("utf-8", errors="replace")
                        if isinstance(elem[0], (bytes, bytearray))
                        else elem[0]
                    ).strip()
                    ek_low = ek_s.lower()
                    if any(tok in ek_low for tok in _RAW_BUFFER_KEY_TOKENS):
                        seq_out.append([ek_s, "[REDACTED_BUFFER]"])
                        seq_cnt += 1
                        continue
                    if _is_sensitive_key(ek_low):
                        seq_out.append([ek_s, "[REDACTED]"])
                        seq_cnt += 1
                        continue
                    sc_ev, ev_cnt = _scrub_value(
                        ek_low, elem[1], depth + 1, seq_sql_context=seq_has_sql_kv
                    )
                    seq_out.append([ek_s, sc_ev])
                    seq_cnt += ev_cnt
                    continue
                sc_el, el_cnt = _scrub_value(
                    k_low, elem, depth + 1, seq_sql_context=seq_has_sql_kv
                )
                seq_out.append(sc_el)
                seq_cnt += el_cnt
            return seq_out, seq_cnt
        if isinstance(raw_v, (int, float, bool)) or raw_v is None:
            return raw_v, 0
        raw_s = _safe_str(raw_v)[:256]
        sc_s = _BEARER_INLINE_RE.sub(r"\1 [REDACTED]", raw_s)
        return sc_s, (1 if sc_s != raw_s else 0)

    for raw_k, raw_v in raw_attrs.items():
        k = _safe_str(raw_k).strip()
        k_low = k.lower()
        if any(tok in k_low for tok in _RAW_BUFFER_KEY_TOKENS):
            cleaned[k] = "[REDACTED_BUFFER]"
            redacted_count += 1
            continue
        if k_low == "values" and has_sql_context and not is_kv_pair:
            if isinstance(raw_v, Sequence) and not isinstance(raw_v, (str, bytes, bytearray)):
                vals = list(raw_v)[:64]
                cleaned[k] = ["[REDACTED_BUFFER]" for _ in vals]
                redacted_count += len(vals)
            elif raw_v is not None:
                cleaned[k] = "[REDACTED_BUFFER]"
                redacted_count += 1
            else:
                cleaned[k] = None
            continue
        if _is_headers_container_key(k_low):
            sc_hdrs, hdr_cnt = _scrub_headers_container(raw_v, _depth)
            cleaned[k] = sc_hdrs
            redacted_count += hdr_cnt
            continue
        if _is_sensitive_key(k_low):
            cleaned[k] = "[REDACTED]"
            redacted_count += 1
            continue
        sc_val, v_cnt = _scrub_value(k_low, raw_v, _depth)
        cleaned[k] = sc_val
        redacted_count += v_cnt
    if is_kv_candidate:
        cleaned, kv_extra = _scrub_kv_pair_mapping(cleaned)
        redacted_count += kv_extra
    return cleaned, redacted_count


@dataclass(frozen=True)
class ObservedRuntimeTransition:
    """Single normalized, payload-redacted runtime span or eBPF L7 flow event."""

    source: Literal["otel", "ebpf"]
    protocol: Literal["http", "sql", "rpc", "ipc"]
    service_name: str
    peer_service: str = ""
    http_method: str = ""
    http_route: str = ""
    db_operation: str = ""
    db_table: str = ""
    rpc_service: str = ""
    rpc_method: str = ""
    code_filepath: str = ""
    code_function: str = ""
    redacted_summary: str = ""
    attributes: dict[str, object] = field(default_factory=dict)
    redacted_fields: int = 0
    trace_id: str = ""
    span_id: str = ""
    parent_span_id: str = ""
    span_kind: str = ""


_OTEL_SPAN_KIND_BY_INT: dict[int, str] = {
    1: "INTERNAL",
    2: "SERVER",
    3: "CLIENT",
    4: "PRODUCER",
    5: "CONSUMER",
}
_OTEL_SPAN_KIND_STRS: frozenset[str] = frozenset(
    {"INTERNAL", "SERVER", "CLIENT", "PRODUCER", "CONSUMER"}
)


def _normalize_otel_span_kind(raw_kind: object) -> str:
    if raw_kind is None or isinstance(raw_kind, bool):
        return ""
    if isinstance(raw_kind, int):
        return _OTEL_SPAN_KIND_BY_INT.get(raw_kind, "")
    s = _safe_str(raw_kind).strip().upper()
    if s.isascii() and s.isdigit() and len(s) <= 5:
        return _OTEL_SPAN_KIND_BY_INT.get(int(s), "")
    if s.startswith("SPAN_KIND_"):
        s = s.removeprefix("SPAN_KIND_")
    return s if s in _OTEL_SPAN_KIND_STRS else ""


def _clean_span_ident(raw_val: object) -> str:
    if raw_val is None or isinstance(raw_val, bool):
        return ""
    s = re.sub(r"[^A-Za-z0-9_.:/-]+", "", _safe_str(raw_val).strip())[:128]
    if s and set(s) == {"0"}:
        return ""
    return s


def _otel_any_value(val_obj: Any, depth: int = 0) -> Any:
    if depth > 16:
        if isinstance(val_obj, (Mapping, Sequence)) and not isinstance(
            val_obj, (str, bytes, bytearray)
        ):
            return "[REDACTED_NESTED]"
        return val_obj
    if not isinstance(val_obj, Mapping):
        if isinstance(val_obj, Sequence) and not isinstance(val_obj, (str, bytes, bytearray)):
            return [_otel_any_value(v, depth + 1) for v in list(val_obj)[:64]]
        return val_obj
    for key in ("stringValue", "intValue", "doubleValue", "boolValue"):
        if key in val_obj:
            return val_obj[key]
    if "bytesValue" in val_obj:
        return b"<bytes>"
    if "arrayValue" in val_obj and isinstance(val_obj["arrayValue"], Mapping):
        vals = val_obj["arrayValue"].get("values", [])
        if isinstance(vals, list):
            return [_otel_any_value(v, depth + 1) for v in vals[:32]]
    if "kvlistValue" in val_obj and isinstance(val_obj["kvlistValue"], Mapping):
        vals = val_obj["kvlistValue"].get("values", [])
        if isinstance(vals, list):
            return _otel_kv_list_to_dict(vals, depth + 1)
    return {_safe_str(k): _otel_any_value(v, depth + 1) for k, v in list(val_obj.items())[:64]}


def _otel_kv_list_to_dict(items: Sequence[Any], depth: int = 0) -> dict[str, Any]:
    out: dict[str, Any] = {}
    for item in items:
        if not isinstance(item, Mapping):
            continue
        item_low = {_safe_str(ik).strip().lower(): iv for ik, iv in item.items()}
        key_name = next((ck for ck in ("key", "name", "k") if ck in item_low), None)
        if key_name is not None:
            k_str = _safe_str(item_low[key_name])
            if "value" in item_low:
                out[k_str] = _otel_any_value(item_low["value"], depth + 1)
            elif "val" in item_low:
                out[k_str] = _otel_any_value(item_low["val"], depth + 1)
            elif "values" in item_low:
                raw_vs = item_low["values"]
                if isinstance(raw_vs, Sequence) and not isinstance(raw_vs, (str, bytes, bytearray)):
                    out[k_str] = [_otel_any_value(v, depth + 1) for v in list(raw_vs)[:64]]
                else:
                    out[k_str] = _otel_any_value(raw_vs, depth + 1)
            elif "v" in item_low:
                out[k_str] = _otel_any_value(item_low["v"], depth + 1)
            else:
                out[k_str] = None
    return out


def _extract_sql_table_and_op(
    sql_text: str,
    explicit_op: str,
    explicit_tbl: str,
    *,
    db_system: str = "",
) -> tuple[str, str]:
    _redacted, _changed, op, tbl = _scan_sql_statement(
        sql_text,
        db_system=db_system,
        explicit_op=explicit_op,
        explicit_table=explicit_tbl,
    )
    return op, tbl


def _transition_from_attr_dict(
    source_kind: Literal["otel", "ebpf"],
    service_name: str,
    span_name: str,
    raw_attrs: Mapping[str, Any],
) -> tuple[ObservedRuntimeTransition | None, int]:
    span_has_sql = _str_looks_like_sql(span_name)
    redacted_map, red_cnt = redact_attributes(raw_attrs, inherited_sql_context=span_has_sql)
    http_method = _safe_str(
        raw_attrs.get("http.request.method")
        or raw_attrs.get("http.method")
        or raw_attrs.get("method")
        or ""
    ).strip().upper()
    raw_route = _safe_str(
        raw_attrs.get("http.route")
        or raw_attrs.get("url.path")
        or raw_attrs.get("http.target")
        or raw_attrs.get("url.full")
        or raw_attrs.get("http.url")
        or raw_attrs.get("path")
        or raw_attrs.get("url")
        or ""
    ).strip()
    clean_route, red_url, u_red = redact_url_target(raw_route) if raw_route else ("", "", False)
    if u_red:
        red_cnt += 1

    db_sys = _safe_str(
        raw_attrs.get("db.system")
        or raw_attrs.get("db.system.name")
        or raw_attrs.get("db_system")
        or ""
    ).strip()
    raw_sql = _safe_str(
        raw_attrs.get("db.statement")
        or raw_attrs.get("db.sql.statement")
        or raw_attrs.get("db.query.text")
        or raw_attrs.get("db.query")
        or raw_attrs.get("sql")
        or raw_attrs.get("sql.query")
        or raw_attrs.get("sql.statement")
        or raw_attrs.get("query")
        or raw_attrs.get("statement")
        or ""
    ).strip()
    explicit_op_str = _safe_str(
        raw_attrs.get("db.operation") or raw_attrs.get("db.operation.name") or ""
    )
    explicit_tbl_str = _safe_str(
        raw_attrs.get("db.sql.table")
        or raw_attrs.get("db.collection.name")
        or raw_attrs.get("table")
        or ""
    )
    db_op, db_tbl = _extract_sql_table_and_op(
        raw_sql,
        explicit_op_str,
        explicit_tbl_str,
        db_system=db_sys,
    )
    raw_span_name = span_name.strip()
    m_span_http = _HTTP_SPAN_VERB_TARGET_RE.match(raw_span_name)
    span_url_counted = False
    if (
        not raw_route
        and not (db_tbl or db_op or db_sys or raw_sql)
        and m_span_http is not None
        and not m_span_http.group("rest").strip()
    ):
        cand_tgt = m_span_http.group("target")
        if cand_tgt.startswith("/") or "://" in cand_tgt or ("@" in cand_tgt and "/" in cand_tgt):
            http_method = http_method or m_span_http.group("method").upper()
            clean_route, red_url, u_red = redact_url_target(cand_tgt)
            if u_red:
                red_cnt += 1
                span_url_counted = True
    inline_span_redacted = ""
    if (
        not raw_sql
        and not clean_route
        and not http_method
        and raw_span_name
        and _looks_like_inline_sql(raw_span_name)
    ):
        sp_red, sp_was_red, sp_op, sp_tbl = _scan_sql_statement(
            raw_span_name,
            db_system=db_sys,
            explicit_op=explicit_op_str,
            explicit_table=explicit_tbl_str,
        )
        inline_span_redacted = sp_red
        if sp_was_red:
            red_cnt += 1
        if sp_op and not db_op:
            db_op = sp_op
        if sp_tbl and not db_tbl:
            db_tbl = sp_tbl

    def _scrub_free_field(val: str, *, skip_url_count: bool = False) -> str:
        nonlocal red_cnt
        if not val:
            return ""
        rem = val[:1024]
        prefix_parts: list[str] = []
        first_url = True
        for _ in range(4):
            m_verb = _HTTP_SPAN_VERB_TARGET_RE.match(rem)
            if m_verb is None:
                break
            tgt = m_verb.group("target")
            if (
                tgt.startswith("/")
                or "://" in tgt
                or "?" in tgt
                or "@" in tgt
                or ";" in tgt
                or "#" in tgt
            ):
                _p, red_tgt, was_vt = redact_url_target(tgt)
                if was_vt and not (skip_url_count and first_url):
                    red_cnt += 1
                first_url = False
                prefix_parts.append(f"{m_verb.group('prefix')}{red_tgt}")
                rest_part = m_verb.group("rest").strip()
                if not rest_part:
                    rem = ""
                    break
                rem = rest_part
            else:
                break

        cur = rem
        if cur:
            if (
                (("?" in cur or "@" in cur or ";" in cur or "#" in cur) and ("://" in cur or cur.startswith("/")))
                or ("@" in cur and " " not in cur and "/" in cur)
                or _COMPOUND_SCHEME_URI_RE.match(cur) is not None
            ):
                _p, cur, was_u = redact_url_target(cur)
                if was_u and not (skip_url_count and first_url):
                    red_cnt += 1
            elif _looks_like_inline_sql(cur):
                cur, was_sql = _redact_sql_statement(
                    cur,
                    db_system=db_sys,
                    explicit_op=explicit_op_str,
                    explicit_table=explicit_tbl_str,
                )
                if was_sql:
                    red_cnt += 1
            else:
                cur, was_emb_sql = _scrub_embedded_sql(
                    cur,
                    db_system=db_sys,
                    explicit_op=explicit_op_str,
                    explicit_table=explicit_tbl_str,
                )
                if was_emb_sql:
                    red_cnt += 1
            if "://" in cur:
                free_uri_hits = 0

                def _sub_free_uri(match: re.Match[str]) -> str:
                    nonlocal free_uri_hits
                    raw_tok = match.group(0)
                    _fp, red_tok, was_tok = redact_url_target(raw_tok)
                    if was_tok or (red_tok and red_tok != raw_tok):
                        free_uri_hits += 1
                        return red_tok
                    return raw_tok

                cur = _INLINE_URI_TOKEN_RE.sub(_sub_free_uri, cur)
                red_cnt += free_uri_hits

        assembled = " ".join([*prefix_parts, *([cur] if cur else [])]) if prefix_parts else cur
        scrubbed = _BEARER_INLINE_RE.sub(r"\1 [REDACTED]", assembled)
        if scrubbed != assembled:
            red_cnt += 1
        return scrubbed[:256]

    service_name = _scrub_free_field(service_name.strip()) or "service"
    span_name = (
        _BEARER_INLINE_RE.sub(r"\1 [REDACTED]", inline_span_redacted)[:256]
        if inline_span_redacted
        else _scrub_free_field(raw_span_name, skip_url_count=span_url_counted)
    )
    rpc_sys = _safe_str(raw_attrs.get("rpc.system") or "").strip().lower()
    rpc_svc = _scrub_free_field(_safe_str(raw_attrs.get("rpc.service") or "").strip())
    rpc_mth = _scrub_free_field(_safe_str(raw_attrs.get("rpc.method") or "").strip())
    peer = _scrub_free_field(_safe_str(raw_attrs.get("peer.service") or raw_attrs.get("dst_service") or "").strip())
    code_fp = _scrub_free_field(_safe_str(raw_attrs.get("code.filepath") or "").strip())
    code_fn = _scrub_free_field(_safe_str(raw_attrs.get("code.function") or "").strip())

    if db_tbl or db_op or db_sys or raw_sql or inline_span_redacted:
        red_sql = _safe_str(
            redacted_map.get("db.statement")
            or redacted_map.get("db.sql.statement")
            or redacted_map.get("db.query.text")
            or redacted_map.get("db.query")
            or redacted_map.get("sql")
            or redacted_map.get("sql.query")
            or redacted_map.get("sql.statement")
            or redacted_map.get("query")
            or redacted_map.get("statement")
            or inline_span_redacted
            or f"{db_op} {db_tbl}"
        ).strip()
        return (
            ObservedRuntimeTransition(
                source=source_kind,
                protocol="sql",
                service_name=service_name,
                peer_service=peer,
                db_operation=db_op or "SELECT",
                db_table=db_tbl,
                code_filepath=code_fp,
                code_function=code_fn,
                redacted_summary=red_sql[:240],
                attributes=redacted_map,
                redacted_fields=red_cnt,
            ),
            red_cnt,
        )
    if clean_route or http_method:
        mth = http_method or "GET"
        return (
            ObservedRuntimeTransition(
                source=source_kind,
                protocol="http",
                service_name=service_name,
                peer_service=peer,
                http_method=mth,
                http_route=clean_route or "/",
                code_filepath=code_fp,
                code_function=code_fn,
                redacted_summary=f"{mth} {red_url or clean_route}"[:240],
                attributes=redacted_map,
                redacted_fields=red_cnt,
            ),
            red_cnt,
        )
    if rpc_svc or rpc_mth or rpc_sys:
        proto: Literal["rpc", "ipc"] = "ipc" if rpc_sys in ("xpc", "mach", "unix", "vsock") else "rpc"
        return (
            ObservedRuntimeTransition(
                source=source_kind,
                protocol=proto,
                service_name=service_name,
                peer_service=peer or rpc_svc,
                rpc_service=rpc_svc,
                rpc_method=rpc_mth or span_name,
                code_filepath=code_fp,
                code_function=code_fn,
                redacted_summary=f"{rpc_sys or proto}:{rpc_svc}/{rpc_mth or span_name}"[:240],
                attributes=redacted_map,
                redacted_fields=red_cnt,
            ),
            red_cnt,
        )
    if peer or code_fn:
        return (
            ObservedRuntimeTransition(
                source=source_kind,
                protocol="ipc",
                service_name=service_name,
                peer_service=peer,
                rpc_method=code_fn or span_name,
                code_filepath=code_fp,
                code_function=code_fn,
                redacted_summary=f"ipc:{service_name}->{peer or code_fn}"[:240],
                attributes=redacted_map,
                redacted_fields=red_cnt,
            ),
            red_cnt,
        )
    return None, red_cnt


def _attach_otel_span_envelope(
    tr: ObservedRuntimeTransition,
    sp: Mapping[str, Any],
    sp_attrs: Mapping[str, Any],
) -> ObservedRuntimeTransition:
    t_id = _clean_span_ident(sp.get("traceId") or sp.get("trace_id") or sp_attrs.get("trace_id"))
    s_id = _clean_span_ident(sp.get("spanId") or sp.get("span_id") or sp_attrs.get("span_id"))
    p_id = _clean_span_ident(
        sp.get("parentSpanId") or sp.get("parent_span_id") or sp_attrs.get("parent_span_id")
    )
    raw_kind = (
        sp.get("kind")
        if "kind" in sp
        else (sp.get("spanKind") or sp.get("span_kind") or sp_attrs.get("span.kind"))
    )
    s_kind = _normalize_otel_span_kind(raw_kind)
    return replace(
        tr,
        trace_id=t_id,
        span_id=s_id,
        parent_span_id=p_id,
        span_kind=s_kind,
    )


def parse_otel_traces(
    raw_path: Path | str,
    *,
    repo_root: Path | None = None,
    allow_external: bool = False,
) -> tuple[list[ObservedRuntimeTransition], int]:
    """Parse an OTLP JSON trace capture into redacted `ObservedRuntimeTransition` items."""
    _resolved, data = read_bounded_json(
        raw_path, repo_root=repo_root, allow_external=allow_external
    )
    transitions: list[ObservedRuntimeTransition] = []
    total_redacted = 0

    if isinstance(data, Mapping) and isinstance(data.get("resourceSpans"), list):
        for res_span in data["resourceSpans"]:
            if not isinstance(res_span, Mapping):
                continue
            res_obj = res_span.get("resource", {})
            res_attrs = (
                _otel_kv_list_to_dict(res_obj.get("attributes", []))
                if isinstance(res_obj, Mapping) and isinstance(res_obj.get("attributes"), list)
                else (dict(res_obj.get("attributes", {})) if isinstance(res_obj, Mapping) and isinstance(res_obj.get("attributes"), Mapping) else {})
            )
            svc_name = _safe_str(res_attrs.get("service.name") or "service")
            scopes = res_span.get("scopeSpans") or res_span.get("instrumentationLibrarySpans") or []
            if not isinstance(scopes, list):
                continue
            for sc in scopes:
                if not isinstance(sc, Mapping) or not isinstance(sc.get("spans"), list):
                    continue
                for sp in sc["spans"]:
                    if not isinstance(sp, Mapping):
                        continue
                    raw_sp_attrs = sp.get("attributes", {})
                    sp_attrs = (
                        _otel_kv_list_to_dict(raw_sp_attrs)
                        if isinstance(raw_sp_attrs, list)
                        else (dict(raw_sp_attrs) if isinstance(raw_sp_attrs, Mapping) else {})
                    )
                    merged_attrs = {**res_attrs, **sp_attrs}
                    tr, r_cnt = _transition_from_attr_dict(
                        "otel", svc_name, _safe_str(sp.get("name") or ""), merged_attrs
                    )
                    total_redacted += r_cnt
                    if tr is not None:
                        transitions.append(_attach_otel_span_envelope(tr, sp, sp_attrs))
    else:
        raw_list = (
            data.get("spans", [])
            if isinstance(data, Mapping) and isinstance(data.get("spans", []), list)
            else (data if isinstance(data, list) else None)
        )
        if raw_list is None:
            raise ValueError("Unrecognized OTLP trace schema; expected resourceSpans or spans list.")
        for sp in raw_list:
            if not isinstance(sp, Mapping):
                continue
            raw_sp_attrs = sp.get("attributes", sp)
            sp_attrs = (
                _otel_kv_list_to_dict(raw_sp_attrs)
                if isinstance(raw_sp_attrs, list)
                else (dict(raw_sp_attrs) if isinstance(raw_sp_attrs, Mapping) else {})
            )
            svc_name = _safe_str(sp.get("service_name") or sp_attrs.get("service.name") or "service")
            tr, r_cnt = _transition_from_attr_dict(
                "otel", svc_name, _safe_str(sp.get("name") or ""), sp_attrs
            )
            total_redacted += r_cnt
            if tr is not None:
                transitions.append(_attach_otel_span_envelope(tr, sp, sp_attrs))

    return transitions, total_redacted


def parse_ebpf_flows(
    raw_path: Path | str,
    *,
    repo_root: Path | None = None,
    allow_external: bool = False,
) -> tuple[list[ObservedRuntimeTransition], int]:
    """Parse JSONL or JSON array eBPF L7 HTTP/SQL/gRPC flow captures with default redaction."""
    _resolved, raw_bytes = read_bounded_regular_bytes(
        raw_path, repo_root=repo_root, allow_external=allow_external
    )
    text = raw_bytes.decode("utf-8-sig").strip()
    if "\x00" in text:
        raise ValueError(f"Refusing eBPF flow capture '{raw_path}' containing NUL bytes.")
    if not text:
        return [], 0

    records: list[Mapping[str, Any]] = []
    if text.startswith("["):
        ensure_json_depth_bounded(text)
        parsed = json.loads(text, parse_int=_parse_bounded_json_int)
        if not isinstance(parsed, list):
            raise ValueError("Expected JSON array in eBPF flow capture.")
        records = [r for r in parsed if isinstance(r, Mapping)]
    else:
        for line_no, raw_line in enumerate(text.splitlines(), start=1):
            s = raw_line.strip()
            if not s or s.startswith("#"):
                continue
            ensure_json_depth_bounded(s)
            try:
                obj = json.loads(s, parse_int=_parse_bounded_json_int)
            except json.JSONDecodeError as exc:
                raise ValueError(f"Invalid JSONL at line {line_no} in '{raw_path}': {exc}") from exc
            if isinstance(obj, Mapping):
                records.append(obj)

    transitions: list[ObservedRuntimeTransition] = []
    total_redacted = 0
    for rec in records[:16384]:
        flat: dict[str, Any] = dict(rec)
        l7 = rec.get("l7") if isinstance(rec.get("l7"), Mapping) else {}
        for sub_key in ("http", "sql", "db", "grpc", "rpc"):
            sub_obj = l7.get(sub_key) or rec.get(sub_key)
            if isinstance(sub_obj, Mapping):
                for k, v in sub_obj.items():
                    flat.setdefault(k, v)
                if sub_key == "grpc" and "service" in sub_obj:
                    flat.setdefault("rpc.system", "grpc")
                    flat.setdefault("rpc.service", sub_obj.get("service"))
                    flat.setdefault("rpc.method", sub_obj.get("method", ""))
        src_obj = rec.get("source") if isinstance(rec.get("source"), Mapping) else {}
        dst_obj = rec.get("destination") if isinstance(rec.get("destination"), Mapping) else {}
        svc_name = str(
            rec.get("service_name")
            or rec.get("src_service")
            or rec.get("process")
            or src_obj.get("workload")
            or src_obj.get("pod_name")
            or "ebpf-source"
        )
        if dst_obj and "dst_service" not in flat:
            flat["dst_service"] = str(dst_obj.get("workload") or dst_obj.get("pod_name") or "")
        if "headers" in flat and isinstance(flat["headers"], Mapping):
            for hk, hv in flat["headers"].items():
                flat[f"http.request.header.{hk}"] = hv
            flat.pop("headers", None)
        tr, r_cnt = _transition_from_attr_dict("ebpf", svc_name, str(rec.get("type") or "flow"), flat)
        total_redacted += r_cnt
        if tr is not None:
            transitions.append(tr)
    return transitions, total_redacted


def _http_path_matches(template_path: str, observed_path: str) -> bool:
    t_norm = "/" + template_path.strip("/")
    o_norm = "/" + observed_path.strip("/")
    if t_norm == o_norm:
        return True
    t_segs = [s for s in t_norm.split("/") if s]
    o_segs = [s for s in o_norm.split("/") if s]
    if len(t_segs) != len(o_segs):
        return False
    for ts, os_seg in zip(t_segs, o_segs, strict=True):
        if (ts.startswith("{") and ts.endswith("}")) or ts.startswith(":"):
            continue
        if ts != os_seg:
            return False
    return True


def _norm_tok(raw: str) -> str:
    return re.sub(r"[^a-z0-9]+", "", raw.lower())


_GENERIC_RUNTIME_SERVICES: frozenset[str] = frozenset(
    {"", "service", "ebpf-source", "unknown_service", "unknownservice", "ebpfsource"}
)
_GENERIC_FILE_STEMS: frozenset[str] = frozenset(
    {"index", "page", "layout", "route", "main", "app", "__init__", "models", "views", "urls", "service", "services"}
)


def _non_generic_svc_norm(service_name: str) -> str:
    raw = service_name.strip().lower()
    if raw in _GENERIC_RUNTIME_SERVICES:
        return ""
    norm = _norm_tok(raw)
    return "" if norm in _GENERIC_RUNTIME_SERVICES else norm


def _service_matches_node(svc_norm: str, node: Any) -> bool:
    if not svc_norm or len(svc_norm) < 3 or node is None:
        return False
    raw_lbl = str(getattr(node, "label", "") or "")
    nsf = str(getattr(node, "source_file", "") or "").replace("\\", "/")
    tail = nsf.rsplit("/", 1)[-1]
    nsf_no_ext = nsf.rsplit(".", 1)[0] if "." in tail else nsf
    lbl_norm = _norm_tok(raw_lbl)
    sf_norm = _norm_tok(nsf_no_ext)
    if len(svc_norm) < 6:
        toks = {
            _norm_tok(t)
            for part in (raw_lbl, nsf_no_ext)
            for t in re.split(r"[^A-Za-z0-9]+", part)
            if t
        }
        return svc_norm in toks or svc_norm == lbl_norm or svc_norm == sf_norm
    return (bool(lbl_norm) and svc_norm in lbl_norm) or (bool(sf_norm) and svc_norm in sf_norm)


def _filepath_or_func_matches(
    code_filepath: str,
    code_function: str,
    node: Any,
    symbol_links: Sequence[str] = (),
) -> bool:
    if node is None:
        return False
    fp = code_filepath.strip().replace("\\", "/").lstrip("./").lower()
    nsf = str(getattr(node, "source_file", "") or "").strip().replace("\\", "/").lstrip("./").lower()
    has_fp = False
    if fp and nsf:
        if fp == nsf or fp.endswith("/" + nsf) or ("/" in fp and nsf.endswith("/" + fp)):
            has_fp = True
        elif "/" not in fp:
            stem = PurePosixPath(fp).stem
            if fp == PurePosixPath(nsf).name and stem not in _GENERIC_FILE_STEMS:
                has_fp = True
    if fp and nsf and not has_fp:
        return False

    fn_raw = code_function.strip()
    fn_short = fn_raw.rpartition(".")[2] if "." in fn_raw else fn_raw
    has_fn = False
    explicit_fn_callers = False
    if fn_short:
        for lnk in symbol_links:
            lhs, _sep, _rhs = str(lnk).partition("->")
            lhs_s = lhs.strip()
            if lhs_s and lhs_s != "*" and " " not in lhs_s and not lhs_s.startswith("/"):
                explicit_fn_callers = True
                if lhs_s == fn_short:
                    has_fn = True
                    break
        if not has_fn and not explicit_fn_callers:
            fn_norm = _norm_tok(fn_short)
            nsf_stem = PurePosixPath(nsf).stem if nsf else ""
            if len(fn_norm) >= 4 and (
                fn_norm == _norm_tok(str(getattr(node, "label", "") or ""))
                or (nsf_stem not in _GENERIC_FILE_STEMS and fn_norm == _norm_tok(nsf_stem))
            ):
                has_fn = True

    if fp:
        return (has_fp and has_fn) if (fn_short and explicit_fn_callers) else has_fp
    return has_fn if fn_short else False


def _positive_http_caller_matches(
    tr: ObservedRuntimeTransition,
    parent_span: ObservedRuntimeTransition | None,
    src_node: Any,
    symbol_links: Sequence[str] = (),
) -> bool:
    if src_node is None:
        return False
    if tr.span_kind != "SERVER":
        if (tr.code_filepath or tr.code_function) and _filepath_or_func_matches(
            tr.code_filepath, tr.code_function, src_node, symbol_links
        ):
            return True
        if tr.span_kind == "CLIENT" or tr.source == "ebpf":
            c_svc = _non_generic_svc_norm(tr.service_name)
            if c_svc and _service_matches_node(c_svc, src_node):
                return True
    if parent_span is not None:
        if (parent_span.code_filepath or parent_span.code_function) and _filepath_or_func_matches(
            parent_span.code_filepath, parent_span.code_function, src_node, symbol_links
        ):
            return True
        p_svc = _non_generic_svc_norm(parent_span.service_name)
        if p_svc and _service_matches_node(p_svc, src_node):
            return True
    return False


def _route_helper_edge_scoped(edge_obj: Any, tr: ObservedRuntimeTransition) -> bool:
    links = getattr(edge_obj, "symbol_links", None) or ()
    mth_prefix = f"{tr.http_method.upper()} "
    fn_short = (
        tr.code_function.strip().rpartition(".")[2] or tr.code_function.strip()
        if (tr.span_kind != "CLIENT" and tr.code_function)
        else ""
    )
    for raw_link in links:
        lhs, _sep, rhs = str(raw_link).partition("->")
        lhs_s = lhs.strip()
        if lhs_s.upper().startswith(mth_prefix):
            l_path = lhs_s[len(mth_prefix) :].strip()
            if l_path and _http_path_matches(l_path, tr.http_route):
                return True
        elif (lhs_s.startswith("/") and _http_path_matches(lhs_s, tr.http_route)) or (
            fn_short and (lhs_s == fn_short or rhs.strip() == fn_short)
        ):
            return True
    return False


def correlate_traces_and_flows(
    report: Any,
    transitions: Sequence[ObservedRuntimeTransition],
) -> dict[str, object]:
    """Partition transitions into `corroborated_edges`, `static_dark_matter`, & `runtime_only`."""
    nodes = list(getattr(report, "nodes", ()))
    edges = list(getattr(report, "edges", ()))
    chains = list(getattr(report, "chains", ()))
    node_by_id = {n.id: n for n in nodes}

    edge_hits: dict[str, int] = {e.id: 0 for e in edges}
    edge_sources: dict[str, set[str]] = {e.id: set() for e in edges}
    edge_samples: dict[str, list[str]] = {e.id: [] for e in edges}
    node_hits: dict[str, int] = {n.id: 0 for n in nodes}
    blind_spots: dict[tuple[str, str, str], dict[str, Any]] = {}

    route_nodes = [n for n in nodes if n.http_paths and getattr(n, "tier", "") != "display"]
    truth_nodes = [n for n in nodes if n.tier == "truth"]
    manip_nodes = [n for n in nodes if n.tier == "manipulate"]

    def _credit_edge(edge_obj: Any, src_kind: str, sample: str) -> None:
        eid = edge_obj.id
        edge_hits[eid] = edge_hits.get(eid, 0) + 1
        edge_sources.setdefault(eid, set()).add(src_kind)
        if len(edge_samples.setdefault(eid, [])) < 5 and sample not in edge_samples[eid]:
            edge_samples[eid].append(sample)
        node_hits[edge_obj.source_id] = node_hits.get(edge_obj.source_id, 0) + 1
        node_hits[edge_obj.target_id] = node_hits.get(edge_obj.target_id, 0) + 1

    span_by_key: dict[tuple[str, str], ObservedRuntimeTransition] = {
        (t.trace_id, t.span_id): t for t in transitions if t.trace_id and t.span_id
    }
    exercised_handlers_by_ctx: dict[tuple[str, str], set[str]] = {}
    exercised_handlers_by_span: dict[tuple[str, str], set[str]] = {}

    def _resolve_http_match(
        tr: ObservedRuntimeTransition,
    ) -> tuple[list[Any], set[str], list[Any], list[Any]]:
        raw_rns = [
            rn
            for rn in route_nodes
            if (not rn.http_methods or tr.http_method in rn.http_methods)
            and any(_http_path_matches(hp, tr.http_route) for hp in rn.http_paths)
        ]
        if not raw_rns:
            return [], set(), [], []
        matched_rns = list(raw_rns)
        if len(matched_rns) > 1 and tr.span_kind != "CLIENT" and (tr.code_filepath or tr.code_function):
            fp_sub = [
                rn for rn in matched_rns if _filepath_or_func_matches(tr.code_filepath, tr.code_function, rn)
            ]
            if fp_sub:
                matched_rns = fp_sub
        if len(matched_rns) > 1:
            tgt_svc = _non_generic_svc_norm(
                (tr.peer_service or tr.service_name)
                if (tr.span_kind == "CLIENT" or tr.source == "ebpf")
                else tr.service_name
            )
            if tgt_svc:
                svc_sub = [rn for rn in matched_rns if _service_matches_node(tgt_svc, rn)]
                if svc_sub:
                    matched_rns = svc_sub

        parent_sp = span_by_key.get((tr.trace_id, tr.parent_span_id)) if (tr.trace_id and tr.parent_span_id) else None
        cand_ids = {rn.id for rn in matched_rns}
        pos_callers = [
            e
            for e in edges
            if e.kind in ("queries_endpoint", "mutates_endpoint", "uses_client")
            and e.target_id in cand_ids
            and _positive_http_caller_matches(tr, parent_sp, node_by_id.get(e.source_id), e.symbol_links)
        ]
        if len(matched_rns) > 1:
            disambig_tgts = {e.target_id for e in pos_callers}
            if len(disambig_tgts) == 1:
                matched_rns = [rn for rn in matched_rns if rn.id in disambig_tgts]
                cand_ids = disambig_tgts
            else:
                return matched_rns, set(), [], []
        if len({e.source_id for e in pos_callers}) > 1:
            exact_callers = [
                e
                for e in pos_callers
                if (tr.code_filepath or tr.code_function)
                and _filepath_or_func_matches(tr.code_filepath, tr.code_function, node_by_id.get(e.source_id), e.symbol_links)
            ]
            pos_callers = exact_callers if len({e.source_id for e in exact_callers}) == 1 else []
        scoped_helpers = (
            [
                e
                for e in edges
                if e.kind == "calls_helper" and e.source_id in cand_ids and _route_helper_edge_scoped(e, tr)
            ]
            if len(cand_ids) == 1
            else []
        )
        return matched_rns, cand_ids, pos_callers, scoped_helpers

    # Pre-index exercised route handlers across traces/services so out-of-order child SQL spans join cleanly.
    for tr in transitions:
        if tr.protocol != "http":
            continue
        _rns, _nids, _callers, scoped_h = _resolve_http_match(tr)
        if not scoped_h:
            continue
        h_targets = {e.target_id for e in scoped_h}
        if tr.trace_id and tr.span_id:
            exercised_handlers_by_span.setdefault((tr.trace_id, tr.span_id), set()).update(h_targets)
        if tr.trace_id:
            exercised_handlers_by_ctx.setdefault(("trace", tr.trace_id), set()).update(h_targets)
        svc_k = _non_generic_svc_norm(tr.service_name)
        if svc_k:
            exercised_handlers_by_ctx.setdefault(("svc", svc_k), set()).update(h_targets)

    for tr in transitions:
        matched_any = False
        parent_sp = (
            span_by_key.get((tr.trace_id, tr.parent_span_id))
            if (tr.trace_id and tr.parent_span_id)
            else None
        )
        if tr.protocol == "http":
            matched_rns, matched_nids, pos_callers, scoped_helpers = _resolve_http_match(tr)
            for rn in matched_rns:
                node_hits[rn.id] = node_hits.get(rn.id, 0) + 1
                matched_any = True
            for e in pos_callers:
                _credit_edge(e, tr.source, tr.redacted_summary)
                matched_any = True
            scoped_targets: set[str] = set()
            for e in scoped_helpers:
                _credit_edge(e, tr.source, tr.redacted_summary)
                scoped_targets.add(e.target_id)
                matched_any = True
            if len(matched_nids) == 1 and scoped_targets:
                pos_disp_ids = {e.source_id for e in pos_callers}
                for ch in chains:
                    if (
                        ch.route_node_id in matched_nids
                        and (not ch.http_method or ch.http_method == tr.http_method)
                        and (not ch.http_path or _http_path_matches(ch.http_path, tr.http_route))
                    ):
                        manip_set = set(ch.manipulator_node_ids)
                        for src_h in sorted(scoped_targets):
                            out_h = [
                                e
                                for e in edges
                                if e.kind == "calls_helper" and e.source_id == src_h and e.target_id in manip_set
                            ]
                            if len(out_h) == 1:
                                _credit_edge(out_h[0], tr.source, tr.redacted_summary)
                        if ch.display_node_id in pos_disp_ids and ch.via_node_ids:
                            via_chain = [ch.display_node_id, *ch.via_node_ids]
                            for u_id, v_id in itertools.pairwise(via_chain):
                                for e in edges:
                                    if e.source_id == u_id and e.target_id == v_id:
                                        _credit_edge(e, tr.source, tr.redacted_summary)
        elif tr.protocol == "sql":
            tbl_low = tr.db_table.lower()
            is_write = tr.db_operation in ("INSERT", "UPDATE", "DELETE", "UPSERT", "MERGE")
            want_kinds = ("writes_truth",) if is_write else ("reads_truth", "guards_truth")
            t_matches = {
                tn.id
                for tn in truth_nodes
                if tbl_low
                and (
                    tn.id.removeprefix("t:").lower() == tbl_low
                    or tn.label.lower() == tbl_low
                    or tn.label.rpartition(":")[2].lower() == tbl_low
                )
            }
            for tid in t_matches:
                node_hits[tid] = node_hits.get(tid, 0) + 1
                matched_any = True
            cand_edges = [
                e for e in edges if e.target_id in t_matches and e.kind in want_kinds and e.source_id in node_by_id
            ]
            credited_sql: list[Any] = []
            if tr.code_filepath or tr.code_function:
                fp_matches = [
                    ce
                    for ce in cand_edges
                    if _filepath_or_func_matches(
                        tr.code_filepath, tr.code_function, node_by_id[ce.source_id], ce.symbol_links
                    )
                ]
                if len({ce.source_id for ce in fp_matches}) == 1:
                    credited_sql = fp_matches
            if not credited_sql and parent_sp is not None:
                p_span_handlers = exercised_handlers_by_span.get((parent_sp.trace_id, parent_sp.span_id), set())
                p_svc = _non_generic_svc_norm(parent_sp.service_name)
                p_matches = [
                    ce
                    for ce in cand_edges
                    if ce.source_id in p_span_handlers
                    or (
                        (parent_sp.code_filepath or parent_sp.code_function)
                        and _filepath_or_func_matches(
                            parent_sp.code_filepath, parent_sp.code_function, node_by_id[ce.source_id], ce.symbol_links
                        )
                    )
                    or (p_svc and _service_matches_node(p_svc, node_by_id[ce.source_id]))
                ]
                if len({ce.source_id for ce in p_matches}) == 1:
                    credited_sql = p_matches
            svc_norm = _non_generic_svc_norm(tr.service_name)
            if not credited_sql and svc_norm:
                narrowed = [ce for ce in cand_edges if _service_matches_node(svc_norm, node_by_id[ce.source_id])]
                if len({ce.source_id for ce in narrowed}) == 1:
                    credited_sql = narrowed
            if not credited_sql:
                ctx_key = ("trace", tr.trace_id) if tr.trace_id else None
                exercised = exercised_handlers_by_ctx.get(ctx_key, set()) if ctx_key is not None else set()
                ctx_narrowed = [ce for ce in cand_edges if ce.source_id in exercised]
                if len(ctx_narrowed) == 1:
                    credited_sql = ctx_narrowed
            for ce in credited_sql:
                _credit_edge(ce, tr.source, tr.redacted_summary)
                matched_any = True
        else:
            peer_norm = _norm_tok(tr.rpc_service or tr.peer_service or tr.rpc_method)
            caller_svc = _non_generic_svc_norm(tr.service_name)
            rpc_cands = [
                e
                for e in edges
                if e.kind == "calls_helper"
                and e.target_id in node_by_id
                and e.source_id in node_by_id
                and peer_norm
                and _service_matches_node(peer_norm, node_by_id[e.target_id])
                and (
                    (
                        (tr.code_filepath or tr.code_function)
                        and _filepath_or_func_matches(
                            tr.code_filepath, tr.code_function, node_by_id[e.source_id], e.symbol_links
                        )
                    )
                    or (caller_svc and _service_matches_node(caller_svc, node_by_id[e.source_id]))
                )
            ]
            if len({e.source_id for e in rpc_cands}) == 1:
                for rc in rpc_cands:
                    _credit_edge(rc, tr.source, tr.redacted_summary)
                    matched_any = True
            if not matched_any and peer_norm:
                for mn in manip_nodes:
                    if peer_norm in _norm_tok(mn.label):
                        node_hits[mn.id] = node_hits.get(mn.id, 0) + 1
                        matched_any = True

        if not matched_any:
            b_target = tr.http_route or tr.db_table or f"{tr.rpc_service}/{tr.rpc_method}".strip("/") or tr.peer_service
            b_key = (tr.protocol, tr.service_name, b_target)
            entry = blind_spots.get(b_key)
            if entry is None:
                blind_spots[b_key] = {
                    "category": "dynamic_blind_spot",
                    "overlay_kind": "runtime_only",
                    "protocol": tr.protocol,
                    "service_name": tr.service_name,
                    "target": b_target,
                    "witness_count": 1,
                    "sources": [tr.source],
                    "redacted_samples": [tr.redacted_summary],
                    "mutates_static_verification": False,
                }
            else:
                entry["witness_count"] += 1
                if tr.source not in entry["sources"]:
                    entry["sources"].append(tr.source)
                if len(entry["redacted_samples"]) < 5 and tr.redacted_summary not in entry["redacted_samples"]:
                    entry["redacted_samples"].append(tr.redacted_summary)

    corroborated_edges = [
        {
            "edge_id": e.id,
            "source_id": e.source_id,
            "target_id": e.target_id,
            "kind": e.kind,
            "static_verification": e.verification,
            "witness_count": edge_hits[e.id],
            "sources": sorted(edge_sources[e.id]),
            "redacted_samples": edge_samples[e.id],
        }
        for e in sorted(edges, key=lambda x: x.id)
        if edge_hits.get(e.id, 0) > 0
    ]
    dark_edges = [
        {
            "edge_id": e.id,
            "source_id": e.source_id,
            "target_id": e.target_id,
            "kind": e.kind,
            "static_verification": e.verification,
            "witness_count": 0,
            "epistemic_status": "unexercised_in_sample",
            "dead_code_proof": False,
        }
        for e in sorted(edges, key=lambda x: x.id)
        if edge_hits.get(e.id, 0) == 0
    ]
    dark_nodes = [
        {
            "node_id": n.id,
            "label": n.label,
            "tier": n.tier,
            "subkind": n.subkind,
            "witness_count": 0,
            "epistemic_status": "unexercised_in_sample",
            "dead_code_proof": False,
        }
        for n in sorted(nodes, key=lambda x: x.id)
        if node_hits.get(n.id, 0) == 0
    ]
    runtime_only_list = [blind_spots[k] for k in sorted(blind_spots)]

    return {
        "transition_count": len(transitions),
        "corroborated_edge_count": len(corroborated_edges),
        "static_dark_matter_edge_count": len(dark_edges),
        "static_dark_matter_node_count": len(dark_nodes),
        "runtime_only_count": len(runtime_only_list),
        "corroborated_edges": corroborated_edges,
        "static_dark_matter": {
            "epistemic_note": (
                "Zero observed spans in this capture window means unexercised in this sample "
                "(static dark matter), NEVER proof of dead or unreachable code."
            ),
            "edges": dark_edges,
            "nodes": dark_nodes,
        },
        "runtime_only": runtime_only_list,
        "node_hit_counts": {k: v for k, v in sorted(node_hits.items()) if v > 0},
        "sample_transitions": [asdict(t) for t in transitions[:20]],
    }
