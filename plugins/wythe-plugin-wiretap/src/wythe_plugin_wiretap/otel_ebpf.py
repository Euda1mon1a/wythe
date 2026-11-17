"""Path-safe bounded readers, payload redaction, and OTLP/eBPF trace-to-Atlas correlation."""

from __future__ import annotations

import json
import os
import re
import stat
from collections.abc import Mapping, Sequence
from dataclasses import asdict, dataclass, field
from pathlib import Path
from typing import Any, Literal
from urllib.parse import urlsplit

MAX_WIRETAP_BYTES = 32 * 1024 * 1024  # 32 MiB passive read ceiling
MAX_NESTING_DEPTH = 64

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
    "api_key",
    "apikey",
    "token",
    "secret",
    "password",
    "passwd",
    "credential",
    "bearer",
    "session_key",
    "private_key",
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
    "sql.params",
    "query.parameter",
)
_BEARER_INLINE_RE = re.compile(r"\b(Bearer|Basic)\s+[A-Za-z0-9._~+/-]+=*", re.IGNORECASE)
MAX_SQL_STATEMENT_CHARS = 65536
_SQL_OMITTED_MARKER = "[sql_statement_omitted_unparsed]"
_SAFE_SQL_IDENT_RE = re.compile(r"^[A-Za-z_][A-Za-z0-9_$]{0,127}$")
_SQL_ATTR_KEYS: frozenset[str] = frozenset(
    {
        "db.statement",
        "db.query.text",
        "db.query",
        "sql",
        "sql.query",
        "query",
        "statement",
        "db.query.summary",
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


def _check_absolute_non_symlink_components(abs_path: Path, raw_label: str) -> None:
    parts = abs_path.parts
    if ".." in parts:
        raise ValueError(f"Path traversal segment '..' is forbidden in '{raw_label}'.")
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


def validate_non_symlink_path(
    raw_path: Path | str,
    *,
    repo_root: Path | None = None,
) -> Path:
    """Validate every path component before `.resolve()`, rejecting symlinks fail-closed."""
    raw_str = str(raw_path).strip()
    if not raw_str or "\x00" in raw_str:
        raise ValueError("Wiretap artifact path must be a non-empty string without NUL bytes.")
    cand = Path(raw_str).expanduser() if raw_str.startswith("~") else Path(raw_str)
    if ".." in cand.parts:
        raise ValueError(f"Path traversal segment '..' is forbidden in '{raw_path}'.")
    if cand.is_symlink():
        raise ValueError(f"Refusing symlinked artifact path: '{raw_path}'.")

    if not cand.is_absolute():
        base_raw = repo_root if repo_root is not None else Path.cwd()
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
            real_root = repo_root.resolve()
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
    return cand


def read_bounded_regular_bytes(
    raw_path: Path | str,
    *,
    repo_root: Path | None = None,
    max_bytes: int = MAX_WIRETAP_BYTES,
) -> tuple[Path, bytes]:
    """Read `<= max_bytes` (default 32 MiB) from a regular non-symlink file via `O_NOFOLLOW`."""
    cand = validate_non_symlink_path(raw_path, repo_root=repo_root)
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


def read_bounded_json(
    raw_path: Path | str,
    *,
    repo_root: Path | None = None,
    max_bytes: int = MAX_WIRETAP_BYTES,
    max_depth: int = MAX_NESTING_DEPTH,
) -> tuple[Path, Any]:
    """Read and parse a JSON artifact enforcing `<= 32 MiB` and `depth <= 64`."""
    resolved, raw = read_bounded_regular_bytes(raw_path, repo_root=repo_root, max_bytes=max_bytes)
    text = raw.decode("utf-8-sig")
    if "\x00" in text:
        raise ValueError(f"Refusing JSON artifact '{raw_path}' containing NUL bytes.")
    ensure_json_depth_bounded(text, max_depth=max_depth)
    return resolved, json.loads(text)


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


def _sanitize_sql_op_and_table(op: str, tbl: str) -> tuple[str, str]:
    clean_op = op.strip().upper()
    if clean_op not in _RECOGNIZED_SQL_VERBS:
        clean_op = ""
    raw_tbl = tbl.strip().strip('"').strip("`").strip("[]")
    if "." in raw_tbl:
        raw_tbl = raw_tbl.rpartition(".")[2]
    clean_tbl = raw_tbl.strip().strip('"').strip("`").strip("[]")
    if not _SAFE_SQL_IDENT_RE.match(clean_tbl) or clean_tbl.upper() in _SQL_NON_TABLE_KEYWORDS:
        clean_tbl = ""
    return clean_op, clean_tbl


def _format_omitted_sql(op: str, tbl: str) -> str:
    c_op, c_tbl = _sanitize_sql_op_and_table(op, tbl)
    prefix = " ".join(part for part in (c_op, c_tbl) if part)
    return f"{prefix} {_SQL_OMITTED_MARKER}" if prefix else _SQL_OMITTED_MARKER


def _consume_single_quoted(
    raw_sql: str,
    quote_idx: int,
    n: int,
    *,
    allow_backslash_escape: bool = False,
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
                if (bs_len % 2) == 1 or (j + 1 < n and raw_sql[j + 1] == "'"):
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
    if not raw_sql or not raw_sql.strip():
        c_op, c_tbl = _sanitize_sql_op_and_table(explicit_op, explicit_table)
        return "", False, c_op, c_tbl

    detected_op = ""
    detected_tbl = ""

    def _fail() -> tuple[str, bool, str, str]:
        f_op, f_tbl = _sanitize_sql_op_and_table(explicit_op or detected_op, explicit_table or detected_tbl)
        return _format_omitted_sql(f_op, f_tbl), True, f_op, f_tbl

    if len(raw_sql) > max_chars or any(
        (ord(c) < 32 and c not in ("\t", "\n", "\r")) or ord(c) == 0x7F for c in raw_sql
    ):
        return _fail()

    db_low = db_system.strip().lower()
    is_mysql = db_low in ("mysql", "mariadb")
    uses_dq_strings = is_mysql or db_low in ("sqlite", "sqlite3")
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

        # Line comments: `-- ...` or MySQL `# ...`
        if (ch == "-" and i + 1 < n and raw_sql[i + 1] == "-") or (ch == "#" and is_mysql):
            changed = True
            _append_space()
            i += 2 if ch == "-" else 1
            while i < n and raw_sql[i] not in ("\n", "\r"):
                i += 1
            continue

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
                allow_backslash_escape=is_pg_escape_str,
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

        # Double-quoted identifiers (`"ident"`) & MySQL/SQLite/value-position `"..."` literals
        if ch == '"':
            j = i + 1
            closed_end: int | None = None
            while j < n:
                c = raw_sql[j]
                if c == "\\":
                    if not is_mysql:
                        return _fail()
                    bs_start = j
                    while j < n and raw_sql[j] == "\\":
                        j += 1
                    bs_len = j - bs_start
                    if j >= n:
                        return _fail()
                    if raw_sql[j] == '"':
                        if (bs_len % 2) == 1 or (j + 1 < n and raw_sql[j + 1] == '"'):
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
                return _fail()
            peek = closed_end
            while peek < n and raw_sql[peek] in (" ", "\t", "\n", "\r"):
                peek += 1
            next_ch = raw_sql[peek] if peek < n else ""
            in_val_paren = ("VALUES" in paren_clause_stack) or ("IN" in paren_clause_stack)
            in_val_pos = in_val_paren or (prev_sig_tok in _VALUE_PREV_TOKENS and next_ch != ".")
            keep_ident = (
                (prev_sig_tok in _SQL_TABLE_PREPOSITIONS or prev_sig_tok == "." or next_ch == ".")
                and not in_val_paren
                if uses_dq_strings
                else not in_val_pos
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
                    return _fail()
                if raw_sql[j] == "`":
                    if j + 1 < n and raw_sql[j + 1] == "`":
                        j += 2
                        continue
                    closed_bt = j + 1
                    break
                j += 1
            if closed_bt is None:
                return _fail()
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
                if not detected_op:
                    detected_op = tok_up
                need_stmt_verb = False
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

    c_op, c_tbl = _sanitize_sql_op_and_table(explicit_op or detected_op, explicit_table or detected_tbl)
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
    parsed = urlsplit(raw_url.strip())
    clean_path = parsed.path or "/"
    redacted = False
    host_part = parsed.hostname or ""
    if parsed.port:
        host_part = f"{host_part}:{parsed.port}"
    if parsed.username or parsed.password:
        redacted = True
    q_parts: list[str] = []
    if parsed.query:
        for seg in parsed.query.split("&")[:32]:
            if not seg:
                continue
            k, sep, _v = seg.partition("=")
            if sep:
                redacted = True
                q_parts.append(f"{k}=[REDACTED]")
            else:
                q_parts.append(k)
    prefix = f"{parsed.scheme}://{host_part}" if parsed.scheme and host_part else ""
    q_str = f"?{'&'.join(q_parts)}" if q_parts else ""
    return clean_path, f"{prefix}{clean_path}{q_str}", redacted


def _looks_like_inline_sql(text: str) -> bool:
    s = text.lstrip()
    idx = 0
    n = len(s)
    while idx < n:
        if s[idx] in (" ", "\t", "\n", "\r", "("):
            idx += 1
            continue
        if s.startswith("--", idx):
            nl = s.find("\n", idx + 2)
            if nl == -1:
                return False
            idx = nl + 1
            continue
        if s.startswith("/*", idx):
            end_c = s.find("*/", idx + 2)
            if end_c == -1:
                return True
            idx = end_c + 2
            continue
        break
    v_end = idx
    while v_end < n and ("A" <= s[v_end] <= "Z" or "a" <= s[v_end] <= "z"):
        v_end += 1
    if v_end == idx or v_end >= n:
        return False
    verb = s[idx:v_end].upper()
    return verb in _RECOGNIZED_SQL_VERBS and s[v_end] in (
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
    )


def redact_attributes(
    raw_attrs: Mapping[str, Any],
    *,
    inherited_db_system: str = "",
    inherited_op: str = "",
    inherited_table: str = "",
) -> tuple[dict[str, object], int]:
    """Redact auth/cookie headers, SQL bind/literal values, URL query values, and raw buffers."""
    cleaned: dict[str, object] = {}
    redacted_count = 0
    db_sys_hint = str(
        raw_attrs.get("db.system")
        or raw_attrs.get("db.system.name")
        or raw_attrs.get("db_system")
        or inherited_db_system
        or ""
    ).strip()
    op_hint = str(
        raw_attrs.get("db.operation")
        or raw_attrs.get("db.operation.name")
        or inherited_op
        or ""
    ).strip()
    tbl_hint = str(
        raw_attrs.get("db.sql.table")
        or raw_attrs.get("db.collection.name")
        or raw_attrs.get("table")
        or inherited_table
        or ""
    ).strip()

    def _scrub_str(k_low: str, val_s: str) -> tuple[str, int]:
        cnt = 0
        is_url_key = k_low in ("url.full", "http.url", "http.target", "url", "path", "http.route", "url.path")
        if k_low in _SQL_ATTR_KEYS or (not is_url_key and _looks_like_inline_sql(val_s)):
            val_s, was_sql = _redact_sql_statement(
                val_s,
                db_system=db_sys_hint,
                explicit_op=op_hint,
                explicit_table=tbl_hint,
            )
            if was_sql:
                cnt += 1
        elif is_url_key and ("?" in val_s or "@" in val_s):
            _p, val_s, was_u = redact_url_target(val_s)
            if was_u:
                cnt += 1
        scrubbed = _BEARER_INLINE_RE.sub(r"\1 [REDACTED]", val_s)
        if scrubbed != val_s:
            cnt += 1
        return scrubbed[:512], cnt

    for raw_k, raw_v in raw_attrs.items():
        k = str(raw_k).strip()
        k_low = k.lower()
        if any(tok in k_low for tok in _RAW_BUFFER_KEY_TOKENS):
            cleaned[k] = "[REDACTED_BUFFER]"
            redacted_count += 1
            continue
        if any(tok in k_low for tok in _SENSITIVE_KEY_TOKENS) or k_low.startswith(
            ("http.request.header.", "http.response.header.", "rpc.metadata.")
        ):
            cleaned[k] = "[REDACTED]"
            redacted_count += 1
            continue
        if isinstance(raw_v, Mapping):
            sub_map, sub_cnt = redact_attributes(
                raw_v,
                inherited_db_system=db_sys_hint,
                inherited_op=op_hint,
                inherited_table=tbl_hint,
            )
            cleaned[k] = sub_map
            redacted_count += sub_cnt
            continue
        if isinstance(raw_v, (bytes, bytearray)):
            cleaned[k] = "[REDACTED_BUFFER]"
            redacted_count += 1
            continue
        if isinstance(raw_v, str):
            scrubbed_s, s_cnt = _scrub_str(k_low, raw_v)
            cleaned[k] = scrubbed_s
            redacted_count += s_cnt
        elif isinstance(raw_v, Sequence) and not isinstance(raw_v, (str, bytes, bytearray)):
            seq_out: list[object] = []
            for elem in list(raw_v)[:32]:
                if isinstance(elem, str):
                    sc_el, el_cnt = _scrub_str(k_low, elem)
                    seq_out.append(sc_el)
                    redacted_count += el_cnt
                elif isinstance(elem, Mapping):
                    sub_m, m_cnt = redact_attributes(
                        elem,
                        inherited_db_system=db_sys_hint,
                        inherited_op=op_hint,
                        inherited_table=tbl_hint,
                    )
                    seq_out.append(sub_m)
                    redacted_count += m_cnt
                elif isinstance(elem, (bytes, bytearray)):
                    seq_out.append("[REDACTED_BUFFER]")
                    redacted_count += 1
                elif isinstance(elem, (int, float, bool)) or elem is None:
                    seq_out.append(elem)
                else:
                    seq_out.append(str(elem)[:256])
            cleaned[k] = seq_out
        elif isinstance(raw_v, (int, float, bool)) or raw_v is None:
            cleaned[k] = raw_v
        else:
            cleaned[k] = str(raw_v)[:256]
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


def _otel_any_value(val_obj: Any, depth: int = 0) -> Any:
    if depth > 16 or not isinstance(val_obj, Mapping):
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
    return str(val_obj)[:256]


def _otel_kv_list_to_dict(items: Sequence[Any], depth: int = 0) -> dict[str, Any]:
    out: dict[str, Any] = {}
    for item in items:
        if isinstance(item, Mapping) and "key" in item:
            out[str(item["key"])] = _otel_any_value(item.get("value"), depth + 1)
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
    redacted_map, red_cnt = redact_attributes(raw_attrs)
    http_method = str(
        raw_attrs.get("http.request.method")
        or raw_attrs.get("http.method")
        or raw_attrs.get("method")
        or ""
    ).strip().upper()
    raw_route = str(
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

    db_sys = str(
        raw_attrs.get("db.system")
        or raw_attrs.get("db.system.name")
        or raw_attrs.get("db_system")
        or ""
    ).strip()
    raw_sql = str(
        raw_attrs.get("db.statement")
        or raw_attrs.get("db.query.text")
        or raw_attrs.get("db.query")
        or raw_attrs.get("sql")
        or raw_attrs.get("sql.query")
        or raw_attrs.get("query")
        or raw_attrs.get("statement")
        or ""
    ).strip()
    db_op, db_tbl = _extract_sql_table_and_op(
        raw_sql,
        str(raw_attrs.get("db.operation") or raw_attrs.get("db.operation.name") or ""),
        str(
            raw_attrs.get("db.sql.table")
            or raw_attrs.get("db.collection.name")
            or raw_attrs.get("table")
            or ""
        ),
        db_system=db_sys,
    )
    def _scrub_free_field(val: str) -> str:
        nonlocal red_cnt
        if not val:
            return ""
        cur = val
        if _looks_like_inline_sql(cur):
            cur, was_sql = _redact_sql_statement(cur, db_system=db_sys)
            if was_sql:
                red_cnt += 1
        elif ("?" in cur or "@" in cur) and ("://" in cur or cur.startswith("/")):
            _p, cur, was_u = redact_url_target(cur)
            if was_u:
                red_cnt += 1
        scrubbed = _BEARER_INLINE_RE.sub(r"\1 [REDACTED]", cur)
        if scrubbed != cur:
            red_cnt += 1
        return scrubbed[:256]

    service_name = _scrub_free_field(service_name.strip()) or "service"
    span_name = _scrub_free_field(span_name.strip())
    rpc_sys = str(raw_attrs.get("rpc.system") or "").strip().lower()
    rpc_svc = _scrub_free_field(str(raw_attrs.get("rpc.service") or "").strip())
    rpc_mth = _scrub_free_field(str(raw_attrs.get("rpc.method") or "").strip())
    peer = _scrub_free_field(str(raw_attrs.get("peer.service") or raw_attrs.get("dst_service") or "").strip())
    code_fp = _scrub_free_field(str(raw_attrs.get("code.filepath") or "").strip())
    code_fn = _scrub_free_field(str(raw_attrs.get("code.function") or "").strip())

    if db_tbl or db_op or db_sys or raw_sql:
        red_sql = str(
            redacted_map.get("db.statement")
            or redacted_map.get("db.query.text")
            or redacted_map.get("db.query")
            or redacted_map.get("sql")
            or redacted_map.get("sql.query")
            or redacted_map.get("query")
            or redacted_map.get("statement")
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


def parse_otel_traces(
    raw_path: Path | str,
    *,
    repo_root: Path | None = None,
) -> tuple[list[ObservedRuntimeTransition], int]:
    """Parse an OTLP JSON trace capture into redacted `ObservedRuntimeTransition` items."""
    _resolved, data = read_bounded_json(raw_path, repo_root=repo_root)
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
            svc_name = str(res_attrs.get("service.name") or "service")
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
                        "otel", svc_name, str(sp.get("name") or ""), merged_attrs
                    )
                    total_redacted += r_cnt
                    if tr is not None:
                        transitions.append(tr)
    else:
        raw_list = data.get("spans", []) if isinstance(data, Mapping) else (data if isinstance(data, list) else None)
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
            svc_name = str(sp.get("service_name") or sp_attrs.get("service.name") or "service")
            tr, r_cnt = _transition_from_attr_dict(
                "otel", svc_name, str(sp.get("name") or ""), sp_attrs
            )
            total_redacted += r_cnt
            if tr is not None:
                transitions.append(tr)

    return transitions, total_redacted


def parse_ebpf_flows(
    raw_path: Path | str,
    *,
    repo_root: Path | None = None,
) -> tuple[list[ObservedRuntimeTransition], int]:
    """Parse JSONL or JSON array eBPF L7 HTTP/SQL/gRPC flow captures with default redaction."""
    _resolved, raw_bytes = read_bounded_regular_bytes(raw_path, repo_root=repo_root)
    text = raw_bytes.decode("utf-8-sig").strip()
    if "\x00" in text:
        raise ValueError(f"Refusing eBPF flow capture '{raw_path}' containing NUL bytes.")
    if not text:
        return [], 0

    records: list[Mapping[str, Any]] = []
    if text.startswith("["):
        ensure_json_depth_bounded(text)
        parsed = json.loads(text)
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
                obj = json.loads(s)
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

    route_nodes = [n for n in nodes if n.http_paths]
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

    for tr in transitions:
        matched_any = False
        if tr.protocol == "http":
            matched_nids: set[str] = set()
            for rn in route_nodes:
                method_ok = not rn.http_methods or tr.http_method in rn.http_methods
                if method_ok and any(_http_path_matches(hp, tr.http_route) for hp in rn.http_paths):
                    matched_nids.add(rn.id)
                    node_hits[rn.id] = node_hits.get(rn.id, 0) + 1
                    matched_any = True
            for e in edges:
                if e.kind in ("queries_endpoint", "mutates_endpoint", "uses_client") and (
                    e.target_id in matched_nids or e.source_id in matched_nids
                ):
                    _credit_edge(e, tr.source, tr.redacted_summary)
                    matched_any = True
            for ch in chains:
                if ch.route_node_id in matched_nids and (
                    not ch.http_method or ch.http_method == tr.http_method
                ):
                    ch_set = {ch.display_node_id, *ch.via_node_ids, ch.route_node_id, *ch.manipulator_node_ids}
                    for e in edges:
                        if e.kind == "calls_helper" and e.source_id in ch_set and e.target_id in ch_set:
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
            svc_norm = _norm_tok(tr.code_filepath or tr.service_name)
            cand_edges = [e for e in edges if e.target_id in t_matches and e.kind in want_kinds]
            if len(cand_edges) > 1 and svc_norm:
                narrowed = [
                    e
                    for e in cand_edges
                    if svc_norm in _norm_tok(node_by_id[e.source_id].source_file)
                    or svc_norm in _norm_tok(node_by_id[e.source_id].label)
                ]
                if narrowed:
                    cand_edges = narrowed
            for ce in cand_edges:
                _credit_edge(ce, tr.source, tr.redacted_summary)
                matched_any = True
            for tid in t_matches:
                node_hits[tid] = node_hits.get(tid, 0) + 1
                matched_any = True
        else:
            peer_norm = _norm_tok(tr.rpc_service or tr.peer_service or tr.rpc_method)
            caller_norm = _norm_tok(tr.code_filepath or tr.service_name)
            for e in edges:
                if e.kind != "calls_helper":
                    continue
                tgt_n = node_by_id.get(e.target_id)
                src_n = node_by_id.get(e.source_id)
                if tgt_n is None or src_n is None:
                    continue
                if (
                    peer_norm
                    and (peer_norm in _norm_tok(tgt_n.label) or peer_norm in _norm_tok(tgt_n.source_file))
                    and (
                        not caller_norm
                        or caller_norm in _norm_tok(src_n.label)
                        or caller_norm in _norm_tok(src_n.source_file)
                        or caller_norm == "service"
                    )
                ):
                    _credit_edge(e, tr.source, tr.redacted_summary)
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
