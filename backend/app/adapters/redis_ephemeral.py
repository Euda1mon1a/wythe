"""Cross-Language Ephemeral Redis Keyspace, Worker Entry-Door, & Shadow-Truth Inspector.

Why Redis is inspected as Tier-1 `cache_store` (`role='ephemeral'`) rather than Truth Atlas's own DB:
  - Durable relational catalogs hold authoritative business truth; Redis holds volatile caches, locks,
    rate-limiters, and job queues.
  - Writing to Redis via `SET` / `HSET` without a TTL (`TRUTH-004`) silently creates volatile shadow
    truth that can diverge from or evaporate independently of PostgreSQL/MySQL/SQLite.
"""

from __future__ import annotations

import ast
import re
import socket
import ssl
from pathlib import Path
from urllib.parse import urlparse

from app.adapters.base import (
    ManipulatorExtractionResult,
    RawCandidateFinding,
    TruthExtractionResult,
)
from app.schemas.atlas import AtlasEdge, AtlasNode

_SKIP_PARTS = ("adapters", "tests", "__pycache__", "node_modules", "target", ".git", "migrations", "alembic")
_CODE_SUFFIXES = (".py", ".ts", ".js", ".go", ".rs")

_REDIS_SDK_RE = re.compile(
    r"""\b(?:import\s+redis|from\s+redis|aioredis|django\.core\.cache|ioredis|@upstash/redis|createClient|go-redis|asynq|deadpool_redis|redis::|fred::|celery|shared_task|bullmq)\b"""
)
_PY_COMMENT_RE = re.compile(r"#[^\n]*")
_C_COMMENT_RE = re.compile(r"//[^\n]*|/\*[\s\S]*?\*/")

_RECV_PAT = r"(?:redis(?:_[A-Za-z0-9_]+)?|rdb|rcache|cache|valkey|upstash|kv|[A-Za-z0-9_]+_redis)"
_REDIS_CALL_RE = re.compile(
    rf"""\b(?P<recv>{_RECV_PAT})\s*\.\s*(?P<op>get|mget|hget|hgetall|lrange|smembers|xread|set|setex|psetex|set_ex|hset|hmset|mset|lpush|rpush|xadd|publish|delete|unlink|del|expire|pexpire|expireat|pexpireat|Get|MGet|HGet|HGetAll|Set|SetEx|SetNX|HSet|LPush|RPush|Delete|Del|Unlink|Expire)\s*\("""
)
_RUST_CMD_RE = re.compile(
    r"""\bredis::cmd\(\s*"(?P<op>GET|MGET|HGET|HGETALL|SET|SETEX|PSETEX|HSET|LPUSH|RPUSH|DEL|UNLINK|EXPIRE)"\s*\)\s*\.\s*arg\(\s*"(?P<key>[A-Za-z0-9_.-]+:[A-Za-z0-9_:.*{}-]*)" """.strip()
)
_FIRST_STR_ARG_RE = re.compile(r"""^\s*(?:ctx\s*,\s*)?['"`](?P<key>[A-Za-z0-9_.-]+:[A-Za-z0-9_:.*{}$/-]*)['"`]""")
_EXPIRE_CALL_RE = re.compile(
    rf"""\b(?P<recv>{_RECV_PAT})\s*\.\s*(?:expire|pexpire|expireat|pexpireat|Expire)\s*\(\s*(?:ctx\s*,\s*)?['"`](?P<key>[A-Za-z0-9_.-]+:)"""
)
_TTL_OPT_RE = re.compile(
    r"""(?:\b(?:ex|px|exat|pxat|timeout|ttl|EX|PX)\s*[=:]|\b(?:keepttl|KEEPTTL)\s*[=:]\s*(?:True|true)\b|['"](?:EX|PX|KEEPTTL)['"]\s*[,)])"""
)
# Python keyword arguments that bound a write's lifetime (redis-py and common cache wrappers).
_PY_TTL_KWARGS = frozenset({"ex", "px", "exat", "pxat", "ttl", "timeout", "expire", "expires", "expiry"})
_PY_EXPIRE_OPS = frozenset({"expire", "pexpire", "expireat", "pexpireat"})

_WORKER_DEF_RE = re.compile(
    r"""(?:@(?P<cel_dec>shared_task|(?:celery_app|app|celery)\.task)\b|\bnew\s+Worker\s*\(\s*['"](?P<bull_q>[A-Za-z0-9_:-]+)['"]|\basynq\.NewServeMux\s*\()"""
)
_NEXT_PY_DEF_RE = re.compile(r"\bdef\s+(?P<fn>[A-Za-z_]\w*)\s*\(")
_QUEUE_PRODUCE_RE = re.compile(
    r"""(?:\b(?P<task>[A-Za-z_]\w*)\.(?:delay|apply_async)\s*\(|\bnew\s+Queue\s*\(\s*['"](?P<bull_q>[A-Za-z0-9_:-]+)['"]|\basynq\.NewTask\s*\(\s*"(?P<asynq_q>[A-Za-z0-9_:-]+)")"""
)
_SEND_TASK_RE = re.compile(
    r"""\.send_task\s*\(\s*['"](?P<task_fqn>[A-Za-z0-9_.:-]+)['"]"""
)
_TASK_ROUTE_ENTRY_RE = re.compile(
    r"""['"](?P<pat>[A-Za-z0-9_.*]+)['"]\s*:\s*\{\s*['"]queue['"]\s*:\s*['"](?P<q>[A-Za-z0-9_:-]+)['"]"""
)
_BEAT_TASK_ENTRY_RE = re.compile(
    r"""['"]task['"]\s*:\s*['"](?P<task_fqn>[A-Za-z0-9_.:-]+)['"]"""
)
_ADD_PERIODIC_RE = re.compile(
    r"""\.add_periodic_task\s*\([^,\n]+,\s*(?P<sig>[A-Za-z_]\w*)\.s\("""
)
_EXPLICIT_QUEUE_OPT_RE = re.compile(r"""(?:\bqueue\s*=\s*|['"]queue['"]\s*:\s*)['"](?P<q>[A-Za-z0-9_:-]+)['"]""")
_DECLARED_QUEUES_RE = re.compile(
    r"""\bCELERY_QUEUE_NAMES\b[^=\n]*=\s*[\(\[](?P<body>[^\)\]]{1,400})[\)\]]"""
)
_ASYNQ_SCHED_RE = re.compile(
    r"""\.Register\s*\(\s*"[^"\n]+"\s*,\s*asynq\.NewTask\s*\(\s*"(?P<asynq_q>[A-Za-z0-9_:-]+)" """.strip()
)

_READ_OPS = frozenset({"get", "mget", "hget", "hgetall", "lrange", "smembers", "xread", "Get", "MGet", "HGet", "HGetAll", "GET", "MGET", "HGET", "HGETALL"})
_TTL_WRITE_OPS = frozenset({"setex", "psetex", "set_ex", "SetEx", "SETEX", "PSETEX", "lpush", "rpush", "xadd", "publish", "LPush", "RPush", "LPUSH", "RPUSH"})
_UNBOUNDED_CANDIDATE_OPS = frozenset({"set", "hset", "hmset", "mset", "Set", "SetNX", "HSet", "SET", "HSET"})
_INVALIDATE_OPS = frozenset({"delete", "unlink", "del", "Delete", "Del", "Unlink", "DEL", "UNLINK"})
_GENERIC_KEY_STEMS = frozenset({"default", "state", "cache", "data", "temp", "tmp", "redis", "queue", "session", "token", "limit", "limits", "rate", "ratelimit", "shadow_state"})


def _key_domain_stem(raw: str) -> str:
    cleaned = raw.lower()
    for pfx in ("t:redis:", "t:sql:", "t:db:", "t:"):
        cleaned = cleaned.removeprefix(pfx)
    cleaned = cleaned.split(":", 1)[0]
    for suffix in ("_copy", "_cache", "_replica", "_view", "_snapshot"):
        if cleaned.endswith(suffix):
            cleaned = cleaned[: -len(suffix)]
            break
    if len(cleaned) > 4 and cleaned.endswith("s"):
        cleaned = cleaned[:-1]
    return cleaned


def _strip_comments_keep_lines(raw: str, suffix: str) -> str:
    if suffix == ".py":
        return _PY_COMMENT_RE.sub("", raw)
    return _C_COMMENT_RE.sub(lambda m: "\n" * m.group(0).count("\n"), raw)


def _extract_call_window(txt: str, open_paren_end: int) -> str:
    depth = 1
    i = open_paren_end
    limit = min(len(txt), open_paren_end + 260)
    while i < limit and depth > 0:
        if txt[i] == "(":
            depth += 1
        elif txt[i] == ")":
            depth -= 1
        i += 1
    return txt[open_paren_end : max(open_paren_end, i - 1)]


def _go_set_has_ttl(args_str: str) -> bool:
    parts = [p.strip() for p in args_str.split(",")]
    if len(parts) >= 4:
        ttl_expr = parts[3]
        return ttl_expr not in ("0", "0s", "time.Duration(0)")
    return False


def _is_falsy_const(node: ast.AST) -> bool:
    return isinstance(node, ast.Constant) and node.value in (None, 0, False)


def _leading_literal(node: ast.AST | None) -> str | None:
    """Literal text a key expression starts with: `"a:b"`, `f"a:{x}"`, `"a:" + x`."""
    if isinstance(node, ast.Constant) and isinstance(node.value, str):
        return node.value
    if isinstance(node, ast.JoinedStr):
        head = ""
        for part in node.values:
            if isinstance(part, ast.Constant) and isinstance(part.value, str):
                head += part.value
            else:
                break
        return head
    if isinstance(node, ast.BinOp) and isinstance(node.op, ast.Add):
        return _leading_literal(node.left)
    return None


class _PyRedisCalls:
    """Syntax-tree view of one Python file, used to qualify regex-found Redis calls.

    A regex hit with no matching call in the tree is inside a string or docstring and is not
    code. For a real call, the tree answers what the regex cannot: TTL keyword/positional
    arguments, an `expire(<same key>)` in the same block after the write, and the literal prefix
    of an f-string or of a key variable assigned in the same function.
    """

    def __init__(self, tree: ast.Module) -> None:
        self._calls: dict[tuple[int, str], list[ast.Call]] = {}
        self._parent: dict[int, ast.AST] = {}
        expire_calls: list[ast.Call] = []
        for node in ast.walk(tree):
            for child in ast.iter_child_nodes(node):
                self._parent[id(child)] = node
            if isinstance(node, ast.Call) and isinstance(node.func, ast.Attribute):
                line = node.func.value.end_lineno or node.lineno
                self._calls.setdefault((line, node.func.attr), []).append(node)
                if node.func.attr in _PY_EXPIRE_OPS and node.args:
                    expire_calls.append(node)
        for calls in self._calls.values():
            calls.sort(key=lambda c: c.func.value.end_col_offset or 0)  # type: ignore[attr-defined]
        self._expires = expire_calls

    def take(self, lineno: int, op: str) -> ast.Call | None:
        calls = self._calls.get((lineno, op))
        return calls.pop(0) if calls else None

    def _enclosing(self, node: ast.AST, kinds: tuple[type, ...]) -> ast.AST | None:
        cur = self._parent.get(id(node))
        while cur is not None and not isinstance(cur, kinds):
            cur = self._parent.get(id(cur))
        return cur

    def _block(self, node: ast.AST) -> tuple[int, str] | None:
        stmt = node if isinstance(node, ast.stmt) else self._enclosing(node, (ast.stmt,))
        parent = self._parent.get(id(stmt)) if stmt is not None else None
        if parent is None:
            return None
        for name, value in ast.iter_fields(parent):
            if isinstance(value, list) and any(item is stmt for item in value):
                return (id(parent), name)
        return None

    def has_ttl(self, call: ast.Call, op: str) -> bool:
        options: dict[str, ast.AST] = {}
        for kw in call.keywords:
            values = {kw.arg: kw.value} if kw.arg is not None else self._keyword_mapping(kw.value, call)
            if values is None or options.keys() & values.keys():
                # Unknown unpacking and duplicate call keywords are not TTL evidence.
                return False
            options.update(values)
        for name, value in options.items():
            if name in _PY_TTL_KWARGS and not _is_falsy_const(value):
                return True
            if name == "keepttl" and isinstance(value, ast.Constant) and value.value is True:
                return True
        # redis-py: set(name, value, ex=None, px=None, ...) -> a third positional is `ex`.
        return op == "set" and len(call.args) >= 3 and not _is_falsy_const(call.args[2])

    def _constant_binding(self, name: str, use: ast.AST) -> ast.AST | None:
        """Only single, straight-line bindings with no observed mutation or escape."""
        scope = self._enclosing(use, (ast.FunctionDef, ast.AsyncFunctionDef, ast.Lambda, ast.Module))
        while scope is not None:
            nodes = [n for n in ast.walk(scope) if self._enclosing(
                n, (ast.FunctionDef, ast.AsyncFunctionDef, ast.Lambda, ast.Module)
            ) is scope]
            if any(isinstance(n, ast.arg) and n.arg == name for n in nodes):
                return None
            stores = [n for n in nodes if isinstance(n, ast.Name) and n.id == name
                      and isinstance(n.ctx, (ast.Store, ast.Del))]
            if stores:
                if len(stores) != 1:
                    return None
                assignment = self._parent.get(id(stores[0]))
                if not isinstance(assignment, (ast.Assign, ast.AnnAssign)) or self._parent.get(id(assignment)) is not scope:
                    return None
                if (assignment.lineno, assignment.col_offset) >= (use.lineno, use.col_offset):
                    return None
                if isinstance(assignment, ast.Assign) and len(assignment.targets) != 1:
                    return None
                for node in ast.walk(scope):
                    if not isinstance(node, ast.Name) or node.id != name:
                        continue
                    if isinstance(node.ctx, (ast.Store, ast.Del)) and node is not stores[0]:
                        return None
                    if not isinstance(node.ctx, ast.Load):
                        continue
                    parent = self._parent.get(id(node))
                    if isinstance(parent, (ast.Attribute, ast.Subscript, ast.Assign, ast.AnnAssign,
                                           ast.List, ast.Tuple, ast.Set, ast.Return)):
                        return None
                    if isinstance(parent, ast.Call):
                        return None
                    if isinstance(parent, ast.keyword) and parent.arg is not None:
                        return None
                return assignment.value
            scope = self._enclosing(scope, (ast.FunctionDef, ast.AsyncFunctionDef, ast.Lambda, ast.Module))
        return None

    def _keyword_mapping(
        self, node: ast.AST, use: ast.AST, seen: frozenset[str] = frozenset(),
    ) -> dict[str, ast.AST] | None:
        if isinstance(node, ast.Name):
            if node.id in seen:
                return None
            binding = self._constant_binding(node.id, use)
            return self._keyword_mapping(binding, use, seen | {node.id}) if binding is not None else None
        if isinstance(node, ast.BinOp) and isinstance(node.op, ast.BitOr):
            left = self._keyword_mapping(node.left, use, seen)
            right = self._keyword_mapping(node.right, use, seen)
            return {**left, **right} if left is not None and right is not None else None
        result: dict[str, ast.AST] = {}
        if isinstance(node, ast.Dict):
            pairs = [(key.value if isinstance(key, ast.Constant) and isinstance(key.value, str) else None,
                      value, key is None) for key, value in zip(node.keys, node.values)]
        elif isinstance(node, ast.Call) and isinstance(node.func, ast.Name) and node.func.id == "dict":
            if len(node.args) > 1:
                return None
            if node.args:
                base = self._keyword_mapping(node.args[0], use, seen)
                if base is None:
                    return None
                result.update(base)
            pairs = [(kw.arg, kw.value, kw.arg is None) for kw in node.keywords]
        else:
            return None
        for key, value, unpacked in pairs:
            if unpacked:
                nested = self._keyword_mapping(value, use, seen)
                if nested is None:
                    return None
                result.update(nested)
            elif key is not None:
                if isinstance(value, ast.Name):
                    value = self._constant_binding(value.id, use)
                if not isinstance(value, ast.Constant):
                    return None
                result[key] = value
            else:
                return None
        return result

    def expired_after(self, call: ast.Call) -> bool:
        """`expire(<same key expression>)` later in the same block on the same Redis client."""
        if not call.args or not isinstance(call.func, ast.Attribute):
            return False
        recv_dump = ast.dump(call.func.value)
        key_dump = ast.dump(call.args[0])
        block = self._block(call)
        scope = self._enclosing(call, (ast.FunctionDef, ast.AsyncFunctionDef, ast.Module))
        for exp in self._expires:
            if (
                isinstance(exp.func, ast.Attribute)
                and (exp.lineno, exp.col_offset) >= (call.lineno, call.col_offset)
                and ast.dump(exp.func.value) == recv_dump
                and ast.dump(exp.args[0]) == key_dump
                and (len(exp.args) < 2 or not _is_falsy_const(exp.args[1]))
                and self._enclosing(exp, (ast.FunctionDef, ast.AsyncFunctionDef, ast.Module)) is scope
                and block is not None
                and self._block(exp) == block
            ):
                return True
        return False

    def key_literal(self, call: ast.Call) -> str | None:
        """Leading literal of the key argument, following one local `key = ...` assignment."""
        if not call.args:
            return None
        key = call.args[0]
        if isinstance(key, ast.Name):
            scope = self._enclosing(call, (ast.FunctionDef, ast.AsyncFunctionDef, ast.Module))
            value: ast.AST | None = None
            best_line = 0
            for node in ast.walk(scope) if scope is not None else ():
                if (
                    isinstance(node, ast.Assign)
                    and best_line <= node.lineno < call.lineno
                    and len(node.targets) == 1
                    and isinstance(node.targets[0], ast.Name)
                    and node.targets[0].id == key.id
                ):
                    value, best_line = node.value, node.lineno
            return _leading_literal(value)
        return _leading_literal(key)


def _send_resp(sock: socket.socket, *parts: str) -> str:
    frame = f"*{len(parts)}\r\n" + "".join(f"${len(p.encode())}\r\n{p}\r\n" for p in parts)
    sock.sendall(frame.encode("utf-8"))
    chunks: list[bytes] = []
    sock.settimeout(1.2)
    while True:
        try:
            data = sock.recv(4096)
        except TimeoutError:
            break
        if not data:
            break
        chunks.append(data)
        if len(data) < 4096:
            break
    return b"".join(chunks).decode("utf-8", errors="replace")


def probe_redis_keyspace_prefixes(redis_dsn: str) -> tuple[set[str], str]:
    """Read-only RESP metadata probe (`INFO keyspace` + `SCAN 0 COUNT 200`); zero value reads."""
    parsed = urlparse(redis_dsn)
    host = parsed.hostname or "127.0.0.1"
    port = parsed.port or 6379
    db_idx = parsed.path.lstrip("/") or "0"
    prefixes: set[str] = set()
    try:
        raw_sock = socket.create_connection((host, port), timeout=1.5)
        sock: socket.socket = raw_sock
        if parsed.scheme == "rediss":
            ctx = ssl.create_default_context()
            sock = ctx.wrap_socket(raw_sock, server_hostname=host)
        with sock:
            if parsed.password:
                if parsed.username:
                    _send_resp(sock, "AUTH", parsed.username, parsed.password)
                else:
                    _send_resp(sock, "AUTH", parsed.password)
            if db_idx.isdigit() and int(db_idx) > 0:
                _send_resp(sock, "SELECT", db_idx)
            _send_resp(sock, "INFO", "keyspace")
            scan_out = _send_resp(sock, "SCAN", "0", "COUNT", "200")
            for line in scan_out.splitlines():
                if ":" in line and not line.startswith(("*", "$", "+", "-", ":")):
                    pfx = line.split(":", 1)[0].strip()
                    if pfx and re.match(r"^[A-Za-z0-9_.-]+$", pfx):
                        prefixes.add(pfx.lower())
        return prefixes, "redis_scan"
    except OSError:
        return set(), "redis_unreachable"


def _find_second_authority(
    prefix: str, written_sql_stems: dict[str, AtlasNode]
) -> AtlasNode | None:
    p_stem = _key_domain_stem(prefix)
    if len(p_stem) < 4 or p_stem in _GENERIC_KEY_STEMS:
        return None
    direct = written_sql_stems.get(p_stem)
    if direct is not None:
        return direct
    for t_stem, node in written_sql_stems.items():
        if t_stem.startswith(f"{p_stem}_") or p_stem.startswith(f"{t_stem}_"):
            return node
    return None


def _resolve_redis_call_key(
    txt: str,
    cm: re.Match[str],
    has_sdk: bool,
    py_calls: _PyRedisCalls | None,
) -> tuple[str, ast.Call | None] | None:
    op = cm.group("op")
    lineno = txt.count("\n", 0, cm.start()) + 1
    py_call = py_calls.take(lineno, op) if py_calls is not None else None
    if py_calls is not None and py_call is None:
        return None
    call_args = _extract_call_window(txt, cm.end())
    km = _FIRST_STR_ARG_RE.match(call_args)
    if km is None and not has_sdk:
        return None
    literal = (
        py_calls.key_literal(py_call)
        if py_calls is not None and py_call is not None
        else None
    )
    if km:
        raw_key = km.group("key")
    elif literal and ":" in literal:
        raw_key = f"{literal.split(':', 1)[0]}:*"
    else:
        raw_key = "default:key"
    if ":" not in raw_key and not has_sdk:
        return None
    return raw_key, py_call


def augment_redis_ephemeral_lineage(
    repo_root: Path,
    backend_subdir: str,
    truth: TruthExtractionResult,
    manip: ManipulatorExtractionResult,
    redis_dsn: str | None = None,
) -> str:
    """Augment `truth` and `manip` lists with Redis `cache_store` nodes, edges, and `TRUTH-004`."""
    base_dir = repo_root if backend_subdir in ("", ".") else repo_root / backend_subdir
    if not base_dir.is_dir():
        return truth.observation_source

    manip_by_file: dict[str, AtlasNode] = {n.source_file: n for n in manip.nodes}
    has_service_layer = any(n.subkind == "service" for n in manip.nodes)
    redis_nodes: dict[str, AtlasNode] = {}
    readers: dict[str, set[str]] = {}
    writers: dict[str, set[str]] = {}
    ttl_stores: set[str] = set()
    inval_stores: dict[str, list[tuple[str, int, str]]] = {}
    unestablished_stores: set[str] = set()
    conflict_stores: dict[str, str] = {}
    seen_edges: set[tuple[str, str, str]] = {(e.source_id, e.target_id, e.kind) for e in manip.edges}
    worker_node_ids: set[str] = set()
    written_table_ids = {e.target_id for e in manip.edges if e.kind == "writes_truth"}
    written_sql_stems: dict[str, AtlasNode] = {}
    for tn in truth.nodes:
        if tn.subkind == "table" and tn.id in written_table_ids:
            st = _key_domain_stem(tn.id)
            if len(st) >= 4 and st not in _GENERIC_KEY_STEMS:
                written_sql_stems[st] = tn

    def ensure_store(prefix: str, rel_repo: str, line: int, kind_note: str) -> str:
        slug = re.sub(r"[^a-z0-9_.-]", "_", prefix.lower()).strip("_") or "default"
        nid = f"t:redis:{slug}"
        if nid not in redis_nodes:
            summary = (
                f"Unresolved dynamic Redis {kind_note} `default:*` (grouping reflects unresolved key names, not proof of shared records)."
                if slug == "default"
                else f"Discovered Redis {kind_note} `{slug}:*` (store role not yet declared; inferred from static operations)."
            )
            redis_nodes[nid] = AtlasNode(
                id=nid,
                tier="truth",
                subkind="cache_store",
                label=f"redis:{slug}:*",
                source_file=rel_repo,
                line=line,
                status="clean",
                role="ephemeral",
                cluster="redis",
                summary=summary,
            )
        return nid

    def link(src: str, dst: str, kind: str, rel_repo: str, note: str) -> None:
        key = (src, dst, kind)
        if key not in seen_edges:
            seen_edges.add(key)
            manip.edges.append(
                AtlasEdge(
                    id=f"e:{src}->{dst}:{kind}",
                    source_id=src,
                    target_id=dst,
                    kind=kind,  # type: ignore[arg-type]
                    verification="verified",
                    evidence_path=rel_repo,
                    evidence_note=note,
                )
            )

    file_entries: list[tuple[Path, str, AtlasNode, str]] = []
    route_prefix_queues: list[tuple[str, str]] = []
    task_queues_by_name: dict[str, str] = {}

    for src_file in sorted(base_dir.rglob("*")):
        if not src_file.is_file() or src_file.suffix not in _CODE_SUFFIXES:
            continue
        if any(p in _SKIP_PARTS for p in src_file.parts):
            continue
        rel_repo = src_file.relative_to(repo_root).as_posix()
        mnode = manip_by_file.get(rel_repo)
        if mnode is None:
            continue
        try:
            raw = src_file.read_text(encoding="utf-8")
        except (OSError, UnicodeError):
            continue
        txt = _strip_comments_keep_lines(raw, src_file.suffix)
        file_entries.append((src_file, rel_repo, mnode, txt))

        for tr in _TASK_ROUTE_ENTRY_RE.finditer(txt):
            pat = tr.group("pat").rstrip(".*")
            if pat:
                route_prefix_queues.append((pat, tr.group("q")))
        for dq in _DECLARED_QUEUES_RE.finditer(txt):
            lineno = txt.count("\n", 0, dq.start()) + 1
            for qm in re.finditer(r"""['"]([A-Za-z0-9_:-]+)['"]""", dq.group("body")):
                ensure_store(f"queue_{qm.group(1)}", rel_repo, lineno, "declared task queue")

    def resolve_dotted_queue(dotted: str, fallback: str) -> str:
        for pref, qn in route_prefix_queues:
            if dotted == pref or dotted.startswith(f"{pref}."):
                return qn
        return fallback

    # Pre-index Python Celery task symbols -> resolved queue lane
    for src_file, rel_repo, _mnode, txt in file_entries:
        if src_file.suffix != ".py":
            continue
        rel_base = src_file.relative_to(base_dir).with_suffix("").as_posix()
        dotted_mod = rel_base.replace("/", ".")
        for wm in _WORKER_DEF_RE.finditer(txt):
            if not wm.group("cel_dec"):
                continue
            win = txt[wm.end() : wm.end() + 260]
            dm = _NEXT_PY_DEF_RE.search(win)
            if not dm:
                continue
            fn_name = dm.group("fn")
            qm = _EXPLICIT_QUEUE_OPT_RE.search(win[: dm.start()])
            lane = qm.group("q") if qm else resolve_dotted_queue(
                f"{dotted_mod}.{fn_name}",
                "default" if route_prefix_queues else Path(rel_repo).stem,
            )
            task_queues_by_name[fn_name] = lane
            task_queues_by_name[f"{dotted_mod}.{fn_name}"] = lane

    ast_trees: dict[str, ast.Module] = {}
    named_invalidations: dict[str, tuple[str, int, str]] = {}
    for src_file, rel_repo, _mnode, txt in file_entries:
        has_sdk = bool(_REDIS_SDK_RE.search(txt))
        pre_py: _PyRedisCalls | None = None
        if src_file.suffix == ".py":
            try:
                tree = ast.parse(src_file.read_text(encoding="utf-8"))
                ast_trees[rel_repo] = tree
                pre_py = _PyRedisCalls(tree)
            except (OSError, UnicodeError, SyntaxError, ValueError):
                pre_py = None
        for cm in _REDIS_CALL_RE.finditer(txt):
            resolved = _resolve_redis_call_key(txt, cm, has_sdk, pre_py)
            if resolved is None:
                continue
            raw_key, _ = resolved
            op = cm.group("op")
            if op in _INVALIDATE_OPS:
                pfx_lc = raw_key.split(":", 1)[0].lower()
                if pfx_lc != "default" and pfx_lc not in named_invalidations:
                    lineno = txt.count("\n", 0, cm.start()) + 1
                    named_invalidations[pfx_lc] = (rel_repo, lineno, op)
        for rm in _RUST_CMD_RE.finditer(txt):
            op = rm.group("op")
            if op in _INVALIDATE_OPS:
                pfx_lc = rm.group("key").split(":", 1)[0].lower()
                if pfx_lc != "default" and pfx_lc not in named_invalidations:
                    lineno = txt.count("\n", 0, rm.start()) + 1
                    named_invalidations[pfx_lc] = (rel_repo, lineno, op)

    for src_file, rel_repo, mnode, txt in file_entries:
        has_sdk = bool(_REDIS_SDK_RE.search(txt))
        rel_base = src_file.relative_to(base_dir).with_suffix("").as_posix()
        dotted_mod = rel_base.replace("/", ".")

        # 1. Worker / queue entry doors (Celery, BullMQ, Asynq)
        for wm in _WORKER_DEF_RE.finditer(txt):
            worker_node_ids.add(mnode.id)
            if wm.group("bull_q"):
                qname = wm.group("bull_q")
            elif wm.group("cel_dec"):
                dm = _NEXT_PY_DEF_RE.search(txt[wm.end() : wm.end() + 260])
                fn_name = dm.group("fn") if dm else ""
                qname = task_queues_by_name.get(f"{dotted_mod}.{fn_name}", Path(rel_repo).stem)
            else:
                qname = Path(rel_repo).stem
            lineno = txt.count("\n", 0, wm.start()) + 1
            sid = ensure_store(f"queue_{qname}", rel_repo, lineno, "task queue")
            readers.setdefault(sid, set()).add(mnode.id)
            link(mnode.id, sid, "reads_truth", rel_repo, f"Worker consumes Redis queue `{qname}`.")

        for pm in _QUEUE_PRODUCE_RE.finditer(txt):
            explicit_qm = _EXPLICIT_QUEUE_OPT_RE.search(_extract_call_window(txt, pm.end()))
            if explicit_qm:
                qname = explicit_qm.group("q")
            elif pm.group("bull_q") or pm.group("asynq_q"):
                qname = pm.group("bull_q") or pm.group("asynq_q")
            else:
                tsym = pm.group("task") or "tasks"
                qname = task_queues_by_name.get(tsym, "default" if route_prefix_queues else tsym)
            lineno = txt.count("\n", 0, pm.start()) + 1
            sid = ensure_store(f"queue_{qname}", rel_repo, lineno, "task queue")
            writers.setdefault(sid, set()).add(mnode.id)
            link(mnode.id, sid, "writes_truth", rel_repo, f"Enqueues job onto Redis queue `{qname}`.")

        # 1b. Dynamic `send_task(...)` & Scheduled Beat / Cron producers (`beat_schedule`, `add_periodic_task`, `asynq.Scheduler`)
        for stm in _SEND_TASK_RE.finditer(txt):
            fqn = stm.group("task_fqn")
            explicit_qm = _EXPLICIT_QUEUE_OPT_RE.search(txt[stm.end() : stm.end() + 220])
            qname = explicit_qm.group("q") if explicit_qm else task_queues_by_name.get(
                fqn, resolve_dotted_queue(fqn, "default" if route_prefix_queues else fqn.rsplit(".", 1)[-1])
            )
            lineno = txt.count("\n", 0, stm.start()) + 1
            sid = ensure_store(f"queue_{qname}", rel_repo, lineno, "task queue")
            writers.setdefault(sid, set()).add(mnode.id)
            link(mnode.id, sid, "writes_truth", rel_repo, f"`send_task('{fqn}')` dispatches onto Redis queue `{qname}`.")

        for bm in _BEAT_TASK_ENTRY_RE.finditer(txt):
            fqn = bm.group("task_fqn")
            tail_slice = txt[bm.end() : bm.end() + 240].split("},", 1)[0]
            explicit_qm = _EXPLICIT_QUEUE_OPT_RE.search(tail_slice)
            qname = explicit_qm.group("q") if explicit_qm else task_queues_by_name.get(
                fqn, resolve_dotted_queue(fqn, "default")
            )
            lineno = txt.count("\n", 0, bm.start()) + 1
            sid = ensure_store(f"queue_{qname}", rel_repo, lineno, "periodic beat queue")
            writers.setdefault(sid, set()).add(mnode.id)
            worker_node_ids.add(mnode.id)
            link(mnode.id, sid, "writes_truth", rel_repo, f"Scheduled Beat/cron entry `{fqn}` enqueues onto `{qname}`.")

        for apm in _ADD_PERIODIC_RE.finditer(txt):
            sig = apm.group("sig")
            qname = task_queues_by_name.get(sig, "default" if route_prefix_queues else sig)
            lineno = txt.count("\n", 0, apm.start()) + 1
            sid = ensure_store(f"queue_{qname}", rel_repo, lineno, "periodic beat queue")
            writers.setdefault(sid, set()).add(mnode.id)
            worker_node_ids.add(mnode.id)
            link(mnode.id, sid, "writes_truth", rel_repo, f"`add_periodic_task` schedules `{sig}` onto `{qname}`.")

        for asm in _ASYNQ_SCHED_RE.finditer(txt):
            qname = asm.group("asynq_q")
            lineno = txt.count("\n", 0, asm.start()) + 1
            sid = ensure_store(f"queue_{qname}", rel_repo, lineno, "periodic cron queue")
            writers.setdefault(sid, set()).add(mnode.id)
            worker_node_ids.add(mnode.id)
            link(mnode.id, sid, "writes_truth", rel_repo, f"Asynq cron scheduler enqueues `{qname}`.")

        # 2. Keyspace reads/writes & TRUTH-004 lifetime / authority check
        expired_recv_prefixes = {
            (em.group("recv"), em.group("key").rstrip(":").lower()) for em in _EXPIRE_CALL_RE.finditer(txt)
        }
        expired_prefixes = {pfx for _recv, pfx in expired_recv_prefixes}

        py_calls = _PyRedisCalls(ast_trees[rel_repo]) if rel_repo in ast_trees else None

        def record_unbounded_write(
            caller_node: AtlasNode,
            caller_file: str,
            sid: str,
            prefix: str,
            raw_key: str,
            op: str,
            lineno: int,
            *,
            rust_style: bool = False,
        ) -> None:
            inval = named_invalidations.get(prefix.lower()) if prefix.lower() != "default" else None
            if inval is not None:
                inval_stores.setdefault(sid, []).append(inval)
                return
            second_auth = _find_second_authority(prefix, written_sql_stems)
            if second_auth is not None:
                redis_nodes[sid].status = "duplicated_truth"
                conflict_stores[sid] = second_auth.id
                if caller_node.status == "clean":
                    caller_node.status = "gray_zone"
                manip.findings.append(
                    RawCandidateFinding(
                        rule_code="TRUTH-004",
                        node_id=caller_node.id,
                        target_node_id=sid,
                        source_file=caller_file,
                        line=lineno,
                        title=f"Unbounded Redis `{op}` on `{prefix}:*` conflicts with `{second_auth.label}`",
                        detail=(
                            f"{caller_file}:{lineno} writes `{raw_key}` without TTL or invalidation while "
                            f"active SQL table `{second_auth.label}` ({second_auth.id}) establishes a "
                            "conflicting second authority."
                        ),
                        remediation=(
                            "Bind writes to TTL/explicit invalidation and record `derived_cache` "
                            f"purpose referencing `{second_auth.id}` if it is a replica/cache."
                        ),
                    )
                )
                return
            if redis_nodes[sid].status == "clean":
                redis_nodes[sid].status = "gray_zone"
            unestablished_stores.add(sid)
            if caller_node.status == "clean":
                caller_node.status = "gray_zone"
            title = (
                f"Unestablished expiration on Rust Redis `{op}` for `{prefix}:*`"
                if rust_style
                else f"Unestablished expiration on Redis `{op}` for `{prefix}:*`"
            )
            manip.findings.append(
                RawCandidateFinding(
                    rule_code="TRUTH-004",
                    node_id=caller_node.id,
                    target_node_id=sid,
                    source_file=caller_file,
                    line=lineno,
                    title=title,
                    detail=(
                        f"{caller_file}:{lineno} writes `{raw_key}` without an observed TTL (`ex`/`px`/`setex`) "
                        "or explicit invalidation (`del`/`unlink`). Expiration is unestablished; this "
                        "does not by itself prove duplicated authoritative truth."
                    ),
                    remediation=(
                        "Add a TTL (`ex=`/`setex`), add explicit invalidation (`delete`/`unlink`), "
                        "or declare store purpose (such as `persistent_config` with recovery expectations)."
                    ),
                )
            )

        for cm in _REDIS_CALL_RE.finditer(txt):
            resolved = _resolve_redis_call_key(txt, cm, has_sdk, py_calls)
            if resolved is None:
                continue
            raw_key, py_call = resolved
            op = cm.group("op")
            lineno = txt.count("\n", 0, cm.start()) + 1
            call_args = _extract_call_window(txt, cm.end())
            prefix = raw_key.split(":", 1)[0]
            sid = ensure_store(prefix, rel_repo, lineno, "keyspace")

            if op in _READ_OPS:
                readers.setdefault(sid, set()).add(mnode.id)
                link(mnode.id, sid, "reads_truth", rel_repo, f"Reads Redis keyspace `{prefix}:*` via `{op}`.")
            elif op in _INVALIDATE_OPS:
                writers.setdefault(sid, set()).add(mnode.id)
                link(mnode.id, sid, "writes_truth", rel_repo, f"Invalidates Redis keyspace `{prefix}:*` via `{op}`.")
            elif op in _TTL_WRITE_OPS or op in _UNBOUNDED_CANDIDATE_OPS:
                writers.setdefault(sid, set()).add(mnode.id)
                link(mnode.id, sid, "writes_truth", rel_repo, f"Writes Redis keyspace `{prefix}:*` via `{op}`.")
                has_ttl = (
                    op in _TTL_WRITE_OPS
                    or (
                        py_calls is not None
                        and py_call is not None
                        and (py_calls.has_ttl(py_call, op) or py_calls.expired_after(py_call))
                    )
                    or (
                        py_calls is None
                        and (
                            bool(_TTL_OPT_RE.search(call_args))
                            or (src_file.suffix == ".go" and op == "Set" and _go_set_has_ttl(call_args))
                            or (cm.group("recv"), prefix.lower()) in expired_recv_prefixes
                        )
                    )
                )
                if has_ttl:
                    ttl_stores.add(sid)
                else:
                    record_unbounded_write(mnode, rel_repo, sid, prefix, raw_key, op, lineno)
                if mnode.subkind == "route" and has_service_layer:
                    manip.findings.append(
                        RawCandidateFinding(
                            rule_code="TRUTH-003",
                            node_id=mnode.id,
                            target_node_id=sid,
                            source_file=rel_repo,
                            line=lineno,
                            title=f"HTTP route `{mnode.label}` mutates Redis `{prefix}:*` directly",
                            detail=f"{rel_repo}:{lineno} mutates Redis inside the HTTP route handler instead of a domain service.",
                            remediation="Move cache/queue writes behind an explicit domain service method.",
                        )
                    )

        for rm in _RUST_CMD_RE.finditer(txt):
            op = rm.group("op")
            raw_key = rm.group("key")
            prefix = raw_key.split(":", 1)[0]
            lineno = txt.count("\n", 0, rm.start()) + 1
            sid = ensure_store(prefix, rel_repo, lineno, "keyspace")
            if op in _READ_OPS:
                readers.setdefault(sid, set()).add(mnode.id)
                link(mnode.id, sid, "reads_truth", rel_repo, f"Rust `redis::cmd({op})` reads `{prefix}:*`.")
            elif op in _INVALIDATE_OPS:
                writers.setdefault(sid, set()).add(mnode.id)
                link(mnode.id, sid, "writes_truth", rel_repo, f"Rust `redis::cmd({op})` invalidates `{prefix}:*`.")
            elif op in _TTL_WRITE_OPS or op in _UNBOUNDED_CANDIDATE_OPS:
                writers.setdefault(sid, set()).add(mnode.id)
                link(mnode.id, sid, "writes_truth", rel_repo, f"Rust `redis::cmd({op})` writes `{prefix}:*`.")
                if op in _UNBOUNDED_CANDIDATE_OPS and prefix.lower() not in expired_prefixes:
                    record_unbounded_write(
                        mnode, rel_repo, sid, prefix, raw_key, op, lineno, rust_style=True
                    )
                else:
                    ttl_stores.add(sid)

    # Clear false MANIP-003 inert warnings on verified background queue workers
    if worker_node_ids:
        manip.findings[:] = [
            f
            for f in manip.findings
            if not (f.rule_code == "MANIP-003" and f.node_id in worker_node_ids)
        ]
        for mnode in manip.nodes:
            if mnode.id in worker_node_ids and mnode.status == "unwired":
                mnode.status = "clean"

    obs_source = truth.observation_source
    if redis_dsn:
        live_prefixes, obs = probe_redis_keyspace_prefixes(redis_dsn)
        if obs == "redis_scan":
            obs_source = f"{truth.observation_source}+redis_scan"
        for pfx in sorted(live_prefixes):
            ensure_store(pfx, f"{backend_subdir}/redis", 1, "live keyspace")

    for sid, snode in sorted(redis_nodes.items()):
        snode.read_by_count = len(readers.get(sid, set()))
        snode.written_by_count = len(writers.get(sid, set()))
        if sid in conflict_stores:
            snode.verification_note = f"second authority candidate ({conflict_stores[sid]})"
        elif sid in unestablished_stores:
            snode.verification_note = "unknown lifetime (no TTL or invalidation observed)"
        elif sid in inval_stores:
            inv_path, inv_line, inv_op = inval_stores[sid][0]
            snode.summary = (
                f"{snode.summary} Explicit invalidation observed (`{inv_op}` at `{inv_path}:{inv_line}`; no TTL configured)."
            )
            snode.verification_note = f"explicit invalidation observed ({inv_path}:{inv_line})"
        elif sid in ttl_stores:
            snode.summary = f"{snode.summary} TTL expiration observed."
            snode.verification_note = "TTL expiration observed"
        truth.nodes.append(snode)
    return obs_source
