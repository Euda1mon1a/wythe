"""Pure-AST Python & safe repository file inspector for `wythe-plugin-agent-harness`.

Security boundary:
- Never imports or executes scanned repository code.
- Rejects symlinked roots, symlinked directories/files, paths escaping `repo_root.resolve()`,
  and files larger than `512 KiB`.
"""

from __future__ import annotations

import ast
import json
import os
import re
import tomllib
from dataclasses import dataclass, field
from pathlib import Path, PurePosixPath

MAX_FILE_BYTES = 524_288  # 512 KiB strict static scan cap

EXCLUDED_DIR_NAMES = frozenset(
    {
        ".git",
        ".venv",
        "venv",
        "env",
        "node_modules",
        "vendor",
        "__pycache__",
        "tests",
        "test",
        "__tests__",
        "fixtures",
        "docs",
        "archive",
        "archived",
        "disabled",
        "dist",
        "build",
        ".next",
        ".svelte-kit",
        ".tox",
        ".mypy_cache",
        ".pytest_cache",
    }
)

DISCOVERY_IDENTIFIERS = frozenset(
    {"search_tools", "discover_capabilities", "discover_tools"}
)
SLICE_IDENTIFIERS = frozenset({"slice_mode", "tool_slice", "slm_slice"})
VERIFICATION_PREFIXES = (
    "verify",
    "validate",
    "check_",
    "check",
    "receipt",
    "emit_receipt",
    "build_receipt",
    "record_receipt",
    "run_tests",
    "pytest",
    "tsc",
)
MUTATION_STOP_NAMES = frozenset(
    {
        "files_modified",
        "file_modified",
        "edited",
        "files_edited",
        "mutated",
        "wrote_file",
        "changes_made",
        "has_edits",
    }
)
CANONICAL_CLIENT_STEM_RE = re.compile(
    r"(?:^|_|-)(?:llm_client|model_client|llm_adapter|model_adapter|chat_client|inference_client|ai_client|llmClient|modelClient|llmAdapter|chatAdapter)(?:$|_|-|\.)",
    re.IGNORECASE,
)
RAW_COMPLETION_PATH_RE = re.compile(
    r"(?:/v1/chat/completions|/chat/completions|/v1/completions|/v1/messages)\b"
)


@dataclass(frozen=True)
class HarnessConfig:
    """Thresholds loaded from `[tool.wythe.agent_harness]` in target `pyproject.toml`."""

    max_slm_tools: int = 5
    max_slm_schema_tokens: int = 1000
    max_un_timed_loop_rounds: int = 25


@dataclass(frozen=True)
class PromptSurface:
    rel_path: str
    line: int
    scope_name: str
    language: str
    is_volatile: bool
    volatile_reasons: tuple[str, ...] = ()
    has_tail_turn_context: bool = False
    mechanism: str = "messages[0]"


@dataclass(frozen=True)
class ToolManifestRecord:
    rel_path: str
    line: int
    scope_name: str
    manifest_name: str
    language: str
    tool_names: tuple[str, ...]
    tool_count: int
    byte_len: int
    approx_tokens: int
    has_progressive_discovery: bool
    has_slice_selector: bool
    is_explicit_slm_slice: bool = False


@dataclass(frozen=True)
class RegistryLoadRecord:
    rel_path: str
    line: int
    scope_name: str
    language: str
    registry_hint: str
    accessed_keys: tuple[str, ...] = ()
    returns_hardcoded_tools: bool = False
    substituted_symbols: tuple[str, ...] = ()
    fallback_symbols: tuple[str, ...] = ()
    has_dynamic_lookup: bool = False


@dataclass(frozen=True)
class AgentLoopRecord:
    rel_path: str
    line: int
    scope_name: str
    language: str
    is_unbounded: bool
    max_rounds: int | None
    has_step_timeout: bool
    has_duplicate_brake: bool
    premature_stop_reasons: tuple[str, ...] = ()
    has_verification_gate: bool = False
    called_adapter_symbol: str | None = None


@dataclass(frozen=True)
class RawHttpBypassRecord:
    rel_path: str
    line: int
    scope_name: str
    language: str
    callee: str
    endpoint: str


@dataclass(frozen=True)
class CanonicalClientRecord:
    rel_path: str
    line: int
    symbol_name: str
    language: str


@dataclass(frozen=True)
class HelperCallRecord:
    rel_path: str
    line: int
    caller_scope: str
    callee_symbol: str
    target_rel_hint: str | None = None


@dataclass
class HarnessInspectionBundle:
    prompts: list[PromptSurface] = field(default_factory=list)
    manifests: list[ToolManifestRecord] = field(default_factory=list)
    registry_loads: list[RegistryLoadRecord] = field(default_factory=list)
    loops: list[AgentLoopRecord] = field(default_factory=list)
    raw_http_calls: list[RawHttpBypassRecord] = field(default_factory=list)
    canonical_clients: list[CanonicalClientRecord] = field(default_factory=list)
    helper_calls: list[HelperCallRecord] = field(default_factory=list)
    parse_errors: list[str] = field(default_factory=list)
    skipped_files: int = 0

    def merge(self, other: HarnessInspectionBundle) -> None:
        self.prompts.extend(other.prompts)
        self.manifests.extend(other.manifests)
        self.registry_loads.extend(other.registry_loads)
        self.loops.extend(other.loops)
        self.raw_http_calls.extend(other.raw_http_calls)
        self.canonical_clients.extend(other.canonical_clients)
        self.helper_calls.extend(other.helper_calls)
        self.parse_errors.extend(other.parse_errors)
        self.skipped_files += other.skipped_files


def is_safe_regular_file(path: Path, real_root: Path, max_bytes: int = MAX_FILE_BYTES) -> bool:
    """Verify `path` is a non-symlink regular file inside `real_root` within `max_bytes`."""
    try:
        if path.is_symlink() or not path.is_file():
            return False
        resolved = path.resolve()
        if not resolved.is_relative_to(real_root):
            return False
        return path.stat().st_size <= max_bytes
    except OSError:
        return False


def iter_safe_repo_files(
    repo_root: Path,
    suffixes: set[str],
) -> tuple[list[tuple[Path, str]], int]:
    """Walk `repo_root` safely without following symlinks or reading >512 KiB files."""
    if repo_root.is_symlink() or not repo_root.exists():
        return [], 1
    try:
        real_root = repo_root.resolve()
    except OSError:
        return [], 1

    collected: list[tuple[Path, str]] = []
    skipped = 0
    for parent, dirs, names in os.walk(real_root, followlinks=False):
        parent_path = Path(parent)
        kept_dirs: list[str] = []
        for dname in sorted(dirs):
            dpath = parent_path / dname
            if dname in EXCLUDED_DIR_NAMES or dname.startswith(".") or dpath.is_symlink():
                skipped += 1
                continue
            try:
                if not dpath.resolve().is_relative_to(real_root):
                    skipped += 1
                    continue
            except OSError:
                skipped += 1
                continue
            kept_dirs.append(dname)
        dirs[:] = kept_dirs

        for fname in sorted(names):
            fpath = parent_path / fname
            if fpath.suffix not in suffixes:
                continue
            if fname.endswith((".d.ts", ".min.js")) or any(
                tag in fname for tag in (".test.", ".spec.", ".stories.", ".e2e-spec.")
            ):
                continue
            if not is_safe_regular_file(fpath, real_root):
                skipped += 1
                continue
            rel = fpath.resolve().relative_to(real_root).as_posix()
            collected.append((fpath, rel))
    return collected, skipped


def load_harness_config(repo_root: Path) -> HarnessConfig:
    """Read optional `[tool.wythe.agent_harness]` settings from target `pyproject.toml`."""
    if repo_root.is_symlink() or not repo_root.exists():
        return HarnessConfig()
    try:
        real_root = repo_root.resolve()
        pyproject = repo_root / "pyproject.toml"
        if not is_safe_regular_file(pyproject, real_root):
            return HarnessConfig()
        raw = tomllib.loads(pyproject.read_text(encoding="utf-8"))
    except (OSError, UnicodeError, tomllib.TOMLDecodeError, ValueError):
        return HarnessConfig()

    tool_tbl = raw.get("tool")
    wythe_tbl = tool_tbl.get("wythe") if isinstance(tool_tbl, dict) else None
    cfg = wythe_tbl.get("agent_harness") if isinstance(wythe_tbl, dict) else None
    if not isinstance(cfg, dict):
        return HarnessConfig()

    def _pos_int(key: str, default: int, alt_key: str | None = None) -> int:
        val = cfg.get(key, cfg.get(alt_key) if alt_key else None)
        if isinstance(val, int) and not isinstance(val, bool) and val > 0:
            return val
        return default

    return HarnessConfig(
        max_slm_tools=_pos_int("max_slm_tools", 5),
        max_slm_schema_tokens=_pos_int("max_slm_schema_tokens", 1000),
        max_un_timed_loop_rounds=_pos_int(
            "max_un_timed_loop_rounds", 25, "max_loop_rounds_without_timeout"
        ),
    )


def estimate_schema_budget(raw_obj: object) -> tuple[int, int]:
    """Return `(byte_len, approx_tokens)` using `max(1, (byte_len + 3) // 4)`."""
    encoded = json.dumps(
        raw_obj, sort_keys=True, separators=(",", ":"), ensure_ascii=True
    ).encode("utf-8")
    byte_len = len(encoded)
    return byte_len, max(1, (byte_len + 3) // 4)


def _dotted_name(node: ast.AST | None) -> str:
    if node is None:
        return ""
    if isinstance(node, ast.Name):
        return node.id
    if isinstance(node, ast.Attribute):
        head = _dotted_name(node.value)
        return f"{head}.{node.attr}" if head else node.attr
    if isinstance(node, ast.Call):
        return _dotted_name(node.func)
    return ""


def _eval_static_ast_value(
    node: ast.AST | None,
    env: dict[str, object] | None = None,
    depth: int = 0,
) -> object:
    """Safely materialize JSON-like AST literals and bounded `range(N)` comprehensions."""
    if node is None or depth > 14:
        return None
    local_env = env or {}
    if isinstance(node, ast.Constant):
        if isinstance(node.value, (str, int, float, bool)) or node.value is None:
            return node.value
        return str(node.value)
    if isinstance(node, ast.Name):
        return local_env.get(node.id, f"<ref:{node.id}>")
    if isinstance(node, ast.JoinedStr):
        parts: list[str] = []
        for part in node.values:
            if isinstance(part, ast.Constant) and isinstance(part.value, str):
                parts.append(part.value)
            elif isinstance(part, ast.FormattedValue):
                val = _eval_static_ast_value(part.value, local_env, depth + 1)
                parts.append(str(val) if val is not None else "{expr}")
        return "".join(parts)
    if isinstance(node, (ast.List, ast.Tuple)):
        return [_eval_static_ast_value(elt, local_env, depth + 1) for elt in node.elts[:250]]
    if isinstance(node, ast.Dict):
        out: dict[str, object] = {}
        for k_node, v_node in zip(node.keys, node.values, strict=False):
            if k_node is None:
                spread = _eval_static_ast_value(v_node, local_env, depth + 1)
                if isinstance(spread, dict):
                    out.update(spread)
                continue
            k_val = _eval_static_ast_value(k_node, local_env, depth + 1)
            if isinstance(k_val, str):
                out[k_val] = _eval_static_ast_value(v_node, local_env, depth + 1)
        return out
    if isinstance(node, ast.ListComp) and len(node.generators) == 1:
        gen = node.generators[0]
        if (
            isinstance(gen.target, ast.Name)
            and isinstance(gen.iter, ast.Call)
            and _dotted_name(gen.iter.func) == "range"
            and gen.iter.args
        ):
            bound = _eval_static_ast_value(gen.iter.args[-1], local_env, depth + 1)
            start = (
                _eval_static_ast_value(gen.iter.args[0], local_env, depth + 1)
                if len(gen.iter.args) >= 2
                else 0
            )
            if isinstance(bound, int) and isinstance(start, int) and 0 <= bound - start <= 250:
                items: list[object] = []
                for idx in range(start, bound):
                    sub_env = {**local_env, gen.target.id: idx}
                    items.append(_eval_static_ast_value(node.elt, sub_env, depth + 1))
                return items
    return None


def _extract_tool_schema_items(val: object) -> list[dict[str, object]]:
    if not isinstance(val, list):
        return []
    tools: list[dict[str, object]] = []
    for item in val:
        if not isinstance(item, dict):
            continue
        fn_block = item.get("function")
        if isinstance(fn_block, dict) and isinstance(fn_block.get("name"), str) or isinstance(item.get("name"), str) and (
            any(k in item for k in ("inputSchema", "input_schema", "parameters", "description"))
            or item.get("type") in ("function", "tool")
        ):
            tools.append(item)
    return tools


_VOLATILE_CALL_TAILS = frozenset(
    {
        "now",
        "utcnow",
        "today",
        "strftime",
        "uuid4",
        "uuid1",
        "random",
        "randint",
        " randrange",
        "choice",
        "token_hex",
        "token_urlsafe",
    }
)
_VOLATILE_CALL_DOTTED = frozenset(
    {
        "datetime.now",
        "datetime.datetime.now",
        "datetime.utcnow",
        "datetime.datetime.utcnow",
        "date.today",
        "datetime.date.today",
        "time.time",
        "time.monotonic",
        "time.perf_counter",
        "time.strftime",
        "uuid.uuid4",
        "uuid.uuid1",
        "uuid4",
        "uuid1",
    }
)
_VOLATILE_VAR_TOKENS = frozenset(
    {
        "rag_context",
        "rag_chunks",
        "retrieved_chunks",
        "retrieved_docs",
        "retrieved_context",
        "memory_snippet",
        "memory_context",
        "live_memories",
        "memories",
        "session_state",
        "session_id",
        "turn_id",
        "request_id",
        "current_time",
        "now_iso",
        "timestamp",
        "clock_str",
    }
)


def _volatile_reasons_in_py_expr(
    expr: ast.AST | None,
    sym_exprs: dict[str, ast.AST],
    static_consts: set[str],
    seen: set[str] | None = None,
) -> list[str]:
    """Return volatile clock/UUID/random/RAG expressions interpolated in a system prefix."""
    if expr is None:
        return []
    visited = set(seen or ())
    reasons: list[str] = []

    def _scan(sub: ast.AST, in_interp: bool = False) -> None:
        if isinstance(sub, ast.Call):
            dotted = _dotted_name(sub.func)
            leaf = dotted.rsplit(".", 1)[-1]
            if (
                dotted in _VOLATILE_CALL_DOTTED
                or leaf in _VOLATILE_CALL_TAILS
                or dotted.startswith(("random.", "secrets."))
                or leaf.startswith(("retrieve_", "search_memory", "fetch_memor", "get_rag"))
            ):
                label = dotted or leaf
                if label not in reasons:
                    reasons.append(label)
            elif dotted in sym_exprs and dotted not in visited:
                visited.add(dotted)
                for r in _volatile_reasons_in_py_expr(
                    sym_exprs[dotted], sym_exprs, static_consts, visited
                ):
                    if r not in reasons:
                        reasons.append(r)
        elif isinstance(sub, ast.Name):
            nm = sub.id
            if nm in static_consts or nm.isupper():
                return
            if nm in sym_exprs and nm not in visited:
                visited.add(nm)
                sub_reasons = _volatile_reasons_in_py_expr(
                    sym_exprs[nm], sym_exprs, static_consts, visited
                )
                for r in sub_reasons:
                    if r not in reasons:
                        reasons.append(r)
                if sub_reasons:
                    return
            if (
                in_interp
                and (
                    nm.lower() in _VOLATILE_VAR_TOKENS
                    or any(
                        tok in nm.lower()
                        for tok in (
                            "rag",
                            "memory",
                            "memor",
                            "retrieved",
                            "timestamp",
                            "clock",
                            "now_iso",
                            "current_time",
                            "session_id",
                            "session_state",
                            "turn_id",
                            "turn_context",
                            "request_id",
                            "uuid",
                            "nonce",
                        )
                    )
                )
                and nm not in reasons
            ):
                reasons.append(nm)
        elif isinstance(sub, ast.JoinedStr):
            for part in sub.values:
                if isinstance(part, ast.FormattedValue):
                    _scan(part.value, in_interp=True)
            return
        elif isinstance(sub, ast.BinOp) and isinstance(sub.op, (ast.Add, ast.Mod)):
            _scan(sub.left, in_interp=True)
            _scan(sub.right, in_interp=True)
            return

        for child in ast.iter_child_nodes(sub):
            _scan(child, in_interp=in_interp)

    _scan(expr, in_interp=False)
    return reasons


def _expr_has_tail_turn_context(
    expr: ast.AST | None,
    sym_exprs: dict[str, ast.AST],
    static_consts: set[str],
) -> bool:
    if expr is None:
        return False
    for sub in ast.walk(expr):
        if isinstance(sub, ast.Constant) and isinstance(sub.value, str):
            if "[TURN CONTEXT]" in sub.value or "TURN_CONTEXT" in sub.value:
                return True
        elif isinstance(sub, ast.Name) and sub.id in sym_exprs:
            for inner in ast.walk(sym_exprs[sub.id]):
                if (
                    isinstance(inner, ast.Constant)
                    and isinstance(inner.value, str)
                    and "[TURN CONTEXT]" in inner.value
                ):
                    return True
    return bool(_volatile_reasons_in_py_expr(expr, sym_exprs, static_consts))


def _dict_role_and_content(node: ast.Dict) -> tuple[str | None, ast.AST | None]:
    role_val: str | None = None
    content_expr: ast.AST | None = None
    for k_node, v_node in zip(node.keys, node.values, strict=False):
        if isinstance(k_node, ast.Constant) and isinstance(k_node.value, str):
            if k_node.value == "role" and isinstance(v_node, ast.Constant) and isinstance(v_node.value, str):
                role_val = v_node.value
            elif k_node.value in ("content", "text"):
                content_expr = v_node
    return role_val, content_expr


def _resolve_py_path_str(node: ast.AST | None, str_env: dict[str, str]) -> str | None:
    if node is None:
        return None
    if isinstance(node, ast.Constant) and isinstance(node.value, str):
        return node.value
    if isinstance(node, ast.Name) and node.id in str_env:
        return str_env[node.id]
    if isinstance(node, ast.Call) and _dotted_name(node.func).endswith("Path") and node.args:
        return _resolve_py_path_str(node.args[0], str_env)
    if isinstance(node, ast.BinOp) and isinstance(node.op, (ast.Div, ast.Add)):
        left = _resolve_py_path_str(node.left, str_env)
        right = _resolve_py_path_str(node.right, str_env)
        if left and right:
            sep = "/" if isinstance(node.op, ast.Div) else ""
            return f"{left.rstrip('/')}{sep}{right.lstrip('/')}" if sep else left + right
        if right and (right.endswith((".json", ".yaml", ".yml")) or "config" in right):
            return right
    return None


_LLM_CALL_TOKENS = frozenset(
    {
        "completions.create",
        "messages.create",
        "responses.create",
        "complete",
        "complete_turn",
        "chat_complete",
        "generate",
        "invoke_model",
        "call_llm",
        "call_model",
        "run_completion",
    }
)
_TOOL_DISPATCH_TOKENS = frozenset(
    {
        "execute_tool",
        "dispatch_tool",
        "run_tool",
        "call_tool",
        "invoke_tool",
        "handle_tool_call",
        "handle_tool",
    }
)
_RAW_HTTP_PY_CALLEES = frozenset(
    {
        "requests.post",
        "requests.request",
        "httpx.post",
        "httpx.request",
        "urllib.request.urlopen",
        "urllib.request.Request",
        "urlopen",
    }
)
_DUPLICATE_BRAKE_TOKENS = frozenset(
    {
        "seen_calls",
        "seen_signatures",
        "call_history",
        "last_call",
        "prev_call",
        "previous_call",
        "last_sig",
        "prev_sig",
        "call_sig",
        "call_signature",
        "duplicate_calls",
        "consecutive_duplicates",
        "repeat_count",
        "canonical_args",
    }
)


def _is_py_canonical_client_module(rel_path: str, tree: ast.Module) -> list[CanonicalClientRecord]:
    stem = PurePosixPath(rel_path).name
    records: list[CanonicalClientRecord] = []
    if CANONICAL_CLIENT_STEM_RE.search(stem):
        sym = PurePosixPath(rel_path).stem
        for stmt in tree.body:
            if isinstance(
                stmt, (ast.ClassDef, ast.FunctionDef, ast.AsyncFunctionDef)
            ) and not stmt.name.startswith("_"):
                records.append(CanonicalClientRecord(rel_path, stmt.lineno, stmt.name, "python"))
        if not records:
            records.append(CanonicalClientRecord(rel_path, 1, sym, "python"))
        return records

    for stmt in tree.body:
        if isinstance(stmt, ast.ClassDef) and any(
            stmt.name.endswith(suf)
            for suf in ("LLMClient", "ModelClient", "LLMAdapter", "ModelAdapter", "ChatAdapter")
        ):
            records.append(CanonicalClientRecord(rel_path, stmt.lineno, stmt.name, "python"))
    return records


def _extract_py_loop_ceiling(
    loop_node: ast.While | ast.For | ast.AsyncFor,
    int_env: dict[str, int],
) -> tuple[bool, int | None]:
    if isinstance(loop_node, (ast.For, ast.AsyncFor)):
        if (
            isinstance(loop_node.iter, ast.Call)
            and _dotted_name(loop_node.iter.func) == "range"
            and loop_node.iter.args
        ):
            bound_arg = loop_node.iter.args[-1]
            if isinstance(bound_arg, ast.Constant) and isinstance(bound_arg.value, int):
                return False, bound_arg.value
            if isinstance(bound_arg, ast.Name) and bound_arg.id in int_env:
                return False, int_env[bound_arg.id]
        return False, None

    # ast.While
    test = loop_node.test
    if isinstance(test, ast.Constant) and bool(test.value) is True:
        # Check if body contains an explicit counter ceiling `if step >= N: break/return/raise`
        for sub in ast.walk(loop_node):
            if (
                isinstance(sub, ast.If)
                and isinstance(sub.test, ast.Compare)
                and len(sub.test.comparators) == 1
                and any(isinstance(s, (ast.Break, ast.Return, ast.Raise)) for s in ast.walk(sub))
            ):
                comp = sub.test.comparators[0]
                if isinstance(comp, ast.Constant) and isinstance(comp.value, int):
                    return False, comp.value
                if isinstance(comp, ast.Name) and comp.id in int_env:
                    return False, int_env[comp.id]
                if isinstance(comp, ast.Name) and any(
                    tok in comp.id.lower() for tok in ("max_", "limit", "ceiling", "rounds", "steps")
                ):
                    return False, None
        return True, None

    if isinstance(test, ast.Compare) and len(test.comparators) == 1:
        comp = test.comparators[0]
        if isinstance(comp, ast.Constant) and isinstance(comp.value, int):
            return False, comp.value
        if isinstance(comp, ast.Name) and comp.id in int_env:
            return False, int_env[comp.id]
    return False, None


def _has_py_verification_call(nodes: list[ast.stmt] | ast.AST) -> bool:
    roots = nodes if isinstance(nodes, list) else [nodes]
    for root in roots:
        for sub in ast.walk(root):
            if isinstance(sub, ast.Call):
                dotted = _dotted_name(sub.func)
                leaf = dotted.rsplit(".", 1)[-1].lower()
                if dotted == "ast.parse" or leaf.startswith(VERIFICATION_PREFIXES):
                    return True
    return False


def _inspect_py_loop(
    loop_node: ast.While | ast.For | ast.AsyncFor,
    rel_path: str,
    scope_name: str,
    scope_body: list[ast.stmt],
    int_env: dict[str, int],
) -> AgentLoopRecord | None:
    has_llm = False
    has_tool = False
    has_timeout = False
    has_dup_brake = False
    adapter_sym: str | None = None

    for sub in ast.walk(loop_node):
        if isinstance(sub, ast.Call):
            dotted = _dotted_name(sub.func)
            leaf = dotted.rsplit(".", 1)[-1]
            if (
                any(dotted.endswith(tok) for tok in _LLM_CALL_TOKENS)
                or leaf in _LLM_CALL_TOKENS
                or dotted in _RAW_HTTP_PY_CALLEES
            ):
                has_llm = True
                if dotted not in _RAW_HTTP_PY_CALLEES and dotted:
                    adapter_sym = dotted
            if leaf in _TOOL_DISPATCH_TOKENS or any(
                tok in leaf.lower() for tok in ("execute_tool", "dispatch_tool", "run_tool", "call_tool")
            ):
                has_tool = True
            for kw in sub.keywords:
                if kw.arg and "timeout" in kw.arg.lower():
                    has_timeout = True
            if dotted in ("asyncio.wait_for", "asyncio.timeout"):
                has_timeout = True
            if dotted == "json.dumps" and any(kw.arg == "sort_keys" for kw in sub.keywords):
                has_dup_brake = True
        elif isinstance(sub, ast.Attribute) and sub.attr in ("tool_calls", "function_call", "tool_use") or isinstance(sub, ast.Constant) and sub.value == "tool":
            has_tool = True
        elif isinstance(sub, ast.Name):
            low = sub.id.lower()
            if low in _DUPLICATE_BRAKE_TOKENS:
                has_dup_brake = True
            if "timeout" in low:
                has_timeout = True

    if not (has_llm and has_tool):
        return None

    # Also detect tuple signature brake `(tool_name, ...)` tested with `==` or `in`
    if not has_dup_brake:
        for sub in ast.walk(loop_node):
            if isinstance(sub, ast.Compare) and any(
                isinstance(op, (ast.Eq, ast.In)) for op in sub.ops
            ):
                cmp_names = {
                    n.id.lower() for n in ast.walk(sub) if isinstance(n, ast.Name)
                }
                if cmp_names & {"sig", "signature", "key", "call_key", "seen", "history", "prev", "last"}:
                    has_dup_brake = True
                    break

    is_unbounded, max_rounds = _extract_py_loop_ceiling(loop_node, int_env)
    scope_verified = _has_py_verification_call(scope_body)
    premature_reasons: list[str] = []

    for sub in ast.walk(loop_node):
        if isinstance(sub, ast.If):
            test_names = {n.id for n in ast.walk(sub.test) if isinstance(n, ast.Name)}
            test_strs = {
                c.value for c in ast.walk(sub.test) if isinstance(c, ast.Constant) and isinstance(c.value, str)
            }
            exits_early = any(isinstance(s, (ast.Return, ast.Break)) for s in sub.body)
            branch_verified = _has_py_verification_call(sub.body) or (
                any(isinstance(s, ast.Break) for s in sub.body) and scope_verified
            )
            if exits_early and not branch_verified:
                hit_mut = sorted(test_names & MUTATION_STOP_NAMES)
                if hit_mut:
                    premature_reasons.append(f"mutation flag `{hit_mut[0]}` without verification gate")
                elif any(s.upper() in ("DONE", "TASK_COMPLETE", "FINISHED") for s in test_strs):
                    premature_reasons.append("prose `'DONE'` substring check without verification gate")

    return AgentLoopRecord(
        rel_path=rel_path,
        line=loop_node.lineno,
        scope_name=scope_name,
        language="python",
        is_unbounded=is_unbounded,
        max_rounds=max_rounds,
        has_step_timeout=has_timeout,
        has_duplicate_brake=has_dup_brake,
        premature_stop_reasons=tuple(dict.fromkeys(premature_reasons)),
        has_verification_gate=scope_verified,
        called_adapter_symbol=adapter_sym,
    )


def _extract_py_decorator_tools(tree: ast.Module) -> tuple[list[dict[str, object]], int]:
    tools: list[dict[str, object]] = []
    first_line = 0
    for stmt in ast.walk(tree):
        if not isinstance(stmt, (ast.FunctionDef, ast.AsyncFunctionDef)):
            continue
        is_mcp_tool = False
        for dec in stmt.decorator_list:
            dname = _dotted_name(dec.func if isinstance(dec, ast.Call) else dec)
            if dname.endswith(".tool") or dname == "tool":
                is_mcp_tool = True
                break
        if not is_mcp_tool:
            continue
        if not first_line:
            first_line = stmt.lineno
        props: dict[str, object] = {}
        req: list[str] = []
        for arg in stmt.args.args:
            if arg.arg in ("self", "cls", "ctx", "context"):
                continue
            props[arg.arg] = {"type": "string"}
            req.append(arg.arg)
        doc = ast.get_docstring(stmt) or ""
        tools.append(
            {
                "name": stmt.name,
                "description": doc,
                "inputSchema": {"type": "object", "properties": props, "required": req},
            }
        )
    return tools, first_line


def inspect_python_module_ast(rel_path: str, source_text: str) -> HarnessInspectionBundle:
    """Statically inspect a single Python file AST without importing or executing it."""
    bundle = HarnessInspectionBundle()
    try:
        tree = ast.parse(source_text, filename=rel_path)
    except (SyntaxError, ValueError, RecursionError) as exc:
        bundle.parse_errors.append(f"{rel_path}: {type(exc).__name__}")
        return bundle

    bundle.canonical_clients.extend(_is_py_canonical_client_module(rel_path, tree))

    mod_sym_exprs: dict[str, ast.AST] = {}
    mod_static_consts: set[str] = set()
    mod_str_env: dict[str, str] = {}
    mod_int_env: dict[str, int] = {}
    mod_tool_consts: set[str] = set()
    has_mod_discovery = False
    has_mod_slice = "--slice" in source_text

    for tok in ast.walk(tree):
        if isinstance(tok, ast.Name):
            if tok.id in DISCOVERY_IDENTIFIERS:
                has_mod_discovery = True
            if tok.id in SLICE_IDENTIFIERS:
                has_mod_slice = True
        elif isinstance(tok, (ast.FunctionDef, ast.AsyncFunctionDef)) and tok.name in DISCOVERY_IDENTIFIERS:
            has_mod_discovery = True

    for stmt in tree.body:
        val_node: ast.AST | None = None
        tgt_names: list[str] = []
        if isinstance(stmt, ast.Assign):
            val_node = stmt.value
            tgt_names = [t.id for t in stmt.targets if isinstance(t, ast.Name)]
        elif isinstance(stmt, ast.AnnAssign) and isinstance(stmt.target, ast.Name):
            val_node = stmt.value
            tgt_names = [stmt.target.id]
        if val_node is not None:
            for tname in tgt_names:
                mod_sym_exprs[tname] = val_node
                if isinstance(val_node, ast.Constant):
                    if isinstance(val_node.value, str):
                        mod_str_env[tname] = val_node.value
                        if tname.isupper():
                            mod_static_consts.add(tname)
                    elif isinstance(val_node.value, int) and not isinstance(val_node.value, bool):
                        mod_int_env[tname] = val_node.value
                s_path = _resolve_py_path_str(val_node, mod_str_env)
                if s_path:
                    mod_str_env[tname] = s_path
                eval_val = _eval_static_ast_value(val_node, mod_int_env)
                tool_items = _extract_tool_schema_items(eval_val)
                if tool_items:
                    mod_tool_consts.add(tname)
                    tnames = tuple(
                        str(
                            it["function"]["name"]
                            if isinstance(it.get("function"), dict)
                            else it.get("name", "")
                        )
                        for it in tool_items
                    )
                    blen, atoks = estimate_schema_budget(tool_items)
                    bundle.manifests.append(
                        ToolManifestRecord(
                            rel_path=rel_path,
                            line=stmt.lineno,
                            scope_name="*",
                            manifest_name=tname,
                            language="python",
                            tool_names=tnames,
                            tool_count=len(tool_items),
                            byte_len=blen,
                            approx_tokens=atoks,
                            has_progressive_discovery=has_mod_discovery
                            or bool(set(tnames) & DISCOVERY_IDENTIFIERS),
                            has_slice_selector=has_mod_slice,
                            is_explicit_slm_slice="SLM" in tname.upper(),
                        )
                    )
        elif isinstance(stmt, (ast.FunctionDef, ast.AsyncFunctionDef)):
            ret_exprs = [s.value for s in stmt.body if isinstance(s, ast.Return) and s.value is not None]
            if len(ret_exprs) == 1:
                mod_sym_exprs[stmt.name] = ret_exprs[0]

    dec_tools, dec_line = _extract_py_decorator_tools(tree)
    if dec_tools:
        tnames = tuple(str(t["name"]) for t in dec_tools)
        blen, atoks = estimate_schema_budget(dec_tools)
        bundle.manifests.append(
            ToolManifestRecord(
                rel_path=rel_path,
                line=dec_line,
                scope_name="@mcp.tool",
                manifest_name="@mcp.tool",
                language="python",
                tool_names=tnames,
                tool_count=len(dec_tools),
                byte_len=blen,
                approx_tokens=atoks,
                has_progressive_discovery=has_mod_discovery or bool(set(tnames) & DISCOVERY_IDENTIFIERS),
                has_slice_selector=has_mod_slice,
            )
        )

    llm_import_roots = {
        "openai",
        "anthropic",
        "mlx",
        "mlx_lm",
        "litellm",
        "ollama",
        "langchain",
        "llama_index",
        "llamaindex",
        "mcp",
        "fastmcp",
        "vllm",
        "genai",
        "vertexai",
    }
    mod_has_llm_ctx = bool(bundle.manifests)
    if not mod_has_llm_ctx:
        for tnode in ast.walk(tree):
            if isinstance(tnode, ast.Import):
                if any(a.name.split(".", 1)[0] in llm_import_roots for a in tnode.names):
                    mod_has_llm_ctx = True
                    break
            elif isinstance(tnode, ast.ImportFrom):
                if tnode.module and any(seg in llm_import_roots for seg in tnode.module.split(".")):
                    mod_has_llm_ctx = True
                    break
            elif isinstance(tnode, ast.Constant) and isinstance(tnode.value, str):
                if "sampling/createMessage" in tnode.value or RAW_COMPLETION_PATH_RE.search(tnode.value):
                    mod_has_llm_ctx = True
                    break
            elif isinstance(tnode, ast.Call):
                cdotted = _dotted_name(tnode.func)
                if any(
                    tok in cdotted
                    for tok in ("messages.create", "completions.create", "make_prompt_cache", "generate_step")
                ):
                    mod_has_llm_ctx = True
                    break

    scopes: list[tuple[str, int, list[ast.stmt]]] = [
        ("*", 1, [s for s in tree.body if not isinstance(s, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef))])
    ]
    for stmt in tree.body:
        if isinstance(stmt, (ast.FunctionDef, ast.AsyncFunctionDef)):
            scopes.append((stmt.name, stmt.lineno, stmt.body))
        elif isinstance(stmt, ast.ClassDef):
            for m in stmt.body:
                if isinstance(m, (ast.FunctionDef, ast.AsyncFunctionDef)):
                    scopes.append((f"{stmt.name}.{m.name}", m.lineno, m.body))

    for sc_name, sc_ln, sc_body in scopes:
        if not sc_body:
            continue
        loc_exprs = dict(mod_sym_exprs)
        loc_strs = dict(mod_str_env)
        loc_ints = dict(mod_int_env)
        for s in sc_body:
            if isinstance(s, ast.Assign) and len(s.targets) == 1 and isinstance(s.targets[0], ast.Name):
                vname = s.targets[0].id
                loc_exprs[vname] = s.value
                sp = _resolve_py_path_str(s.value, loc_strs)
                if sp:
                    loc_strs[vname] = sp
                if isinstance(s.value, ast.Constant) and isinstance(s.value.value, int) and not isinstance(s.value.value, bool):
                    loc_ints[vname] = s.value.value

        # Walk statements in this scope without descending into nested defs
        scope_nodes: list[ast.AST] = []
        stack: list[ast.AST] = list(reversed(sc_body))
        while stack:
            cur = stack.pop()
            if isinstance(cur, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef)):
                continue
            scope_nodes.append(cur)
            stack.extend(reversed(list(ast.iter_child_nodes(cur))))

        prompt_ctx_names = {"messages", "chat_messages", "prompt_messages", "system_prompt", "systemPrompt"}
        scope_has_llm_ctx = mod_has_llm_ctx or any(
            (isinstance(sn, ast.Name) and sn.id in prompt_ctx_names)
            or (isinstance(sn, ast.keyword) and sn.arg in prompt_ctx_names)
            for sn in scope_nodes
        )

        seen_prompt_lines: set[int] = set()
        seen_dict_ids: set[int] = set()
        reg_hint: str | None = None
        reg_line = sc_ln
        accessed_keys: set[str] = set()
        subst_syms: set[str] = set()
        fb_syms: set[str] = set()
        has_dyn_key = False

        for node in scope_nodes:
            # 1. Prompt surfaces (`AGENT-001`)
            if isinstance(node, (ast.List, ast.Tuple)) and node.elts:
                first = node.elts[0]
                if isinstance(first, ast.Dict):
                    role0, content0 = _dict_role_and_content(first)
                    has_peer_turn = any(
                        isinstance(elt, ast.Dict)
                        and _dict_role_and_content(elt)[0] in ("user", "assistant")
                        for elt in node.elts[1:]
                    )
                    if (
                        role0 in ("system", "developer")
                        and content0 is not None
                        and (scope_has_llm_ctx or has_peer_turn)
                        and id(first) not in seen_dict_ids
                    ):
                        seen_dict_ids.add(id(first))
                        seen_prompt_lines.add(first.lineno)
                        reasons = _volatile_reasons_in_py_expr(content0, loc_exprs, mod_static_consts)
                        tail_ctx = any(
                            isinstance(elt, ast.Dict)
                            and _dict_role_and_content(elt)[0] == "user"
                            and _expr_has_tail_turn_context(_dict_role_and_content(elt)[1], loc_exprs, mod_static_consts)
                            for elt in node.elts[1:]
                        )
                        bundle.prompts.append(
                            PromptSurface(
                                rel_path=rel_path,
                                line=first.lineno,
                                scope_name=sc_name,
                                language="python",
                                is_volatile=bool(reasons),
                                volatile_reasons=tuple(reasons),
                                has_tail_turn_context=tail_ctx,
                                mechanism="messages[0]",
                            )
                        )
            elif isinstance(node, ast.Dict):
                if id(node) not in seen_dict_ids and node.lineno not in seen_prompt_lines:
                    role_d, content_d = _dict_role_and_content(node)
                    if scope_has_llm_ctx and role_d in ("system", "developer") and content_d is not None:
                        seen_dict_ids.add(id(node))
                        seen_prompt_lines.add(node.lineno)
                        reasons = _volatile_reasons_in_py_expr(content_d, loc_exprs, mod_static_consts)
                        bundle.prompts.append(
                            PromptSurface(
                                rel_path=rel_path,
                                line=node.lineno,
                                scope_name=sc_name,
                                language="python",
                                is_volatile=bool(reasons),
                                volatile_reasons=tuple(reasons),
                                has_tail_turn_context=False,
                                mechanism="system_message",
                            )
                        )
                    for k_n, v_n in zip(node.keys, node.values, strict=False):
                        if isinstance(k_n, ast.Constant) and k_n.value == "systemPrompt" and v_n is not None:
                            seen_prompt_lines.add(node.lineno)
                            reasons = _volatile_reasons_in_py_expr(v_n, loc_exprs, mod_static_consts)
                            bundle.prompts.append(
                                PromptSurface(
                                    rel_path=rel_path,
                                    line=node.lineno,
                                    scope_name=sc_name,
                                    language="python",
                                    is_volatile=bool(reasons),
                                    volatile_reasons=tuple(reasons),
                                    has_tail_turn_context=False,
                                    mechanism="mcp_sampling",
                                )
                            )
            elif isinstance(node, ast.Call):
                dotted = _dotted_name(node.func)
                leaf = dotted.rsplit(".", 1)[-1]
                if leaf and sc_name != "*":
                    bundle.helper_calls.append(HelperCallRecord(rel_path, node.lineno, sc_name, leaf))
                # Anthropic `system=...`, MCP `systemPrompt=...`, MLX cache prompt builders
                has_msg_kw = any(k.arg == "messages" for k in node.keywords)
                for kw in node.keywords:
                    if kw.arg in ("system", "system_prompt", "systemPrompt") and node.lineno not in seen_prompt_lines:
                        if (
                            kw.arg == "system"
                            and not scope_has_llm_ctx
                            and not has_msg_kw
                            and leaf not in {"create", "chat", "complete", "stream", "generate"}
                        ):
                            continue
                        seen_prompt_lines.add(node.lineno)
                        reasons = _volatile_reasons_in_py_expr(kw.value, loc_exprs, mod_static_consts)
                        mech = "mcp_sampling" if kw.arg == "systemPrompt" else "anthropic_system"
                        bundle.prompts.append(
                            PromptSurface(
                                rel_path=rel_path,
                                line=node.lineno,
                                scope_name=sc_name,
                                language="python",
                                is_volatile=bool(reasons),
                                volatile_reasons=tuple(reasons),
                                has_tail_turn_context=False,
                                mechanism=mech,
                            )
                        )
                    elif kw.arg == "tools" and sc_name != "*":
                        t_items = _extract_tool_schema_items(_eval_static_ast_value(kw.value, loc_ints))
                        if t_items:
                            tnames = tuple(
                                str(it["function"]["name"] if isinstance(it.get("function"), dict) else it.get("name", ""))
                                for it in t_items
                            )
                            blen, atoks = estimate_schema_budget(t_items)
                            bundle.manifests.append(
                                ToolManifestRecord(
                                    rel_path=rel_path,
                                    line=node.lineno,
                                    scope_name=sc_name,
                                    manifest_name=f"{sc_name}:tools",
                                    language="python",
                                    tool_names=tnames,
                                    tool_count=len(t_items),
                                    byte_len=blen,
                                    approx_tokens=atoks,
                                    has_progressive_discovery=has_mod_discovery or bool(set(tnames) & DISCOVERY_IDENTIFIERS),
                                    has_slice_selector=has_mod_slice,
                                )
                            )
                # Raw HTTP completion calls (`AGENT-003`)
                if dotted in _RAW_HTTP_PY_CALLEES or leaf in ("post", "request", "urlopen"):
                    for arg in (*node.args, *(kw.value for kw in node.keywords)):
                        url_s = _resolve_py_path_str(arg, loc_strs) or (
                            str(_eval_static_ast_value(arg, loc_ints)) if isinstance(arg, ast.JoinedStr) else ""
                        )
                        if (
                            url_s
                            and RAW_COMPLETION_PATH_RE.search(url_s)
                            and (
                                dotted in _RAW_HTTP_PY_CALLEES
                                or any(
                                    h in dotted.lower()
                                    for h in ("http", "requests", "client", "session", "urllib")
                                )
                            )
                        ):
                            bundle.raw_http_calls.append(
                                RawHttpBypassRecord(
                                    rel_path, node.lineno, sc_name, "python", dotted or leaf, url_s
                                )
                            )
                            break
                # Dict `.get("enabled", ...)` key tracking for registry consumption
                if isinstance(node.func, ast.Attribute) and node.func.attr in ("get", "pop", "setdefault") and node.args:
                    if isinstance(node.args[0], ast.Constant) and isinstance(node.args[0].value, str):
                        accessed_keys.add(node.args[0].value)
                        if len(node.args) >= 2 and isinstance(node.args[1], ast.Name) and node.args[1].id in mod_tool_consts:
                            fb_syms.add(node.args[1].id)
                    else:
                        has_dyn_key = True

            # 2. Registry path detection & subscript/attribute tracking (`AGENT-002`)
            if isinstance(node, (ast.Constant, ast.BinOp, ast.Name)):
                cand_p = _resolve_py_path_str(node, loc_strs)
                if (
                    reg_hint is None
                    and cand_p
                    and cand_p.endswith((".json", ".yaml", ".yml"))
                    and (
                        "config/" in cand_p
                        or "configs/" in cand_p
                        or (
                            "/" not in cand_p
                            and any(
                                k in cand_p.lower()
                                for k in ("tool", "capabilit", "agent", "mcp", "registry", "skill")
                            )
                        )
                    )
                ):
                    reg_hint = cand_p
                    reg_line = getattr(node, "lineno", sc_ln)
            elif isinstance(node, ast.Subscript):
                if isinstance(node.slice, ast.Constant) and isinstance(node.slice.value, str):
                    accessed_keys.add(node.slice.value)
                elif not isinstance(node.slice, (ast.Slice, ast.Constant)):
                    has_dyn_key = True
            elif isinstance(node, ast.Attribute) and not node.attr.startswith("_"):
                accessed_keys.add(node.attr)
            elif (
                isinstance(node, ast.Assign)
                and len(node.targets) == 1
                and isinstance(node.targets[0], ast.Subscript)
                and isinstance(node.targets[0].value, ast.Name)
                and node.targets[0].value.id == "messages"
                and isinstance(node.targets[0].slice, ast.Constant)
                and node.targets[0].slice.value == 0
                and node.lineno not in seen_prompt_lines
            ):
                seen_prompt_lines.add(node.lineno)
                reasons = _volatile_reasons_in_py_expr(node.value, loc_exprs, mod_static_consts)
                bundle.prompts.append(
                    PromptSurface(
                        rel_path=rel_path,
                        line=node.lineno,
                        scope_name=sc_name,
                        language="python",
                        is_volatile=bool(reasons),
                        volatile_reasons=tuple(reasons),
                        has_tail_turn_context=False,
                        mechanism="messages[0]",
                    )
                )
            elif isinstance(node, ast.Return) and node.value is not None:
                if isinstance(node.value, ast.Name) and node.value.id in mod_tool_consts:
                    subst_syms.add(node.value.id)
            elif isinstance(node, (ast.While, ast.For, ast.AsyncFor)):
                loop_rec = _inspect_py_loop(node, rel_path, sc_name, sc_body, loc_ints)
                if loop_rec is not None:
                    bundle.loops.append(loop_rec)

        if reg_hint is not None:
            bundle.registry_loads.append(
                RegistryLoadRecord(
                    rel_path=rel_path,
                    line=reg_line,
                    scope_name=sc_name,
                    language="python",
                    registry_hint=reg_hint,
                    accessed_keys=tuple(sorted(accessed_keys)),
                    returns_hardcoded_tools=bool(subst_syms),
                    substituted_symbols=tuple(sorted(subst_syms)),
                    fallback_symbols=tuple(sorted(fb_syms - subst_syms)),
                    has_dynamic_lookup=has_dyn_key,
                )
            )

    return bundle


def inspect_python_files(repo_root: Path) -> HarnessInspectionBundle:
    """Inspect all contained `.py` source files under `repo_root`."""
    total = HarnessInspectionBundle()
    py_files, skipped = iter_safe_repo_files(repo_root, {".py"})
    total.skipped_files += skipped
    for fpath, rel_path in py_files:
        try:
            text = fpath.read_text(encoding="utf-8")
        except (OSError, UnicodeError) as exc:
            total.parse_errors.append(f"{rel_path}: {type(exc).__name__}")
            continue
        total.merge(inspect_python_module_ast(rel_path, text))
    return total
