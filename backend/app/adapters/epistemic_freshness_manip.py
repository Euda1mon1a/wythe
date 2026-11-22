"""Backend AST checks for freshness laundering (#121 MANIP-007) and static dict emit sets (#120)."""

from __future__ import annotations

import ast
import os
import stat
from collections import deque
from dataclasses import dataclass, field
from pathlib import Path

from app.adapters.base import ManipulatorExtractionResult, RawCandidateFinding
from app.adapters.ts_workspace import (
    MAX_FRONTEND_FILE_BYTES,
    safe_read_repo_text,
    safe_resolve_contained_path,
)

_SKIP_DIRS = frozenset(
    {
        ".git",
        ".venv",
        "venv",
        "node_modules",
        "__pycache__",
        "migrations",
        "alembic",
        "tests",
        "test",
        "ui_dist",
        "dist",
        "build",
    }
)
_ENVELOPE_MARKER_KEYS = frozenset(
    {
        "observed_at",
        "source_observed_at",
        "valid_until",
        "evidence_state",
        "observation_source",
        "slice_id",
    }
)
_OBS_TIME_KEYS = frozenset({"observed_at", "source_observed_at", "updated_at"})
_ENVELOPE_META_KEYS = frozenset(
    {
        "schema",
        "schema_version",
        "slice_id",
        "observed_at",
        "source_observed_at",
        "valid_until",
        "observation_source",
        "history_basis",
        "stale",
        "evidence_state",
        "ok",
        "version",
    }
)
_CLOCK_CALL_NAMES = frozenset({"now", "utcnow", "utc_now", "time", "monotonic"})
_SOURCE_READ_NAMES = frozenset(
    {
        "loads",
        "load",
        "read_text",
        "read_bytes",
        "_load_json",
        "_load_json_safe",
        "_read_json",
        "_cached_call",
    }
)
_STORE_MUTATION_NAMES = frozenset({"commit", "add", "add_all", "delete"})
_FILE_WRITE_NAMES = frozenset({"write_text", "write_bytes"})
_STORE_EXACT_NAMES = frozenset(
    {
        "db",
        "session",
        "store",
        "conn",
        "connection",
        "cursor",
        "cur",
        "tx",
        "uow",
        "repo",
        "repository",
        "redis",
        "cache",
    }
)
_STORE_SUFFIXES = ("_db", "_session", "_store", "_repo", "_conn", "_cache")
_STORE_PREFIXES = ("db_", "session_", "store_")


@dataclass
class ProducerPayloadContract:
    """Static dictionary keys emitted by a route handler or slice builder (#120)."""

    route_keys: set[str]
    source_file: str
    line: int
    node_id: str | None
    func_name: str
    emit_paths: set[str] = field(default_factory=set)
    nested_dict_roots: set[str] = field(default_factory=set)
    top_domain_keys: set[str] = field(default_factory=set)
    has_evidence_state: bool = False
    coverage: str = "complete"  # "complete" | "partial"


def _check_dir_accessible(path: Path) -> None:
    if not os.access(path, os.R_OK | os.X_OK):
        raise PermissionError(f"Directory is not readable/traversable: {path}")
    with os.scandir(path):
        pass


def _inspect_contained_subdir(repo_res: Path, sub_p: Path, label: str) -> tuple[bool, str | None]:
    """Check `sub_p` under `repo_res` with `lstat` only; return `(is_absent, reject_or_error_reason)`."""
    cur = repo_res
    for part in sub_p.parts:
        if part in ("", "."):
            continue
        cur = cur / part
        try:
            st = cur.lstat()
        except FileNotFoundError:
            return True, None
        except OSError as exc:
            return False, f"Unreadable {label} {sub_p}: {exc}"
        if stat.S_ISLNK(st.st_mode):
            return False, f"Rejected symlink/out-of-repo {label}: {sub_p}"
        if stat.S_ISDIR(st.st_mode) and not os.access(cur, os.R_OK | os.X_OK):
            return False, f"Unreadable {label} {sub_p}: directory is not readable/traversable ({cur})"
    return False, None


def _iter_python_files(
    repo_root: Path,
    backend_subdir: str,
    coverage_notes: list[str] | None = None,
) -> list[tuple[str, Path]]:
    found: list[tuple[str, Path]] = []
    try:
        if repo_root.is_symlink():
            if coverage_notes is not None:
                coverage_notes.append(f"Rejected symlink repository root: {repo_root}")
            return found
        repo_res = repo_root.resolve(strict=True)
        if not repo_res.is_dir():
            if coverage_notes is not None:
                coverage_notes.append(f"Repository root {repo_root} is not a directory")
            return found
        _check_dir_accessible(repo_res)
    except OSError as exc:
        if coverage_notes is not None:
            coverage_notes.append(f"Unreadable repository root {repo_root}: {exc}")
        return found

    if backend_subdir in ("", "."):
        base = repo_res
    else:
        sub_p = Path(backend_subdir)
        if sub_p.is_absolute() or ".." in sub_p.parts or "\x00" in backend_subdir:
            if coverage_notes is not None:
                coverage_notes.append(f"Rejected out-of-repo backend_subdir: {backend_subdir}")
            return found
        safe_sub = safe_resolve_contained_path(sub_p, repo_root)
        if safe_sub is not None:
            try:
                sub_st = safe_sub.lstat()
                if stat.S_ISLNK(sub_st.st_mode):
                    if coverage_notes is not None:
                        coverage_notes.append(f"Rejected symlink/out-of-repo backend_subdir: {backend_subdir}")
                    return found
                if not stat.S_ISDIR(sub_st.st_mode):
                    if coverage_notes is not None:
                        coverage_notes.append(f"Rejected non-directory backend_subdir: {backend_subdir}")
                    return found
                _check_dir_accessible(safe_sub)
            except FileNotFoundError:
                base = repo_res
            except OSError as exc:
                if coverage_notes is not None:
                    coverage_notes.append(f"Unreadable backend_subdir {backend_subdir}: {exc}")
                return found
            else:
                base = safe_sub
        else:
            sub_absent, bad_reason = _inspect_contained_subdir(repo_res, sub_p, "backend_subdir")
            if bad_reason is not None:
                if coverage_notes is not None:
                    coverage_notes.append(bad_reason)
                return found
            if not sub_absent:
                if coverage_notes is not None:
                    coverage_notes.append(f"Rejected symlink/out-of-repo backend_subdir: {backend_subdir}")
                return found
            base = repo_res

    def _on_walk_error(exc: OSError) -> None:
        if coverage_notes is not None:
            coverage_notes.append(f"Unreadable directory during Python walk {exc.filename or base}: {exc}")

    for root, dirs, files in os.walk(base, followlinks=False, onerror=_on_walk_error):
        kept_dirs: list[str] = []
        for d in sorted(dirs):
            if d in _SKIP_DIRS or d.startswith("."):
                continue
            d_path = Path(root) / d
            try:
                d_st = d_path.lstat()
            except OSError as exc:
                if coverage_notes is not None:
                    coverage_notes.append(f"Unreadable directory {d_path}: {exc}")
                continue
            if stat.S_ISLNK(d_st.st_mode):
                if coverage_notes is not None:
                    coverage_notes.append(f"Skipped symlink directory: {d_path}")
                continue
            if stat.S_ISDIR(d_st.st_mode):
                if not os.access(d_path, os.R_OK | os.X_OK):
                    if coverage_notes is not None:
                        coverage_notes.append(f"Unreadable directory {d_path}")
                    continue
                kept_dirs.append(d)
        dirs[:] = kept_dirs
        for fname in sorted(files):
            if not fname.endswith(".py") or fname.startswith("test_") or fname.endswith("_test.py"):
                continue
            fpath = Path(root) / fname
            try:
                f_st = fpath.lstat()
            except OSError as exc:
                if coverage_notes is not None:
                    coverage_notes.append(f"Unreadable Python file {fpath}: {exc}")
                continue
            if stat.S_ISLNK(f_st.st_mode):
                if coverage_notes is not None:
                    coverage_notes.append(f"Skipped symlink Python file: {fpath}")
                continue
            if not stat.S_ISREG(f_st.st_mode):
                if coverage_notes is not None:
                    coverage_notes.append(f"Skipped non-regular Python file: {fpath}")
                continue
            safe_fp = safe_resolve_contained_path(fpath, repo_root)
            if safe_fp is None:
                if coverage_notes is not None:
                    coverage_notes.append(f"Rejected out-of-repo Python file: {fpath}")
                continue
            rel = safe_fp.relative_to(repo_res).as_posix()
            if "/tests/" in f"/{rel}" or "/wythe_examples/" in f"/{rel}":
                continue
            found.append((rel, safe_fp))
    return found


def _call_leaf_name(node: ast.AST) -> str:
    if isinstance(node, ast.Name):
        return node.id
    if isinstance(node, ast.Attribute):
        return node.attr
    return ""


def _walk_own_scope(fn: ast.AST):
    """Yield descendants of `fn` without crossing into nested function/class definitions."""
    queue: deque[ast.AST] = deque(ast.iter_child_nodes(fn))
    while queue:
        cur = queue.popleft()
        yield cur
        if not isinstance(cur, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef)):
            queue.extend(ast.iter_child_nodes(cur))


def _is_store_receiver(node: ast.AST) -> bool:
    leaf = ""
    if isinstance(node, ast.Name):
        leaf = node.id
    elif isinstance(node, ast.Attribute):
        leaf = node.attr
    low = leaf.lower()
    if not low:
        return False
    return (
        low in _STORE_EXACT_NAMES
        or low.endswith(_STORE_SUFFIXES)
        or low.startswith(_STORE_PREFIXES)
    )


def _is_path_or_os_replace(call: ast.Call) -> bool:
    if not isinstance(call.func, ast.Attribute) or call.func.attr != "replace":
        return False
    recv = call.func.value
    if isinstance(recv, ast.Name) and recv.id == "os":
        return True
    if len(call.args) != 1 or call.keywords:
        return False
    if _is_store_receiver(recv):
        return True
    if isinstance(recv, ast.Call) and _call_leaf_name(recv.func) == "Path":
        return True
    leaf = _call_leaf_name(recv).lower()
    return leaf in ("path", "file") or leaf.endswith(("_path", "_file"))


def _is_clock_expr(node: ast.AST, clock_vars: set[str]) -> bool:
    for sub in ast.walk(node):
        if isinstance(sub, ast.Name) and sub.id in clock_vars:
            return True
        if isinstance(sub, ast.Call):
            leaf = _call_leaf_name(sub.func)
            if leaf in _CLOCK_CALL_NAMES:
                return True
    return False


def _func_mutates_store(fn: ast.FunctionDef | ast.AsyncFunctionDef) -> bool:
    for sub in _walk_own_scope(fn):
        if isinstance(sub, ast.Call):
            leaf = _call_leaf_name(sub.func)
            if leaf in _FILE_WRITE_NAMES:
                return True
            if (
                leaf in _STORE_MUTATION_NAMES
                and isinstance(sub.func, ast.Attribute)
                and _is_store_receiver(sub.func.value)
            ):
                return True
            if _is_path_or_os_replace(sub):
                return True
        if isinstance(sub, ast.Constant) and isinstance(sub.value, str):
            up = sub.value.lstrip()[:16].upper()
            if up.startswith(("INSERT ", "UPDATE ", "DELETE ")):
                return True
    return False


def _func_reads_upstream_source(fn: ast.FunctionDef | ast.AsyncFunctionDef) -> bool:
    if _func_mutates_store(fn):
        return False
    for sub in _walk_own_scope(fn):
        if isinstance(sub, ast.Call):
            leaf = _call_leaf_name(sub.func)
            if leaf in _SOURCE_READ_NAMES or leaf.startswith(("_load_", "load_json", "read_json")):
                return True
        if (
            isinstance(sub, ast.Subscript)
            and isinstance(sub.slice, ast.Constant)
            and sub.slice.value in ("observed_at", "source_observed_at", "updated_at", "timestamp")
        ):
            return True
        if (
            isinstance(sub, ast.Call)
            and isinstance(sub.func, ast.Attribute)
            and sub.func.attr == "get"
            and sub.args
            and isinstance(sub.args[0], ast.Constant)
            and sub.args[0].value in ("observed_at", "source_observed_at", "updated_at", "timestamp")
        ):
            return True
    return False


def _extract_dict_shape(
    expr: ast.AST,
    local_dicts: dict[str, tuple[set[str], set[str], bool]],
    helper_shapes: dict[str, tuple[set[str], set[str], bool]],
    depth: int = 0,
    passthrough_params: frozenset[str] = frozenset(),
) -> tuple[set[str], set[str], bool] | None:
    """Return `(emit_paths, nested_roots, is_dynamic)` if `expr` evaluates to a dict, else `None`."""
    if depth > 4:
        return set(), set(), True
    if isinstance(expr, ast.Dict):
        paths: set[str] = set()
        nested: set[str] = set()
        dynamic = False
        for k_node, v_node in zip(expr.keys, expr.values):
            if k_node is None:
                if isinstance(v_node, ast.Name) and v_node.id in passthrough_params:
                    continue
                sub = _extract_dict_shape(v_node, local_dicts, helper_shapes, depth + 1, passthrough_params)
                if sub is None:
                    dynamic = True
                else:
                    paths |= sub[0]
                    nested |= sub[1]
                    dynamic = dynamic or sub[2]
            elif isinstance(k_node, ast.Constant) and isinstance(k_node.value, str):
                key = k_node.value
                paths.add(key)
                sub_v = _extract_dict_shape(v_node, local_dicts, helper_shapes, depth + 1, passthrough_params)
                if isinstance(v_node, ast.Dict) and sub_v is not None:
                    nested.add(key)
                    for sp in sub_v[0]:
                        paths.add(f"{key}.{sp}")
                    dynamic = dynamic or sub_v[2]
            else:
                dynamic = True
        return paths, nested, dynamic
    if isinstance(expr, ast.DictComp):
        return set(), set(), True
    if isinstance(expr, ast.Name) and expr.id in local_dicts:
        return local_dicts[expr.id]
    if isinstance(expr, ast.Call):
        leaf = _call_leaf_name(expr.func)
        if leaf == "dict":
            kw_paths = {kw.arg for kw in expr.keywords if kw.arg}
            dyn = bool(expr.args) or any(kw.arg is None for kw in expr.keywords)
            return kw_paths, set(), dyn
        if (leaf in ("JSONResponse", "jsonify", "dumps") or leaf.startswith(("_scrub", "scrub_"))) and expr.args:
            return _extract_dict_shape(expr.args[0], local_dicts, helper_shapes, depth + 1, passthrough_params)
        if leaf in helper_shapes:
            h_paths, h_nested, h_dyn = set(helper_shapes[leaf][0]), set(helper_shapes[leaf][1]), helper_shapes[leaf][2]
            for arg in expr.args:
                sub = _extract_dict_shape(arg, local_dicts, helper_shapes, depth + 1)
                if sub is not None:
                    h_paths |= sub[0]
                    h_nested |= sub[1]
                    h_dyn = h_dyn or sub[2]
            for kw in expr.keywords:
                if kw.arg and kw.value is not None:
                    sub = _extract_dict_shape(kw.value, local_dicts, helper_shapes, depth + 1)
                    if sub is not None:
                        h_paths |= sub[0]
                        h_nested |= sub[1]
                        h_dyn = h_dyn or sub[2]
            return h_paths, h_nested, h_dyn
    return None


def _resolve_manip_node_id(rel_file: str, manip: ManipulatorExtractionResult) -> str | None:
    for n in manip.nodes:
        if n.source_file == rel_file:
            return n.id
    return None


def _apply_local_dict_mutations(
    fn: ast.FunctionDef | ast.AsyncFunctionDef,
    local_dicts: dict[str, tuple[set[str], set[str], bool]],
    helper_shapes: dict[str, tuple[set[str], set[str], bool]],
    passthrough_params: frozenset[str] = frozenset(),
    local_dict_nodes: dict[str, ast.Dict] | None = None,
) -> bool:
    """Populate `local_dicts` with initial bindings and post-construction mutations; return `has_dynamic_mut`."""
    has_dynamic_mut = False

    def _merge_into(var_name: str, paths: set[str], nested: set[str], dyn: bool) -> None:
        prev = local_dicts.get(var_name)
        if prev is None:
            local_dicts[var_name] = (set(paths), set(nested), dyn)
        else:
            local_dicts[var_name] = (prev[0] | paths, prev[1] | nested, prev[2] or dyn)

    def _record_key_val(var_name: str, key: str, val_node: ast.AST | None) -> None:
        paths = {key}
        nested: set[str] = set()
        dyn = False
        if val_node is not None:
            sub_v = _extract_dict_shape(val_node, local_dicts, helper_shapes, 1, passthrough_params)
            if sub_v is not None and (isinstance(val_node, ast.Dict) or sub_v[0] or sub_v[2]):
                if isinstance(val_node, ast.Dict) or sub_v[0]:
                    nested.add(key)
                    for sp in sub_v[0]:
                        paths.add(f"{key}.{sp}")
                dyn = sub_v[2]
        _merge_into(var_name, paths, nested, dyn)

    for st in _walk_own_scope(fn):
        if isinstance(st, ast.Assign) and len(st.targets) == 1 and isinstance(st.targets[0], ast.Name):
            var_name = st.targets[0].id
            sh = _extract_dict_shape(st.value, local_dicts, helper_shapes, 0, passthrough_params)
            if sh is not None:
                _merge_into(var_name, sh[0], sh[1], sh[2])
            if local_dict_nodes is not None and isinstance(st.value, ast.Dict):
                local_dict_nodes[var_name] = st.value
        elif isinstance(st, ast.AnnAssign) and isinstance(st.target, ast.Name) and st.value is not None:
            var_name = st.target.id
            sh = _extract_dict_shape(st.value, local_dicts, helper_shapes, 0, passthrough_params)
            if sh is not None:
                _merge_into(var_name, sh[0], sh[1], sh[2])
            if local_dict_nodes is not None and isinstance(st.value, ast.Dict):
                local_dict_nodes[var_name] = st.value

    for st in _walk_own_scope(fn):
        sub_targets: list[tuple[ast.AST, ast.AST | None]] = []
        if isinstance(st, ast.Assign):
            for t in st.targets:
                sub_targets.append((t, st.value))
        elif isinstance(st, ast.AnnAssign) and st.value is not None:
            sub_targets.append((st.target, st.value))
        elif isinstance(st, ast.AugAssign):
            if isinstance(st.op, ast.BitOr) and isinstance(st.target, ast.Name) and st.target.id in local_dicts:
                sh = _extract_dict_shape(st.value, local_dicts, helper_shapes, 1, passthrough_params)
                if sh is not None:
                    _merge_into(st.target.id, sh[0], sh[1], sh[2])
                    if sh[2]:
                        has_dynamic_mut = True
                else:
                    _merge_into(st.target.id, set(), set(), True)
                    has_dynamic_mut = True
            else:
                sub_targets.append((st.target, st.value))

        for tgt, rhs_val in sub_targets:
            if not isinstance(tgt, ast.Subscript):
                continue
            if isinstance(tgt.value, ast.Name) and tgt.value.id in local_dicts:
                if isinstance(tgt.slice, ast.Constant) and isinstance(tgt.slice.value, str):
                    _record_key_val(tgt.value.id, tgt.slice.value, rhs_val)
                else:
                    _merge_into(tgt.value.id, set(), set(), True)
                    has_dynamic_mut = True
            elif (
                isinstance(tgt.value, ast.Subscript)
                and isinstance(tgt.value.value, ast.Name)
                and tgt.value.value.id in local_dicts
            ):
                base_var = tgt.value.value.id
                if (
                    isinstance(tgt.value.slice, ast.Constant)
                    and isinstance(tgt.value.slice.value, str)
                    and isinstance(tgt.slice, ast.Constant)
                    and isinstance(tgt.slice.value, str)
                ):
                    k1, k2 = tgt.value.slice.value, tgt.slice.value
                    _merge_into(base_var, {k1, f"{k1}.{k2}"}, {k1}, False)
                else:
                    _merge_into(base_var, set(), set(), True)
                    has_dynamic_mut = True
            elif not isinstance(tgt.slice, ast.Constant):
                has_dynamic_mut = True

        if (
            isinstance(st, ast.Call)
            and isinstance(st.func, ast.Attribute)
            and isinstance(st.func.value, ast.Name)
            and st.func.value.id in local_dicts
        ):
            dvar = st.func.value.id
            meth = st.func.attr
            if meth == "setdefault":
                if st.args and isinstance(st.args[0], ast.Constant) and isinstance(st.args[0].value, str):
                    def_val = st.args[1] if len(st.args) >= 2 else None
                    _record_key_val(dvar, st.args[0].value, def_val)
                else:
                    _merge_into(dvar, set(), set(), True)
                    has_dynamic_mut = True
            elif meth == "update":
                if len(st.args) > 1:
                    _merge_into(dvar, set(), set(), True)
                    has_dynamic_mut = True
                elif len(st.args) == 1:
                    sh = _extract_dict_shape(st.args[0], local_dicts, helper_shapes, 1, passthrough_params)
                    if sh is not None:
                        _merge_into(dvar, sh[0], sh[1], sh[2])
                        if sh[2]:
                            has_dynamic_mut = True
                    else:
                        _merge_into(dvar, set(), set(), True)
                        has_dynamic_mut = True
                for kw in st.keywords:
                    if kw.arg is None:
                        sh_kw = _extract_dict_shape(kw.value, local_dicts, helper_shapes, 1, passthrough_params)
                        if sh_kw is not None:
                            _merge_into(dvar, sh_kw[0], sh_kw[1], sh_kw[2])
                            if sh_kw[2]:
                                has_dynamic_mut = True
                        else:
                            _merge_into(dvar, set(), set(), True)
                            has_dynamic_mut = True
                    else:
                        _record_key_val(dvar, kw.arg, kw.value)

    return has_dynamic_mut


def _collect_module_slice_map(tree: ast.Module) -> dict[str, set[str]]:
    """Map function names to `slice:<slug>` / `GET /api/v1/slices/<slug>` from slice registries or slice_id branches."""
    fn_to_routes: dict[str, set[str]] = {}
    for node in ast.walk(tree):
        target_name = ""
        val: ast.AST | None = None
        if isinstance(node, ast.Assign) and len(node.targets) == 1 and isinstance(node.targets[0], ast.Name):
            target_name = node.targets[0].id
            val = node.value
        elif isinstance(node, ast.AnnAssign) and isinstance(node.target, ast.Name):
            target_name = node.target.id
            val = node.value
        if isinstance(val, ast.Dict) and any(tok in target_name.upper() for tok in ("SLICE", "ROUTE", "BUILDER")):
            for k_node, v_node in zip(val.keys, val.values):
                if (
                    isinstance(k_node, ast.Constant)
                    and isinstance(k_node.value, str)
                    and isinstance(v_node, ast.Name)
                ):
                    slug = k_node.value.strip("/")
                    if slug and slug.replace("-", "_").replace("/", "_").isalnum():
                        fn_to_routes.setdefault(v_node.id, set()).update(
                            {f"slice:{slug}", f"GET /api/v1/slices/{slug}"}
                        )
        elif isinstance(node, ast.If):
            slug_candidate: str | None = None
            if (
                isinstance(node.test, ast.Compare)
                and len(node.test.ops) == 1
                and isinstance(node.test.ops[0], ast.Eq)
                and len(node.test.comparators) == 1
                and isinstance(node.test.comparators[0], ast.Constant)
                and isinstance(node.test.comparators[0].value, str)
            ):
                raw_cmp = node.test.comparators[0].value
                if raw_cmp.startswith("/api/"):
                    fn_key = f"GET {raw_cmp.rstrip('/') or '/'}"
                    for sub in ast.walk(node):
                        if isinstance(sub, ast.Call) and isinstance(sub.func, ast.Name):
                            fn_to_routes.setdefault(sub.func.id, set()).add(fn_key)
                elif (
                    isinstance(node.test.left, ast.Name)
                    and node.test.left.id in ("slice_id", "slice_name", "slice_key")
                    and raw_cmp.replace("-", "_").isalnum()
                ):
                    slug_candidate = raw_cmp
            if slug_candidate:
                for sub in ast.walk(node):
                    if isinstance(sub, ast.Call) and isinstance(sub.func, ast.Name):
                        fn_to_routes.setdefault(sub.func.id, set()).update(
                            {f"slice:{slug_candidate}", f"GET /api/v1/slices/{slug_candidate}"}
                        )
    return fn_to_routes


def _collect_scope_functions(
    tree: ast.Module,
) -> list[tuple[ast.FunctionDef | ast.AsyncFunctionDef, dict[str, str]]]:
    """Iteratively collect module, class, and nested functions with inherited APIRouter prefixes."""
    collected: list[tuple[ast.FunctionDef | ast.AsyncFunctionDef, dict[str, str]]] = []
    stack: list[tuple[list[ast.stmt], dict[str, str]]] = [(list(tree.body), {})]
    while stack:
        stmts, inherited_prefixes = stack.pop()
        scope_prefixes = dict(inherited_prefixes)
        for stmt in stmts:
            if (
                isinstance(stmt, ast.Assign)
                and isinstance(stmt.value, ast.Call)
                and _call_leaf_name(stmt.value.func) == "APIRouter"
            ):
                for kw in stmt.value.keywords:
                    if (
                        kw.arg == "prefix"
                        and isinstance(kw.value, ast.Constant)
                        and isinstance(kw.value.value, str)
                    ):
                        for tgt in stmt.targets:
                            if isinstance(tgt, ast.Name):
                                scope_prefixes[tgt.id] = kw.value.value

        nested_blocks: list[tuple[list[ast.stmt], dict[str, str]]] = []
        for stmt in stmts:
            if isinstance(stmt, (ast.FunctionDef, ast.AsyncFunctionDef)):
                collected.append((stmt, scope_prefixes))
                nested_blocks.append((list(stmt.body), scope_prefixes))
            elif isinstance(stmt, ast.ClassDef):
                nested_blocks.append((list(stmt.body), scope_prefixes))
            elif isinstance(stmt, (ast.If, ast.For, ast.AsyncFor, ast.While, ast.With, ast.AsyncWith)):
                if stmt.body:
                    nested_blocks.append((list(stmt.body), scope_prefixes))
                if getattr(stmt, "orelse", None):
                    nested_blocks.append((list(stmt.orelse), scope_prefixes))
            elif isinstance(stmt, ast.Try):
                if stmt.body:
                    nested_blocks.append((list(stmt.body), scope_prefixes))
                for handler in stmt.handlers:
                    if handler.body:
                        nested_blocks.append((list(handler.body), scope_prefixes))
                if stmt.orelse:
                    nested_blocks.append((list(stmt.orelse), scope_prefixes))
                if stmt.finalbody:
                    nested_blocks.append((list(stmt.finalbody), scope_prefixes))
        stack.extend(reversed(nested_blocks))
    return collected


def _decorator_route_keys(
    fn: ast.FunctionDef | ast.AsyncFunctionDef, router_prefixes: dict[str, str]
) -> set[str]:
    keys: set[str] = set()
    for dec in fn.decorator_list:
        if not isinstance(dec, ast.Call) or not isinstance(dec.func, ast.Attribute):
            continue
        verb = dec.func.attr.upper()
        if verb not in ("GET", "POST", "PUT", "PATCH", "DELETE"):
            continue
        if not dec.args or not isinstance(dec.args[0], ast.Constant) or not isinstance(dec.args[0].value, str):
            continue
        sub_path = dec.args[0].value
        prefix = ""
        if isinstance(dec.func.value, ast.Name):
            prefix = router_prefixes.get(dec.func.value.id, "")
        full = f"{prefix.rstrip('/')}/{sub_path.lstrip('/')}".rstrip("/") or "/"
        keys.add(f"{verb} {full}")
        if verb == "GET" and "/slices/" in full and "{" not in full.split("/slices/", 1)[1]:
            slug = full.split("/slices/", 1)[1].strip("/")
            if slug:
                keys.add(f"slice:{slug}")
    return keys


def analyze_python_freshness_and_producers(
    repo_root: Path,
    backend_subdir: str,
    manip: ManipulatorExtractionResult,
    *,
    coverage_notes: list[str] | None = None,
) -> tuple[list[RawCandidateFinding], dict[str, ProducerPayloadContract]]:
    """Emit `MANIP-007` freshness-laundering findings and collect static dict contracts (#120/#121)."""
    findings: list[RawCandidateFinding] = []
    contracts_by_route: dict[str, ProducerPayloadContract] = {}

    route_line_map: dict[tuple[str, int], set[str]] = {}
    for r in manip.routes:
        rk = f"{r.http_method.upper()} {r.full_path.rstrip('/') or '/'}"
        route_line_map.setdefault((r.source_file, r.line), set()).add(rk)

    for rel, fpath in _iter_python_files(repo_root, backend_subdir, coverage_notes=coverage_notes):
        try:
            source = safe_read_repo_text(
                fpath, repo_root, max_bytes=MAX_FRONTEND_FILE_BYTES, encoding="utf-8"
            )
            tree = ast.parse(source, filename=rel)
        except (OSError, UnicodeDecodeError, ValueError, SyntaxError) as exc:
            if coverage_notes is not None:
                coverage_notes.append(f"Unreadable or unparseable Python file {rel}: {exc}")
            continue

        node_id = _resolve_manip_node_id(rel, manip)
        slice_fn_map = _collect_module_slice_map(tree)
        scoped_funcs = _collect_scope_functions(tree)

        # Pass 1: helper dict shapes & envelope helper detection
        helper_shapes: dict[str, tuple[set[str], set[str], bool]] = {}
        envelope_helpers: set[str] = set()
        for fn, _ in scoped_funcs:
            fn_params = frozenset(a.arg for a in (*fn.args.args, *fn.args.kwonlyargs))
            local_dicts: dict[str, tuple[set[str], set[str], bool]] = {}
            ret_shapes: list[tuple[set[str], set[str], bool]] = []
            has_unknown_ret = False
            helper_dyn_mut = _apply_local_dict_mutations(fn, local_dicts, {}, fn_params)
            for st in _walk_own_scope(fn):
                if isinstance(st, ast.Return) and st.value is not None:
                    sh = _extract_dict_shape(st.value, local_dicts, {}, 0, fn_params)
                    if sh is None:
                        has_unknown_ret = True
                    else:
                        ret_shapes.append(sh)
            if ret_shapes:
                merged_p = set().union(*(s[0] for s in ret_shapes))
                merged_n = set().union(*(s[1] for s in ret_shapes))
                merged_d = helper_dyn_mut or has_unknown_ret or any(s[2] for s in ret_shapes)
                helper_shapes[fn.name] = (merged_p, merged_n, merged_d)
                if merged_p & _ENVELOPE_MARKER_KEYS:
                    envelope_helpers.add(fn.name)

        # Pass 2: MANIP-007 freshness checks & route/slice producer contracts
        for fn, router_prefixes in scoped_funcs:
            reads_source = _func_reads_upstream_source(fn)
            clock_vars: set[str] = {
                arg.arg
                for arg in (*fn.args.args, *fn.args.kwonlyargs)
                if arg.arg in ("generated_at", "request_time", "request_now", "now_iso")
            }
            local_dicts = {}
            local_dict_nodes: dict[str, ast.Dict] = {}
            emitted_lines: set[tuple[int, str]] = set()

            for st in _walk_own_scope(fn):
                if (
                    isinstance(st, ast.Assign)
                    and len(st.targets) == 1
                    and isinstance(st.targets[0], ast.Name)
                    and _is_clock_expr(st.value, clock_vars)
                ):
                    clock_vars.add(st.targets[0].id)
                elif (
                    isinstance(st, ast.AnnAssign)
                    and isinstance(st.target, ast.Name)
                    and st.value is not None
                    and _is_clock_expr(st.value, clock_vars)
                ):
                    clock_vars.add(st.target.id)
            has_dynamic_mut = _apply_local_dict_mutations(
                fn, local_dicts, helper_shapes, frozenset(), local_dict_nodes
            )

            for st in _walk_own_scope(fn):
                if isinstance(st, ast.Dict):
                    str_keys = {
                        k.value: (k, v)
                        for k, v in zip(st.keys, st.values)
                        if isinstance(k, ast.Constant) and isinstance(k.value, str)
                    }
                    is_env = bool(set(str_keys) & _ENVELOPE_MARKER_KEYS) or "envelope" in fn.name
                    if is_env and "stale" in str_keys:
                        _, stale_val = str_keys["stale"]
                        if isinstance(stale_val, ast.Constant) and stale_val.value is False:
                            key = (stale_val.lineno, "stale_false")
                            if key not in emitted_lines:
                                emitted_lines.add(key)
                                findings.append(
                                    RawCandidateFinding(
                                        rule_code="MANIP-007",
                                        node_id=node_id,
                                        source_file=rel,
                                        line=stale_val.lineno,
                                        title=f"`{fn.name}` hard-codes `stale=False` in observation envelope",
                                        detail=f"{rel}:{stale_val.lineno} sets `'stale': False` unconditionally instead of deriving staleness from `valid_until` or source age.",
                                        remediation="Compute `stale` by comparing the upstream source timestamp/`valid_until` against the reference clock, or omit `stale=False` when unverified.",
                                    )
                                )
                    if reads_source:
                        for obs_k in _OBS_TIME_KEYS & set(str_keys):
                            _, obs_val = str_keys[obs_k]
                            if _is_clock_expr(obs_val, clock_vars):
                                key = (obs_val.lineno, "clock_launder")
                                if key not in emitted_lines:
                                    emitted_lines.add(key)
                                    findings.append(
                                        RawCandidateFinding(
                                            rule_code="MANIP-007",
                                            node_id=node_id,
                                            source_file=rel,
                                            line=obs_val.lineno,
                                            title=f"`{fn.name}` stamps request clock onto `{obs_k}` while reading an upstream source",
                                            detail=f"{rel}:{obs_val.lineno} assigns `{obs_k}` from the request/host clock instead of propagating the upstream source's observation timestamp.",
                                            remediation="Propagate the upstream record/file `observed_at` (or mark observation time unmeasured when absent) rather than stamping `now()`.",
                                        )
                                    )
                    # Check `{**payload, **envelope}` overwriting producer `valid_until`
                    if len(st.keys) >= 2 and st.keys[0] is None and st.keys[-1] is None:
                        last_spread = st.values[-1]
                        if isinstance(last_spread, ast.Name) and last_spread.id in local_dict_nodes:
                            env_dict = local_dict_nodes[last_spread.id]
                            env_keys = {
                                k.value
                                for k in env_dict.keys
                                if isinstance(k, ast.Constant) and isinstance(k.value, str)
                            }
                            if "valid_until" in env_keys and (env_keys & _ENVELOPE_MARKER_KEYS):
                                key = (st.lineno, "overwrite_valid_until")
                                if key not in emitted_lines:
                                    emitted_lines.add(key)
                                    findings.append(
                                        RawCandidateFinding(
                                            rule_code="MANIP-007",
                                            node_id=node_id,
                                            source_file=rel,
                                            line=st.lineno,
                                            title=f"`{fn.name}` overwrites producer `valid_until` in `{last_spread.id}` merge",
                                            detail=f"{rel}:{st.lineno} spreads `**{last_spread.id}` after payload with an unconditional `valid_until` key, clobbering producer-supplied expiry.",
                                            remediation="Preserve `payload.get('valid_until')` when building the outer observation envelope.",
                                        )
                                    )

                elif isinstance(st, ast.Call):
                    callee = _call_leaf_name(st.func)
                    kw_map = {kw.arg: kw.value for kw in st.keywords if kw.arg}
                    is_env_call = bool(callee and not callee[:1].isupper()) and (
                        callee in envelope_helpers or "envelope" in callee.lower()
                    )
                    if is_env_call and "stale" in kw_map:
                        sv = kw_map["stale"]
                        if isinstance(sv, ast.Constant) and sv.value is False:
                            key = (sv.lineno, "kw_stale_false")
                            if key not in emitted_lines:
                                emitted_lines.add(key)
                                findings.append(
                                    RawCandidateFinding(
                                        rule_code="MANIP-007",
                                        node_id=node_id,
                                        source_file=rel,
                                        line=sv.lineno,
                                        title=f"`{fn.name}` passes `stale=False` to `{callee}`",
                                        detail=f"{rel}:{sv.lineno} hard-codes `stale=False` in `{callee}(...)`.",
                                        remediation="Derive `stale` from `valid_until` / upstream timestamp age rather than passing a constant `False`.",
                                    )
                                )
                    if is_env_call and reads_source:
                        for obs_k in _OBS_TIME_KEYS & set(kw_map):
                            ov = kw_map[obs_k]
                            if _is_clock_expr(ov, clock_vars):
                                key = (ov.lineno, "kw_clock_launder")
                                if key not in emitted_lines:
                                    emitted_lines.add(key)
                                    findings.append(
                                        RawCandidateFinding(
                                            rule_code="MANIP-007",
                                            node_id=node_id,
                                            source_file=rel,
                                            line=ov.lineno,
                                            title=f"`{fn.name}` passes request-clock `{obs_k}` to `{callee}`",
                                            detail=f"{rel}:{ov.lineno} stamps request-time `{obs_k}` in `{callee}(...)` while reading upstream state.",
                                            remediation="Pass the upstream source's `observed_at` timestamp (or an explicit unmeasured sentinel) to the envelope builder.",
                                        )
                                    )

            # Register static dict contract if this function serves a route or slice
            r_keys = (
                _decorator_route_keys(fn, router_prefixes)
                | set(slice_fn_map.get(fn.name, set()))
                | set(route_line_map.get((rel, fn.lineno), set()))
            )
            if not r_keys:
                continue
            ret_shapes = []
            has_unknown_ret = False
            for st in _walk_own_scope(fn):
                if isinstance(st, ast.Return) and st.value is not None:
                    sh = _extract_dict_shape(st.value, local_dicts, helper_shapes, 0)
                    if sh is None:
                        has_unknown_ret = True
                    else:
                        ret_shapes.append(sh)
            if not ret_shapes:
                continue
            emit_paths = set().union(*(s[0] for s in ret_shapes))
            nested_roots = set().union(*(s[1] for s in ret_shapes))
            is_dyn = has_dynamic_mut or has_unknown_ret or any(s[2] for s in ret_shapes)
            top_keys = {p.split(".", 1)[0] for p in emit_paths} - _ENVELOPE_META_KEYS
            contract = ProducerPayloadContract(
                route_keys=r_keys,
                source_file=rel,
                line=fn.lineno,
                node_id=node_id,
                func_name=fn.name,
                emit_paths=emit_paths,
                nested_dict_roots=nested_roots,
                top_domain_keys=top_keys,
                has_evidence_state="evidence_state" in emit_paths,
                coverage="partial" if is_dyn else "complete",
            )
            for rk in r_keys:
                contracts_by_route[rk] = contract

    return findings, contracts_by_route
