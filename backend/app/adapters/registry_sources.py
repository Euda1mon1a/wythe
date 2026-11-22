"""Declarative JSON/YAML registries (`config/`, `configs/`), Tier-1 policy Truth, and key consumption."""

from __future__ import annotations

import ast
import json
import os
from pathlib import Path, PurePosixPath
from typing import Self

import yaml

from app.adapters.base import ManipulatorExtractionResult, TruthExtractionResult
from app.adapters.deployment_sources import normalize_home
from app.adapters.dockerfile_sources import (
    _has_safe_path_segments,
    _is_within_root,
    _load_bounded_yaml,
    _read_bounded_regular_text,
    _safe_contained_dir,
    _safe_contained_file,
    _safe_is_dir,
    _safe_is_symlink,
    _safe_resolve,
)
from app.adapters.inline_store_truth import _collect_str_bindings, _eval_str_expr
from app.adapters.launchd_sources import shell_references
from app.adapters.python_policy_consumption import (
    _const_bool,
    classify_table_policy_columns,
    is_policy_constant_symbol,
    merge_policy_consumptions,
)
from app.adapters.service_sources import EXCLUDED_PARTS, script_id, source_reference
from app.schemas.atlas import (
    AtlasEdge,
    AtlasNode,
    PolicyConsumptionMechanism,
    PolicyConsumptionState,
    PolicyFieldConsumption,
)

_COMMAND_KEYS = frozenset({"command", "argv", "script", "script_path", "entrypoint", "wrapper"})
_REGISTRY_SECTION_KEYS = frozenset(
    {
        "commands",
        "wrapper",
        "capabilities",
        "surfaces",
        "jobs",
        "schedules",
        "providers",
        "seats",
        "lanes",
        "models",
        "routes",
        "policies",
        "rules",
        "tokens",
    }
)
_REGISTRY_POLICY_FIELD_HINTS = frozenset(
    {
        "enabled",
        "disabled",
        "schedule",
        "schedules",
        "cron",
        "interval",
        "interval_seconds",
        "cadence",
        "cadence_seconds",
        "timeout",
        "timeout_seconds",
        "retry_limit",
        "max_retries",
        "rate_limit",
        "concurrency",
        "max_concurrency",
        "quota",
        "capacity",
        "threshold",
        "allow",
        "allowlist",
        "denylist",
        "mode",
        "scopes",
        "permissions",
        "grants",
        "capabilities",
        "surfaces",
        "commands",
        "jobs",
        "wrapper",
        "providers",
        "seats",
        "lanes",
        "models",
        "routes",
        "policies",
        "rules",
        "tokens",
        "default_model",
        "seat",
        "lane",
        "provider",
        "fallback",
        "priority",
        "weight",
    }
)
_REGISTRY_FILE_SUFFIXES = (".json", ".yaml", ".yml")
_JSON_SCHEMA_META_ONLY_KEYS = frozenset(
    {
        "$schema",
        "$id",
        "id",
        "title",
        "description",
        "version",
        "$defs",
        "definitions",
        "type",
        "properties",
        "required",
        "additionalProperties",
        "examples",
        "default",
    }
)


def _registry_format_label(rel: str) -> str:
    return "YAML" if PurePosixPath(rel.lower()).suffix in {".yaml", ".yml"} else "JSON"


def _is_excluded_registry_candidate(rel: str, data: object) -> bool:
    rel_lc = rel.lower()
    padded = f"/{rel_lc}/"
    bname = PurePosixPath(rel_lc).name
    if bname in {
        "pnpm-lock.yaml",
        "pnpm-lock.yml",
        "package-lock.json",
        "npm-shrinkwrap.json",
        "composer.lock",
        "pipfile.lock",
        "cargo.lock",
        "yarn.lock",
        "deno.lock",
        "lockfile.json",
        "lockfile.yaml",
        "lockfile.yml",
    } or bname.endswith(
        ("-lock.json", "-lock.yaml", "-lock.yml", ".lock.json", ".lock.yaml", ".lock.yml")
    ):
        return True
    if bname.startswith(("docker-compose", "compose.", "compose-")) or bname in {
        "compose.yml",
        "compose.yaml",
        "docker-compose.yml",
        "docker-compose.yaml",
    }:
        return True
    if bname.endswith((".schema.json", ".schema.yaml", ".schema.yml")) or bname in {
        "schema.json",
        "schema.yaml",
        "schema.yml",
    }:
        return True
    if any(
        seg in padded
        for seg in (
            "/workflows/",
            "/.github/",
            "/.circleci/",
            "/fixtures/",
            "/testdata/",
            "/__tests__/",
        )
    ):
        return True
    if (
        "/.gitlab-ci" in f"/{rel_lc}"
        or bname.startswith((".gitlab-ci", "gitlab-ci.", ".circleci"))
        or ".gitlab-ci." in bname
        or ".fixture." in bname
    ):
        return True
    if not isinstance(data, dict):
        return False
    if "lockfileVersion" in data and (
        "packages" in data or "dependencies" in data or "importers" in data
    ):
        return True
    svcs = data.get("services")
    if isinstance(svcs, dict) and svcs and all(
        isinstance(v, dict) and bool(set(v) & {"image", "build", "ports", "volumes", "container_name"})
        for v in svcs.values()
    ):
        return True
    jobs = data.get("jobs")
    if isinstance(jobs, dict) and jobs and any(
        isinstance(v, dict) and ("runs-on" in v or "steps" in v or "uses" in v)
        for v in jobs.values()
    ):
        return True
    top_keys = set(data.keys())
    if "$schema" in data:
        if top_keys <= _JSON_SCHEMA_META_ONLY_KEYS:
            return True
        if not (top_keys & (_REGISTRY_SECTION_KEYS | _COMMAND_KEYS)) and (
            (data.get("type") == "object" and isinstance(data.get("properties"), dict))
            or bool(top_keys & {"properties", "$defs", "definitions", "allOf", "oneOf", "anyOf"})
        ):
            return True
    return bool(
        data.get("type") == "object"
        and isinstance(data.get("properties"), dict)
        and (top_keys & {"$id", "$defs", "definitions", "additionalProperties", "required"})
        and not (top_keys & (_REGISTRY_SECTION_KEYS | _COMMAND_KEYS))
    )


def _commands(value: object):
    stack: list[tuple[object, int]] = [(value, 0)]
    visited: set[int] = set()
    visits = 0
    max_visits = 4096
    while stack:
        cur, depth = stack.pop()
        if depth > 32:
            continue
        if isinstance(cur, dict):
            oid = id(cur)
            if oid in visited:
                continue
            visited.add(oid)
            visits += 1
            if visits > max_visits:
                break
            children: list[object] = []
            for key, child in cur.items():
                if key in _COMMAND_KEYS:
                    if isinstance(child, str):
                        yield child
                    elif isinstance(child, list):
                        for item in child:
                            if isinstance(item, str):
                                yield item
                children.append(child)
            for child in reversed(children):
                stack.append((child, depth + 1))
        elif isinstance(cur, list):
            oid = id(cur)
            if oid in visited:
                continue
            visited.add(oid)
            visits += 1
            if visits > max_visits:
                break
            for child in reversed(cur):
                stack.append((child, depth + 1))


def _has_registry_keys(value: object, depth: int = 0) -> bool:
    stack: list[tuple[object, int]] = [(value, depth)]
    best_depth: dict[int, int] = {}
    visits = 0
    max_visits = 4096
    while stack:
        cur, cur_depth = stack.pop()
        if cur_depth > 4:
            continue
        if isinstance(cur, dict):
            oid = id(cur)
            if oid in best_depth and cur_depth >= best_depth[oid]:
                continue
            best_depth[oid] = cur_depth
            visits += 1
            if visits > max_visits:
                break
            if set(cur.keys()) & (_REGISTRY_SECTION_KEYS | _COMMAND_KEYS):
                return True
            for v in reversed(list(cur.values())):
                stack.append((v, cur_depth + 1))
        elif isinstance(cur, list):
            oid = id(cur)
            if oid in best_depth and cur_depth >= best_depth[oid]:
                continue
            best_depth[oid] = cur_depth
            visits += 1
            if visits > max_visits:
                break
            for item in reversed(cur[:20]):
                stack.append((item, cur_depth + 1))
    return False


def _extract_registry_columns(data: object) -> tuple[list[str], list[str]]:
    cols: list[str] = []
    best_depth: dict[int, int] = {}
    visits = 0
    max_visits = 4096

    def _walk_keys(obj: object, depth: int = 0) -> None:
        nonlocal visits
        if depth > 4 or len(cols) >= 40 or visits >= max_visits:
            return
        if isinstance(obj, (dict, list)):
            oid = id(obj)
            if oid in best_depth and depth >= best_depth[oid]:
                return
            best_depth[oid] = depth
            visits += 1
        if isinstance(obj, dict):
            for k, v in obj.items():
                ks = str(k)
                if ks not in cols and len(cols) < 40:
                    cols.append(ks)
                if depth == 0 and ks in _REGISTRY_SECTION_KEYS and isinstance(v, dict):
                    # Map of named entries (`{"surf_demo": {"enabled": true, ...}}`): inspect entry fields
                    for sub_v in list(v.values())[:25]:
                        if isinstance(sub_v, dict):
                            _walk_keys(sub_v, depth + 2)
                else:
                    _walk_keys(v, depth + 1)
        elif isinstance(obj, list):
            for item in obj[:25]:
                _walk_keys(item, depth + 1)

    _walk_keys(data)
    classified = classify_table_policy_columns("policy_registry", cols)
    hinted = [c for c in cols if c.lower() in _REGISTRY_POLICY_FIELD_HINTS]
    pol_cols = list(dict.fromkeys([*classified, *hinted]))
    if not pol_cols and cols:
        pol_cols = cols[:6]
    return cols, pol_cols


def _discover_registry_files(repo_root: Path) -> tuple[list[tuple[str, object, list[str]]], int]:
    if not _has_safe_path_segments(repo_root) or _safe_is_symlink(repo_root):
        return [], 1
    real_root = _safe_resolve(repo_root)
    if real_root is None:
        return [], 1
    found: list[tuple[str, object, list[str]]] = []
    unreadable = 0
    for dirname in ("config", "configs"):
        cfg_dir = repo_root / dirname
        if _safe_is_symlink(cfg_dir):
            unreadable += 1
            continue
        if not _safe_is_dir(cfg_dir):
            continue
        if not _is_within_root(cfg_dir, real_root):
            unreadable += 1
            continue
        candidate_files: list[Path] = []
        walk_errors: list[OSError] = []
        for parent, dirs, names in os.walk(cfg_dir, followlinks=False, onerror=walk_errors.append):
            parent_path = Path(parent)
            keep: list[str] = []
            for name in sorted(dirs):
                if name in EXCLUDED_PARTS or name.startswith("."):
                    continue
                dpath = parent_path / name
                if _safe_contained_dir(dpath, real_root) is None:
                    unreadable += 1
                    continue
                keep.append(name)
            dirs[:] = keep
            for name in sorted(names):
                path = parent_path / name
                if path.suffix.lower() not in _REGISTRY_FILE_SUFFIXES:
                    continue
                if _safe_contained_file(path, real_root) is None:
                    unreadable += 1
                    continue
                candidate_files.append(path)
        unreadable += len(walk_errors)
        for path in sorted(candidate_files):
            rel = path.relative_to(repo_root).as_posix()
            try:
                raw_text = _read_bounded_regular_text(
                    path, max_bytes=1_048_576, real_root=real_root
                )
                if path.suffix.lower() in {".yaml", ".yml"}:
                    data = _load_bounded_yaml(raw_text, max_nodes=4096, max_depth=64)
                else:
                    data = json.loads(raw_text)
            except (OSError, ValueError, UnicodeError, RecursionError, yaml.YAMLError):
                unreadable += 1
                continue
            if data is None or _is_excluded_registry_candidate(rel, data):
                continue
            cmds = list(_commands(data))
            if not cmds and not _has_registry_keys(data):
                continue
            found.append((rel, data, cmds))
    return found, unreadable


def _build_registry_truth_node(rel: str, data: object) -> AtlasNode:
    cols, pol_cols = _extract_registry_columns(data)
    fmt = _registry_format_label(rel)
    return AtlasNode(
        id=f"t:registry:{rel}",
        tier="truth",
        subkind="table",
        label=f"registry:{rel}",
        source_file=rel,
        line=1,
        status="clean",
        role="policy",
        cluster="registries",
        summary=(
            f"Declarative {fmt} policy/command registry `{rel}`; "
            "admission, enabled flags, and schedule state are static declarations."
        ),
        columns=cols,
        policy_columns=pol_cols,
    )


class RegistryTruthExtractionResult(tuple[list[AtlasNode], dict[str, str]]):
    """2-tuple `(nodes, table_symbol_map)` carrying `coverage_complete`, `unreadable_count`, and `notes`."""

    coverage_complete: bool
    unreadable_count: int
    notes: list[str]

    def __new__(
        cls,
        nodes: list[AtlasNode],
        table_symbol_map: dict[str, str],
        *,
        coverage_complete: bool = True,
        unreadable_count: int = 0,
        notes: list[str] | None = None,
    ) -> Self:
        inst = super().__new__(cls, (nodes, table_symbol_map))
        inst.coverage_complete = coverage_complete
        inst.unreadable_count = unreadable_count
        inst.notes = list(notes) if notes is not None else []
        return inst

    @property
    def nodes(self) -> list[AtlasNode]:
        return self[0]

    @property
    def table_symbol_map(self) -> dict[str, str]:
        return self[1]


def extract_registry_truth_nodes(
    repo_root: Path,
    *,
    notes_out: list[str] | None = None,
    coverage_out: list[bool] | None = None,
) -> RegistryTruthExtractionResult:
    """Return Tier-1 `t:registry:<rel>` policy Truth nodes and `table_symbol_map` entries."""
    entries, unreadable = _discover_registry_files(repo_root)
    nodes: list[AtlasNode] = []
    sym_map: dict[str, str] = {}
    for rel, data, _ in entries:
        tnode = _build_registry_truth_node(rel, data)
        nodes.append(tnode)
        sym_map[f"registry:{rel}"] = tnode.id
        sym_map[rel] = tnode.id
    notes: list[str] = []
    coverage_complete = unreadable == 0
    if not coverage_complete:
        note = (
            f"Skipped {unreadable} unreadable or unsafe registry file(s) in `config/`/`configs/`; "
            "registry truth coverage is incomplete."
        )
        notes.append(note)
        if notes_out is not None and note not in notes_out:
            notes_out.append(note)
        if coverage_out is not None:
            coverage_out.append(False)
    return RegistryTruthExtractionResult(
        nodes,
        sym_map,
        coverage_complete=coverage_complete,
        unreadable_count=unreadable,
        notes=notes,
    )


def _match_registry_rel(
    raw: str | None, reg_rels: set[str], unique_basenames: dict[str, str]
) -> str | None:
    if not raw or not raw.lower().endswith(_REGISTRY_FILE_SUFFIXES):
        return None
    norm = raw.strip().replace("\\", "/").removeprefix("./")
    if norm in reg_rels:
        return norm
    for r_rel in reg_rels:
        if norm.endswith("/" + r_rel):
            return r_rel
    leaf = norm.rsplit("/", 1)[-1]
    if "__dyn__" in leaf:
        return None
    if leaf in unique_basenames and (
        "config/" in norm or "configs/" in norm or "/" not in norm or norm.startswith("__dyn__/")
    ):
        return unique_basenames[leaf]
    return None


def _analyze_scope_registry_consumption(
    stmts: list[ast.stmt],
    scope_name: str,
    tnode: AtlasNode,
    mod_policy_consts: set[str],
) -> PolicyFieldConsumption:
    pol_cols = list(tnode.policy_columns)
    pol_set = set(pol_cols)
    known_cols = set(tnode.columns) | pol_set
    accessed: set[str] = set()
    fallbacks: set[str] = set()
    ret_consts: set[str] = set()
    loaded_vars: set[str] = set()
    has_dynamic = False
    returns_loaded = False

    def _expr_is_registry_load(expr: ast.AST | None) -> bool:
        if expr is None:
            return False
        if isinstance(expr, ast.Name):
            return expr.id in loaded_vars
        for sub_e in ast.walk(expr):
            if isinstance(sub_e, ast.Call):
                fn_e = (
                    sub_e.func.attr
                    if isinstance(sub_e.func, ast.Attribute)
                    else (sub_e.func.id if isinstance(sub_e.func, ast.Name) else "")
                )
                if fn_e in {"load", "loads", "safe_load", "safe_load_all", "full_load", "read_text"}:
                    return True
            elif isinstance(sub_e, ast.Name) and sub_e.id in loaded_vars:
                return True
        return False

    _try_types = (ast.Try, *((ast.TryStar,) if hasattr(ast, "TryStar") else ()))

    def _inspect_expr(root_expr: ast.AST | None, *, dead: bool) -> None:
        nonlocal has_dynamic
        if dead or root_expr is None:
            return
        for sub in ast.walk(root_expr):
            if isinstance(sub, ast.Subscript):
                if isinstance(sub.slice, ast.Constant) and isinstance(sub.slice.value, str):
                    accessed.add(sub.slice.value)
                elif not isinstance(sub.slice, (ast.Slice, ast.Constant)):
                    has_dynamic = True
            elif isinstance(sub, ast.Call) and isinstance(sub.func, ast.Attribute):
                if sub.func.attr in {"get", "pop", "setdefault"} and sub.args:
                    arg0 = sub.args[0]
                    if isinstance(arg0, ast.Constant) and isinstance(arg0.value, str):
                        accessed.add(arg0.value)
                        if (
                            len(sub.args) >= 2
                            and isinstance(sub.args[1], ast.Name)
                            and (
                                sub.args[1].id in mod_policy_consts
                                or is_policy_constant_symbol(sub.args[1].id)
                            )
                        ):
                            fallbacks.add(sub.args[1].id)
                    else:
                        has_dynamic = True
            elif isinstance(sub, ast.Compare):
                for op, _ in zip([None, *sub.ops], [sub.left, *sub.comparators], strict=False):
                    if (
                        isinstance(op, (ast.In, ast.NotIn))
                        and isinstance(sub.left, ast.Constant)
                        and isinstance(sub.left.value, str)
                    ):
                        accessed.add(sub.left.value)
            elif isinstance(sub, ast.BoolOp) and isinstance(sub.op, ast.Or) and len(sub.values) >= 2:
                for tail in sub.values[1:]:
                    if isinstance(tail, ast.Name) and (
                        tail.id in mod_policy_consts or is_policy_constant_symbol(tail.id)
                    ):
                        fallbacks.add(tail.id)

    def _walk(nodes: list[ast.stmt], *, dead: bool = False) -> None:
        nonlocal returns_loaded
        stack: list[tuple[ast.stmt, bool]] = [(st, dead) for st in reversed(nodes)]
        while stack:
            s, cur_dead = stack.pop()
            if isinstance(s, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef)):
                continue
            if not cur_dead and isinstance(s, ast.Assign) and _expr_is_registry_load(s.value):
                for tgt in s.targets:
                    if isinstance(tgt, ast.Name):
                        loaded_vars.add(tgt.id)
            elif (
                not cur_dead
                and isinstance(s, ast.AnnAssign)
                and isinstance(s.target, ast.Name)
                and _expr_is_registry_load(s.value)
            ):
                loaded_vars.add(s.target.id)
            if isinstance(s, ast.If):
                _inspect_expr(s.test, dead=cur_dead)
                cb = _const_bool(s.test)
                if cb is True:
                    body_dead, orelse_dead = cur_dead, True
                elif cb is False:
                    body_dead, orelse_dead = True, cur_dead
                else:
                    body_dead, orelse_dead = cur_dead, cur_dead
                for child in reversed(s.orelse):
                    stack.append((child, orelse_dead))
                for child in reversed(s.body):
                    stack.append((child, body_dead))
                continue
            if isinstance(s, (ast.With, ast.AsyncWith)):
                for item in s.items:
                    _inspect_expr(item.context_expr, dead=cur_dead)
                for child in reversed(s.body):
                    stack.append((child, cur_dead))
                continue
            if isinstance(s, _try_types):
                for child in reversed(s.finalbody):
                    stack.append((child, cur_dead))
                for child in reversed(s.orelse):
                    stack.append((child, cur_dead))
                for h in reversed(s.handlers):
                    for child in reversed(h.body):
                        stack.append((child, cur_dead))
                for child in reversed(s.body):
                    stack.append((child, cur_dead))
                continue
            if isinstance(s, (ast.For, ast.AsyncFor)):
                _inspect_expr(s.iter, dead=cur_dead)
                for child in reversed(s.orelse):
                    stack.append((child, cur_dead))
                for child in reversed(s.body):
                    stack.append((child, cur_dead))
                continue
            if isinstance(s, ast.While):
                _inspect_expr(s.test, dead=cur_dead)
                cb_w = _const_bool(s.test)
                w_body_dead = cur_dead or cb_w is False
                for child in reversed(s.orelse):
                    stack.append((child, cur_dead))
                for child in reversed(s.body):
                    stack.append((child, w_body_dead))
                continue
            if isinstance(s, ast.Match):
                _inspect_expr(s.subject, dead=cur_dead)
                for c in reversed(s.cases):
                    for child in reversed(c.body):
                        stack.append((child, cur_dead))
                    if c.guard is not None:
                        stack.append((ast.Expr(value=c.guard), cur_dead))
                continue
            if not cur_dead and isinstance(s, ast.Return) and s.value is not None:
                if isinstance(s.value, ast.Name) and s.value.id in mod_policy_consts:
                    ret_consts.add(s.value.id)
                elif isinstance(s.value, ast.Call):
                    fn_n = s.value.func.attr if isinstance(s.value.func, ast.Attribute) else (
                        s.value.func.id if isinstance(s.value.func, ast.Name) else ""
                    )
                    if fn_n in {"load", "loads", "safe_load", "safe_load_all", "full_load"}:
                        returns_loaded = True
                elif isinstance(s.value, ast.Name) and s.value.id in loaded_vars:
                    returns_loaded = True
            _inspect_expr(s, dead=cur_dead)

    _walk(stmts)
    consumed_cols = sorted(accessed & known_cols) if (accessed & known_cols) else sorted(accessed)
    consumed_pol = accessed & pol_set
    state: PolicyConsumptionState
    mech: PolicyConsumptionMechanism
    subst: list[str] = []

    if consumed_pol:
        state = "consumed"
        mech = "field_controls_result"
        uncons = sorted(pol_set - consumed_pol)
        note = (
            f"`{scope_name}` reads `{tnode.source_file}` and flows policy key(s) "
            f"{', '.join(f'`{k}`' for k in sorted(consumed_pol))}."
        )
    elif returns_loaded and not ret_consts:
        state = "consumed"
        mech = "field_controls_result"
        consumed_cols = sorted(set(consumed_cols) | pol_set)
        uncons = []
        note = f"`{scope_name}` loads and returns declarative registry `{tnode.source_file}`."
    elif has_dynamic and not ret_consts:
        state = "unresolved"
        mech = "dynamic_or_opaque_flow"
        uncons = sorted(pol_set)
        note = f"`{scope_name}` accesses `{tnode.source_file}` via dynamic key lookup."
    else:
        state = "bypassed"
        mech = "constant_or_fallback_wins"
        uncons = sorted(pol_set)
        subst = sorted(ret_consts)
        note = (
            f"`{scope_name}` loads `{tnode.source_file}` without consuming policy key(s) "
            f"{', '.join(f'`{k}`' for k in uncons[:6])}."
        )

    return PolicyFieldConsumption(
        state=state,
        mechanism=mech,
        reader_scopes=[scope_name],
        policy_columns=pol_cols,
        consumed_columns=consumed_cols,
        unconsumed_policy_columns=uncons,
        substituted_constants=subst,
        fallback_constants=sorted(fallbacks - set(subst)),
        note=note,
    )


_IO_CALL_NAMES = frozenset(
    {
        "load",
        "loads",
        "safe_load",
        "safe_load_all",
        "full_load",
        "read_text",
        "read_bytes",
        "open",
    }
)
_TRY_STMT_TYPES = (ast.Try, *((ast.TryStar,) if hasattr(ast, "TryStar") else ()))


def _expr_has_io_call(node: ast.AST | None) -> bool:
    if node is None:
        return False
    return any(
        isinstance(c, ast.Call)
        and (
            c.func.attr
            if isinstance(c.func, ast.Attribute)
            else (c.func.id if isinstance(c.func, ast.Name) else "")
        )
        in _IO_CALL_NAMES
        for c in ast.walk(node)
    )


def _iter_io_checked_nodes(stmts: list[ast.stmt]):
    stack: list[tuple[bool, ast.AST]] = [(False, st) for st in reversed(stmts)]
    while stack:
        is_direct_expr, node = stack.pop()
        if is_direct_expr:
            if _expr_has_io_call(node):
                yield node
            continue
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef)):
            continue
        if isinstance(node, ast.If):
            for child in reversed(node.orelse):
                stack.append((False, child))
            for child in reversed(node.body):
                stack.append((False, child))
            stack.append((True, node.test))
        elif isinstance(node, (ast.With, ast.AsyncWith)):
            for child in reversed(node.body):
                stack.append((False, child))
            for item in reversed(node.items):
                stack.append((True, item.context_expr))
        elif isinstance(node, _TRY_STMT_TYPES):
            for child in reversed(node.finalbody):
                stack.append((False, child))
            for child in reversed(node.orelse):
                stack.append((False, child))
            for h in reversed(node.handlers):
                for child in reversed(h.body):
                    stack.append((False, child))
            for child in reversed(node.body):
                stack.append((False, child))
        elif isinstance(node, (ast.For, ast.AsyncFor)):
            for child in reversed(node.orelse):
                stack.append((False, child))
            for child in reversed(node.body):
                stack.append((False, child))
            stack.append((True, node.iter))
        elif isinstance(node, ast.While):
            for child in reversed(node.orelse):
                stack.append((False, child))
            for child in reversed(node.body):
                stack.append((False, child))
            stack.append((True, node.test))
        elif isinstance(node, ast.Match):
            for c in reversed(node.cases):
                for child in reversed(c.body):
                    stack.append((False, child))
                if c.guard is not None:
                    stack.append((True, c.guard))
            stack.append((True, node.subject))
        elif _expr_has_io_call(node):
            yield node


def _is_type_checking_if(stmt: ast.If) -> bool:
    test = stmt.test
    return (isinstance(test, ast.Name) and test.id == "TYPE_CHECKING") or (
        isinstance(test, ast.Attribute) and test.attr == "TYPE_CHECKING"
    )


def _resolve_mod_candidates(
    mod_dotted: str,
    caller_rel: str,
    all_py_rels: set[str],
    level: int = 0,
) -> list[str]:
    if level > 0:
        caller_parts = list(PurePosixPath(caller_rel).parent.parts)
        up = level - 1
        if up > len(caller_parts):
            return []
        base_parts = caller_parts[: len(caller_parts) - up]
        mod_parts = [p for p in mod_dotted.split(".") if p] if mod_dotted else []
        rel_slash = "/".join([*base_parts, *mod_parts])
        if not rel_slash:
            return [c for c in ("__init__.py",) if c in all_py_rels]
        cands = [f"{rel_slash}.py", f"{rel_slash}/__init__.py"]
        return [c for c in cands if c in all_py_rels]

    mod_slash = mod_dotted.replace(".", "/").strip("/")
    if not mod_slash:
        return []
    exact = [c for c in (f"{mod_slash}.py", f"{mod_slash}/__init__.py") if c in all_py_rels]
    if exact:
        return exact
    py_suf = f"/{mod_slash}.py"
    init_suf = f"/{mod_slash}/__init__.py"
    suffix_matches = sorted(
        c for c in all_py_rels if c.endswith((py_suf, init_suf))
    )
    if len(suffix_matches) > 1:
        caller_head = PurePosixPath(caller_rel).parts[0] if "/" in caller_rel else ""
        if caller_head:
            same_root = [c for c in suffix_matches if c.startswith(caller_head + "/")]
            if same_root:
                return same_root
    return suffix_matches


def _collect_module_imports(
    py_rel: str,
    tree: ast.Module,
    all_py_rels: set[str],
) -> tuple[dict[str, list[str]], dict[str, set[tuple[str, str]]], list[str]]:
    imported_mods: dict[str, list[str]] = {}
    imported_syms: dict[str, set[tuple[str, str]]] = {}
    star_mods: list[str] = []

    def _walk_stmts(stmts: list[ast.stmt]) -> None:
        stack: list[ast.stmt] = list(reversed(stmts))
        while stack:
            stmt = stack.pop()
            if isinstance(stmt, ast.Import):
                for alias in stmt.names:
                    cands = _resolve_mod_candidates(alias.name, py_rel, all_py_rels, level=0)
                    if cands:
                        local_name = alias.asname or alias.name
                        bucket = imported_mods.setdefault(local_name, [])
                        for c in cands:
                            if c not in bucket:
                                bucket.append(c)
            elif isinstance(stmt, ast.ImportFrom):
                mod_name = stmt.module or ""
                base_cands = (
                    _resolve_mod_candidates(mod_name, py_rel, all_py_rels, level=stmt.level)
                    if (mod_name or stmt.level > 0)
                    else []
                )
                for alias in stmt.names:
                    if alias.name == "*":
                        for c in base_cands:
                            if c not in star_mods:
                                star_mods.append(c)
                        continue
                    local_name = alias.asname or alias.name
                    for c in base_cands:
                        imported_syms.setdefault(local_name, set()).add((c, alias.name))
                    sub_dotted = f"{mod_name}.{alias.name}" if mod_name else alias.name
                    sub_cands = _resolve_mod_candidates(
                        sub_dotted, py_rel, all_py_rels, level=stmt.level
                    )
                    if sub_cands:
                        bucket = imported_mods.setdefault(local_name, [])
                        for c in sub_cands:
                            if c not in bucket:
                                bucket.append(c)
            elif isinstance(stmt, ast.If):
                stack.extend(reversed(stmt.orelse))
                if not _is_type_checking_if(stmt):
                    stack.extend(reversed(stmt.body))
            elif isinstance(stmt, _TRY_STMT_TYPES):
                stack.extend(reversed(stmt.finalbody))
                stack.extend(reversed(stmt.orelse))
                for h in reversed(stmt.handlers):
                    stack.extend(reversed(h.body))
                stack.extend(reversed(stmt.body))
            elif isinstance(stmt, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef)):
                stack.extend(reversed(stmt.body))

    _walk_stmts(tree.body)
    return imported_mods, imported_syms, star_mods


def _dotted_call_parts(func: ast.AST) -> list[str] | None:
    parts: list[str] = []
    cur = func
    while isinstance(cur, ast.Attribute):
        parts.append(cur.attr)
        cur = cur.value
    if isinstance(cur, ast.Name):
        parts.append(cur.id)
        parts.reverse()
        return parts
    return None


def _scope_has_nonempty_return(stmts: list[ast.stmt]) -> bool:
    stack: list[ast.AST] = list(reversed(stmts))
    while stack:
        cur = stack.pop()
        if isinstance(cur, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef)):
            continue
        if isinstance(cur, ast.Return) and cur.value is not None:
            return True
        stack.extend(reversed(list(ast.iter_child_nodes(cur))))
    return False


def _wire_python_registry_readers(
    trees: dict[str, ast.Module],
    reg_nodes: dict[str, AtlasNode],
    result: ManipulatorExtractionResult,
    route_keys_by_rel: dict[str, dict[str, list[str]]] | None,
) -> None:
    if not reg_nodes or not trees:
        return
    reg_rels = set(reg_nodes)
    all_py_rels = set(trees)
    bname_counts: dict[str, list[str]] = {}
    for r_rel in reg_rels:
        bname_counts.setdefault(PurePosixPath(r_rel).name, []).append(r_rel)
    unique_basenames = {b: rels[0] for b, rels in bname_counts.items() if len(rels) == 1}

    # Discover direct scopes loading each registry + exported loader helper functions/methods
    direct_scopes: dict[tuple[str, str], dict[str, tuple[int, list[ast.stmt]]]] = {}
    exported_loaders: dict[tuple[str, str | None, str], set[str]] = {}  # (module_rel, cls_name, fn_name) -> {reg_rel}
    scope_loader_key: dict[tuple[str, str], tuple[str, str | None, str]] = {}
    scope_cls_owner: dict[tuple[str, str], str] = {}
    top_level_funcs: set[tuple[str, str]] = set()
    class_methods: dict[tuple[str, str], set[str]] = {}
    mod_scopes_map: dict[str, dict[str, tuple[int, list[ast.stmt]]]] = {}
    mod_pol_consts_map: dict[str, set[str]] = {}

    for py_rel, tree in sorted(trees.items()):
        mod_env = _collect_str_bindings(tree.body, {})
        pol_consts = {
            t.id
            for s in tree.body
            if isinstance(s, ast.Assign)
            for t in s.targets
            if isinstance(t, ast.Name) and is_policy_constant_symbol(t.id)
        }
        mod_pol_consts_map[py_rel] = pol_consts
        scopes: dict[str, tuple[int, list[ast.stmt], dict[str, str]]] = {"*": (1, tree.body, mod_env)}
        for stmt in tree.body:
            if isinstance(stmt, (ast.FunctionDef, ast.AsyncFunctionDef)):
                top_level_funcs.add((py_rel, stmt.name))
                scope_loader_key[(py_rel, stmt.name)] = (py_rel, None, stmt.name)
                scopes[stmt.name] = (stmt.lineno, stmt.body, _collect_str_bindings(stmt.body, mod_env))
            elif isinstance(stmt, ast.ClassDef):
                c_env = _collect_str_bindings(stmt.body, mod_env)
                for m in stmt.body:
                    if isinstance(m, (ast.FunctionDef, ast.AsyncFunctionDef)):
                        sc_key = f"{stmt.name}.{m.name}"
                        class_methods.setdefault((py_rel, stmt.name), set()).add(m.name)
                        scope_cls_owner[(py_rel, sc_key)] = stmt.name
                        scope_loader_key[(py_rel, sc_key)] = (py_rel, stmt.name, m.name)
                        scopes[sc_key] = (m.lineno, m.body, _collect_str_bindings(m.body, c_env))
        mod_scopes_map[py_rel] = {k: (v[0], v[1]) for k, v in scopes.items()}

        for sc_name, (sc_ln, sc_body, sc_env) in scopes.items():
            matched_in_sc: dict[str, int] = {}
            for io_node in _iter_io_checked_nodes(sc_body):
                for sub in ast.walk(io_node):
                    if isinstance(sub, (ast.Constant, ast.JoinedStr, ast.BinOp, ast.Name)):
                        if isinstance(sub, ast.Name) and sub.id not in sc_env:
                            continue
                        val = _eval_str_expr(sub, sc_env)
                        m_reg = _match_registry_rel(val, reg_rels, unique_basenames)
                        if m_reg and m_reg not in matched_in_sc:
                            matched_in_sc[m_reg] = getattr(sub, "lineno", sc_ln)
            for m_reg, hit_ln in matched_in_sc.items():
                direct_scopes.setdefault((py_rel, m_reg), {})[sc_name] = (hit_ln, sc_body)
                lkey = scope_loader_key.get((py_rel, sc_name))
                if lkey is not None and _scope_has_nonempty_return(sc_body):
                    exported_loaders.setdefault(lkey, set()).add(m_reg)

    # 1-hop cross-module / intra-module calls to import-qualified loader helpers
    for py_rel, tree in sorted(trees.items()):
        imported_mods, imported_syms, star_mods = _collect_module_imports(
            py_rel, tree, all_py_rels
        )
        for sc_name, (sc_ln, sc_body) in mod_scopes_map[py_rel].items():
            for s in sc_body:
                if sc_name == "*" and isinstance(s, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef)):
                    continue
                for sub in ast.walk(s):
                    if not isinstance(sub, ast.Call):
                        continue
                    matched_regs: set[str] = set()
                    if isinstance(sub.func, ast.Name):
                        fn_n = sub.func.id
                        for cand_rel, orig_sym in imported_syms.get(fn_n, ()):
                            if (cand_rel, orig_sym) in top_level_funcs:
                                matched_regs.update(
                                    exported_loaders.get((cand_rel, None, orig_sym), ())
                                )
                        for cand_rel in star_mods:
                            if (cand_rel, fn_n) in top_level_funcs:
                                matched_regs.update(
                                    exported_loaders.get((cand_rel, None, fn_n), ())
                                )
                        if (py_rel, fn_n) in top_level_funcs:
                            matched_regs.update(exported_loaders.get((py_rel, None, fn_n), ()))
                    elif isinstance(sub.func, ast.Attribute):
                        parts = _dotted_call_parts(sub.func)
                        if parts and len(parts) >= 2:
                            attr = parts[-1]
                            if parts[0] in {"self", "cls"} and len(parts) == 2:
                                cls_n = scope_cls_owner.get((py_rel, sc_name))
                                if cls_n is not None and attr in class_methods.get((py_rel, cls_n), ()):
                                    matched_regs.update(
                                        exported_loaders.get((py_rel, cls_n, attr), ())
                                    )
                            else:
                                recv = ".".join(parts[:-1])
                                for cand_rel in imported_mods.get(recv, ()):
                                    if (cand_rel, attr) in top_level_funcs:
                                        matched_regs.update(
                                            exported_loaders.get((cand_rel, None, attr), ())
                                        )
                                for cand_rel, orig_sym in imported_syms.get(recv, ()):
                                    if attr in class_methods.get((cand_rel, orig_sym), ()):
                                        matched_regs.update(
                                            exported_loaders.get((cand_rel, orig_sym, attr), ())
                                        )
                                if len(parts) >= 3:
                                    mod_recv = ".".join(parts[:-2])
                                    cls_cand = parts[-2]
                                    for cand_rel in imported_mods.get(mod_recv, ()):
                                        if attr in class_methods.get((cand_rel, cls_cand), ()):
                                            matched_regs.update(
                                                exported_loaders.get((cand_rel, cls_cand, attr), ())
                                            )
                                if attr in class_methods.get((py_rel, recv), ()):
                                    matched_regs.update(
                                        exported_loaders.get((py_rel, recv, attr), ())
                                    )
                    for m_reg in matched_regs:
                        bucket = direct_scopes.setdefault((py_rel, m_reg), {})
                        if sc_name not in bucket:
                            bucket[sc_name] = (getattr(sub, "lineno", sc_ln), sc_body)

    mnodes_by_id = {n.id: n for n in result.nodes}
    pfcs_by_reg: dict[str, list[PolicyFieldConsumption]] = {}

    for (py_rel, reg_rel), sc_dict in sorted(direct_scopes.items()):
        tnode = reg_nodes[reg_rel]
        # Prefer caller scopes over internal loader helper when both exist in the same module
        active_names = sorted(sc_dict)
        if len(active_names) > 1:
            non_loaders = [
                n
                for n in active_names
                if (lkey := scope_loader_key.get((py_rel, n))) is None
                or reg_rel not in exported_loaders.get(lkey, set())
            ]
            if non_loaders:
                active_names = non_loaders

        sc_pfcs: list[PolicyFieldConsumption] = []
        slinks: list[str] = []
        first_ln = min(sc_dict[n][0] for n in active_names)
        rkeys = (route_keys_by_rel or {}).get(py_rel, {})
        for sc_n in active_names:
            _, body = sc_dict[sc_n]
            sc_pfcs.append(
                _analyze_scope_registry_consumption(body, sc_n, tnode, mod_pol_consts_map.get(py_rel, set()))
            )
            slinks.append(f"{sc_n}->*")
            for rk in rkeys.get(sc_n) or rkeys.get(sc_n.rsplit(".", 1)[-1], ()):
                if f"{rk}->*" not in slinks:
                    slinks.append(f"{rk}->*")

        merged_edge_pfc = merge_policy_consumptions(sc_pfcs)
        src_nid = script_id(py_rel)
        fmt = _registry_format_label(reg_rel)
        result.edges.append(
            AtlasEdge(
                id=f"e:script:{py_rel}:reads_truth:{tnode.id}",
                source_id=src_nid,
                target_id=tnode.id,
                kind="reads_truth",
                verification="verified",
                evidence_path=f"{py_rel}:{first_ln}",
                evidence_note=(
                    f"Python module loads declarative {fmt} registry `{reg_rel}` "
                    f"(policy_field_consumption={merged_edge_pfc.state if merged_edge_pfc else 'unresolved'})."
                ),
                symbol_links=slinks,
                policy_field_consumption=merged_edge_pfc,
            )
        )
        if merged_edge_pfc is not None:
            pfcs_by_reg.setdefault(reg_rel, []).append(merged_edge_pfc)
            mnode = mnodes_by_id.get(src_nid)
            if mnode is not None:
                mnode.policy_field_consumption = (
                    merge_policy_consumptions([mnode.policy_field_consumption, merged_edge_pfc])
                    if mnode.policy_field_consumption is not None
                    else merged_edge_pfc
                )

    for reg_rel, pfc_list in pfcs_by_reg.items():
        tnode = reg_nodes[reg_rel]
        merged_t = merge_policy_consumptions(pfc_list)
        if merged_t is not None:
            tnode.policy_field_consumption = merged_t
            tnode.verification_note = f"policy_field_consumption={merged_t.state}"


def add_registry_sources(
    repo_root: Path,
    result: ManipulatorExtractionResult,
    deployments: dict[str, set[str]],
    *,
    truth: TruthExtractionResult | None = None,
    trees: dict[str, ast.Module] | None = None,
    route_keys_by_rel: dict[str, dict[str, list[str]]] | None = None,
) -> None:
    paths = {n.source_file for n in result.nodes if n.id.startswith("m:script:")}
    entries, unreadable = _discover_registry_files(repo_root)
    declarations = len(entries)
    linked = 0
    existing_tnodes = {n.id: n for n in truth.nodes} if truth is not None else {}
    reg_nodes: dict[str, AtlasNode] = {}

    for rel, data, commands in entries:
        tid = f"t:registry:{rel}"
        tnode = existing_tnodes.get(tid)
        if tnode is None:
            tnode = _build_registry_truth_node(rel, data)
            if truth is not None:
                truth.nodes.append(tnode)
                truth.table_symbol_map[f"registry:{rel}"] = tid
                truth.table_symbol_map[rel] = tid
        reg_nodes[rel] = tnode

        targets: set[str] = set()
        for command in commands:
            for candidate in {command, *shell_references(command)}:
                mapped = deployments.get(normalize_home(candidate), set())
                if mapped:
                    targets.update(mapped & paths)
                else:
                    target = source_reference(candidate, rel, paths)
                    if target:
                        targets.add(target)
        if commands or targets:
            nid = f"m:registry:{rel}"
            fmt = _registry_format_label(rel)
            result.nodes.append(
                AtlasNode(
                    id=nid,
                    tier="manipulate",
                    subkind="cli",
                    label=rel,
                    source_file=rel,
                    cluster="registries",
                    summary=f"{fmt} command declarations, including potentially disabled or host-specific entries. Eligibility and scheduling are not inferred.",
                )
            )
            linked += bool(targets)
            for target in sorted(targets):
                result.edges.append(
                    AtlasEdge(
                        id=f"e:registry:{rel}:{target}",
                        source_id=nid,
                        target_id=script_id(target),
                        kind="calls_helper",
                        verification="declared",
                        evidence_path=f"{rel}:1",
                        evidence_note=f"{fmt} command field references a source path; enabled state, runtime registration and actual execution are unknown.",
                    )
                )

    if trees:
        _wire_python_registry_readers(trees, reg_nodes, result, route_keys_by_rel)

    if unreadable > 0:
        object.__setattr__(result, "coverage_complete", False)
        if truth is not None:
            object.__setattr__(truth, "coverage_complete", False)

    yaml_count = sum(1 for rel, _, _ in entries if _registry_format_label(rel) == "YAML")
    json_count = declarations - yaml_count
    if yaml_count and json_count:
        cov_fmt = f"JSON/YAML ({json_count} JSON, {yaml_count} YAML)"
    elif yaml_count:
        cov_fmt = "YAML"
    else:
        cov_fmt = "JSON"
    result.notes.append(
        f"{cov_fmt} command source coverage: {declarations} config/configs files with command or policy registry fields, "
        f"{linked} with source links, {unreadable} unreadable files. Custom registry schemas, "
        "variable substitutions and admission rules are not evaluated; disabled entries are retained."
    )
