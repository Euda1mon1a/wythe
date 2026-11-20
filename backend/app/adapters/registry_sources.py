"""Declarative JSON registries (`config/`, `configs/`), Tier-1 policy Truth, and key consumption."""

from __future__ import annotations

import ast
import json
from pathlib import Path, PurePosixPath

import yaml

from app.adapters.base import ManipulatorExtractionResult, TruthExtractionResult
from app.adapters.deployment_sources import normalize_home
from app.adapters.inline_store_truth import _collect_str_bindings, _eval_str_expr
from app.adapters.launchd_sources import shell_references
from app.adapters.python_policy_consumption import (
    _const_bool,
    classify_table_policy_columns,
    is_policy_constant_symbol,
    merge_policy_consumptions,
)
from app.adapters.service_sources import script_id, source_files, source_reference
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


def _is_excluded_registry_candidate(rel: str, data: object) -> bool:
    rel_lc = rel.lower()
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
    if bname.endswith((".schema.json", ".schema.yaml", ".schema.yml")):
        return True
    if "/workflows/" in f"/{rel_lc}" or "/.github/" in f"/{rel_lc}":
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
    if "$schema" in data:
        top_keys = set(data.keys())
        if top_keys <= _JSON_SCHEMA_META_ONLY_KEYS:
            return True
        if (
            data.get("type") == "object"
            and isinstance(data.get("properties"), dict)
            and not (top_keys & (_REGISTRY_SECTION_KEYS | _COMMAND_KEYS))
        ):
            return True
    return False


def _commands(value: object):
    stack: list[tuple[object, int]] = [(value, 0)]
    while stack:
        cur, depth = stack.pop()
        if depth > 32:
            continue
        if isinstance(cur, dict):
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
            for child in reversed(cur):
                stack.append((child, depth + 1))


def _has_registry_keys(value: object, depth: int = 0) -> bool:
    if depth > 4:
        return False
    if isinstance(value, dict):
        if set(value.keys()) & (_REGISTRY_SECTION_KEYS | _COMMAND_KEYS):
            return True
        return any(_has_registry_keys(v, depth + 1) for v in value.values())
    if isinstance(value, list):
        return any(_has_registry_keys(item, depth + 1) for item in value[:20])
    return False


def _extract_registry_columns(data: object) -> tuple[list[str], list[str]]:
    cols: list[str] = []

    def _walk_keys(obj: object, depth: int = 0) -> None:
        if depth > 4 or len(cols) >= 40:
            return
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
    found: list[tuple[str, object, list[str]]] = []
    unreadable = 0
    for dirname in ("config", "configs"):
        files, _ = source_files(repo_root / dirname, set(_REGISTRY_FILE_SUFFIXES))
        for path in files:
            rel = path.relative_to(repo_root).as_posix()
            try:
                raw_text = path.read_text(encoding="utf-8")
                if path.suffix.lower() in {".yaml", ".yml"}:
                    data = yaml.safe_load(raw_text)
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
            f"Declarative JSON policy/command registry `{rel}`; "
            "admission, enabled flags, and schedule state are static declarations."
        ),
        columns=cols,
        policy_columns=pol_cols,
    )


def extract_registry_truth_nodes(repo_root: Path) -> tuple[list[AtlasNode], dict[str, str]]:
    """Return Tier-1 `t:registry:<rel>` policy Truth nodes and `table_symbol_map` entries."""
    entries, _ = _discover_registry_files(repo_root)
    nodes: list[AtlasNode] = []
    sym_map: dict[str, str] = {}
    for rel, data, _ in entries:
        tnode = _build_registry_truth_node(rel, data)
        nodes.append(tnode)
        sym_map[f"registry:{rel}"] = tnode.id
        sym_map[rel] = tnode.id
    return nodes, sym_map


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
        for s in nodes:
            if isinstance(s, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef)):
                continue
            if not dead and isinstance(s, ast.Assign) and _expr_is_registry_load(s.value):
                for tgt in s.targets:
                    if isinstance(tgt, ast.Name):
                        loaded_vars.add(tgt.id)
            elif (
                not dead
                and isinstance(s, ast.AnnAssign)
                and isinstance(s.target, ast.Name)
                and _expr_is_registry_load(s.value)
            ):
                loaded_vars.add(s.target.id)
            if isinstance(s, ast.If):
                _inspect_expr(s.test, dead=dead)
                cb = _const_bool(s.test)
                if cb is True:
                    _walk(s.body, dead=dead)
                    _walk(s.orelse, dead=True)
                elif cb is False:
                    _walk(s.body, dead=True)
                    _walk(s.orelse, dead=dead)
                else:
                    _walk(s.body, dead=dead)
                    _walk(s.orelse, dead=dead)
                continue
            if isinstance(s, (ast.With, ast.AsyncWith)):
                for item in s.items:
                    _inspect_expr(item.context_expr, dead=dead)
                _walk(s.body, dead=dead)
                continue
            if isinstance(s, _try_types):
                _walk(s.body, dead=dead)
                for h in s.handlers:
                    _walk(h.body, dead=dead)
                _walk(s.orelse, dead=dead)
                _walk(s.finalbody, dead=dead)
                continue
            if isinstance(s, (ast.For, ast.AsyncFor)):
                _inspect_expr(s.iter, dead=dead)
                _walk(s.body, dead=dead)
                _walk(s.orelse, dead=dead)
                continue
            if isinstance(s, ast.While):
                _inspect_expr(s.test, dead=dead)
                cb_w = _const_bool(s.test)
                _walk(s.body, dead=(dead or cb_w is False))
                _walk(s.orelse, dead=dead)
                continue
            if isinstance(s, ast.Match):
                _inspect_expr(s.subject, dead=dead)
                for c in s.cases:
                    _inspect_expr(c.guard, dead=dead)
                    _walk(c.body, dead=dead)
                continue
            if not dead and isinstance(s, ast.Return) and s.value is not None:
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
            _inspect_expr(s, dead=dead)

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


def _wire_python_registry_readers(
    trees: dict[str, ast.Module],
    reg_nodes: dict[str, AtlasNode],
    result: ManipulatorExtractionResult,
    route_keys_by_rel: dict[str, dict[str, list[str]]] | None,
) -> None:
    if not reg_nodes or not trees:
        return
    reg_rels = set(reg_nodes)
    bname_counts: dict[str, list[str]] = {}
    for r_rel in reg_rels:
        bname_counts.setdefault(PurePosixPath(r_rel).name, []).append(r_rel)
    unique_basenames = {b: rels[0] for b, rels in bname_counts.items() if len(rels) == 1}

    # Discover direct scopes loading each registry + exported loader helper functions
    direct_scopes: dict[tuple[str, str], dict[str, tuple[int, list[ast.stmt]]]] = {}
    exported_loaders: dict[str, set[str]] = {}  # fn_name -> {reg_rel}
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
                scopes[stmt.name] = (stmt.lineno, stmt.body, _collect_str_bindings(stmt.body, mod_env))
            elif isinstance(stmt, ast.ClassDef):
                c_env = _collect_str_bindings(stmt.body, mod_env)
                for m in stmt.body:
                    if isinstance(m, (ast.FunctionDef, ast.AsyncFunctionDef)):
                        scopes[m.name] = (m.lineno, m.body, _collect_str_bindings(m.body, c_env))
        mod_scopes_map[py_rel] = {k: (v[0], v[1]) for k, v in scopes.items()}

        for sc_name, (sc_ln, sc_body, sc_env) in scopes.items():
            matched_in_sc: dict[str, int] = {}
            for s in sc_body:
                if sc_name == "*" and isinstance(s, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef)):
                    continue
                stmt_has_io = any(
                    isinstance(c, ast.Call)
                    and (
                        c.func.attr
                        if isinstance(c.func, ast.Attribute)
                        else (c.func.id if isinstance(c.func, ast.Name) else "")
                    )
                    in {
                        "load",
                        "loads",
                        "safe_load",
                        "safe_load_all",
                        "full_load",
                        "read_text",
                        "read_bytes",
                        "open",
                    }
                    for c in ast.walk(s)
                )
                if sc_name == "*" and isinstance(s, (ast.Assign, ast.AnnAssign)) and not stmt_has_io:
                    continue
                for sub in ast.walk(s):
                    if isinstance(sub, (ast.Constant, ast.JoinedStr, ast.BinOp, ast.Name)):
                        if isinstance(sub, ast.Name) and sub.id not in sc_env:
                            continue
                        val = _eval_str_expr(sub, sc_env)
                        m_reg = _match_registry_rel(val, reg_rels, unique_basenames)
                        if m_reg and m_reg not in matched_in_sc:
                            matched_in_sc[m_reg] = getattr(sub, "lineno", sc_ln)
            for m_reg, hit_ln in matched_in_sc.items():
                direct_scopes.setdefault((py_rel, m_reg), {})[sc_name] = (hit_ln, sc_body)
                if sc_name != "*" and any(isinstance(st, ast.Return) and st.value is not None for st in sc_body):
                    exported_loaders.setdefault(sc_name, set()).add(m_reg)

    # 1-hop cross-module / intra-module calls to loader helpers
    for py_rel, tree in sorted(trees.items()):
        for sc_name, (sc_ln, sc_body) in mod_scopes_map[py_rel].items():
            for s in sc_body:
                if sc_name == "*" and isinstance(s, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef)):
                    continue
                for sub in ast.walk(s):
                    if isinstance(sub, ast.Call):
                        fn_n = sub.func.id if isinstance(sub.func, ast.Name) else (
                            sub.func.attr if isinstance(sub.func, ast.Attribute) else ""
                        )
                        for m_reg in exported_loaders.get(fn_n, ()):
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
            non_loaders = [n for n in active_names if reg_rel not in exported_loaders.get(n, set())]
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
            for rk in rkeys.get(sc_n, ()):
                if f"{rk}->*" not in slinks:
                    slinks.append(f"{rk}->*")

        merged_edge_pfc = merge_policy_consumptions(sc_pfcs)
        src_nid = script_id(py_rel)
        result.edges.append(
            AtlasEdge(
                id=f"e:script:{py_rel}:reads_truth:{tnode.id}",
                source_id=src_nid,
                target_id=tnode.id,
                kind="reads_truth",
                verification="verified",
                evidence_path=f"{py_rel}:{first_ln}",
                evidence_note=(
                    f"Python module loads declarative JSON registry `{reg_rel}` "
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
            result.nodes.append(
                AtlasNode(
                    id=nid,
                    tier="manipulate",
                    subkind="cli",
                    label=rel,
                    source_file=rel,
                    cluster="registries",
                    summary="JSON command declarations, including potentially disabled or host-specific entries. Eligibility and scheduling are not inferred.",
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
                        evidence_note="JSON command field references a source path; enabled state, runtime registration and actual execution are unknown.",
                    )
                )

    if trees:
        _wire_python_registry_readers(trees, reg_nodes, result, route_keys_by_rel)

    result.notes.append(
        f"JSON command source coverage: {declarations} config/configs files with command or policy registry fields, "
        f"{linked} with source links, {unreadable} unreadable files. Custom registry schemas, "
        "variable substitutions and admission rules are not evaluated; disabled entries are retained."
    )
