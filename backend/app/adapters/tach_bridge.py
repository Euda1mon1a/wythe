"""Static `tach.toml` horizontal module-boundary bridge for Wythe Tier-2 lineage.

Parses `tach` (`gauge-sh/tach`) configuration files via Python 3.12 `tomllib` without
invoking the `tach` CLI or importing target repository code. Maps extracted Python
manipulator nodes to their owning horizontal `tach` domain module and verifies both
AST imports under `source_roots` and intra-repo `calls_helper` edges against
`depends_on`, `layers`, `utility = true`, `visibility`, `strict`, and `[[interfaces]]`.
"""

from __future__ import annotations

import ast
import fnmatch
import re
import tomllib
from dataclasses import dataclass, field
from pathlib import Path, PurePosixPath

from app.adapters.base import ManipulatorExtractionResult, RawCandidateFinding
from app.adapters.service_sources import source_files
from app.schemas.atlas import AtlasEdge, AtlasNode


@dataclass(frozen=True)
class TachModuleRule:
    """Normalized `[[modules]]` declaration from `tach.toml`."""

    path: str
    depends_on: tuple[str, ...] | None = None
    deprecated_deps: frozenset[str] = field(default_factory=frozenset)
    layer: str | None = None
    utility: bool = False
    strict: bool = False
    visibility: tuple[str, ...] | None = None


@dataclass(frozen=True)
class TachInterfaceRule:
    """Normalized `[[interfaces]]` public contract from `tach.toml`."""

    from_modules: tuple[str, ...]
    expose: tuple[str, ...]
    visibility: tuple[str, ...] | None = None
    exclusive: bool = False


@dataclass(frozen=True)
class TachConfig:
    """Parsed `tach.toml` boundary specification."""

    config_path: Path
    config_rel: str
    config_dir: Path
    source_roots: tuple[Path, ...]
    layers: tuple[str, ...]
    modules: dict[str, TachModuleRule]
    interfaces: tuple[TachInterfaceRule, ...]
    exclude_patterns: tuple[str, ...] = ()


def _pattern_matches(pattern: str, candidate: str) -> bool:
    if pattern in ("*", ".*"):
        return True
    if pattern == candidate:
        return True
    try:
        if re.fullmatch(pattern, candidate) is not None:
            return True
    except re.error:
        pass
    return fnmatch.fnmatchcase(candidate, pattern)


def _find_tach_toml(repo_root: Path, backend_subdir: str) -> Path | None:
    resolved_root = repo_root.resolve()
    candidates = [repo_root / "tach.toml"]
    clean_sub = backend_subdir.strip().strip("/")
    if clean_sub and clean_sub != ".":
        candidates.append(repo_root / clean_sub / "tach.toml")
    for cand in candidates:
        if cand.is_symlink() or not cand.is_file():
            continue
        resolved = cand.resolve()
        if resolved.is_relative_to(resolved_root):
            return resolved
    return None


def _parse_depends_on(raw_deps: object) -> tuple[tuple[str, ...] | None, frozenset[str]]:
    if raw_deps is None:
        return None, frozenset()
    if not isinstance(raw_deps, list):
        return (), frozenset()
    allowed: list[str] = []
    deprecated: set[str] = set()
    for item in raw_deps:
        if isinstance(item, str) and item.strip():
            allowed.append(item.strip())
        elif isinstance(item, dict):
            dep_path = item.get("path")
            if isinstance(dep_path, str) and dep_path.strip():
                clean = dep_path.strip()
                allowed.append(clean)
                if bool(item.get("deprecated", False)):
                    deprecated.add(clean)
    return tuple(dict.fromkeys(allowed)), frozenset(deprecated)


def _as_str_tuple(raw: object) -> tuple[str, ...] | None:
    if raw is None:
        return None
    if isinstance(raw, str):
        return (raw.strip(),) if raw.strip() else ()
    if isinstance(raw, list):
        return tuple(x.strip() for x in raw if isinstance(x, str) and x.strip())
    return ()


def parse_tach_toml(config_path: Path, repo_root: Path) -> TachConfig:
    """Parse a validated `tach.toml` file into `TachConfig`."""
    resolved_root = repo_root.resolve()
    data = tomllib.loads(config_path.read_text(encoding="utf-8-sig"))
    config_dir = config_path.parent.resolve()
    config_rel = config_path.relative_to(resolved_root).as_posix()

    raw_roots = data.get("source_roots")
    if raw_roots is None:
        single_root = data.get("source_root", ".")
        raw_roots = [single_root] if isinstance(single_root, str) else ["."]
    roots: list[Path] = []
    if isinstance(raw_roots, list):
        for entry in raw_roots:
            if not isinstance(entry, str) or not entry.strip():
                continue
            cand = (config_dir / entry.strip()).resolve()
            if cand.is_relative_to(resolved_root) and cand.is_dir() and not cand.is_symlink():
                roots.append(cand)
    if not roots:
        roots.append(config_dir)
    # Longest path first so nested source roots bind to their most specific root.
    roots.sort(key=lambda p: len(p.parts), reverse=True)

    layers = _as_str_tuple(data.get("layers")) or ()
    excludes = _as_str_tuple(data.get("exclude")) or ()

    modules: dict[str, TachModuleRule] = {}
    raw_modules = data.get("modules", [])
    if isinstance(raw_modules, list):
        for entry in raw_modules:
            if not isinstance(entry, dict):
                continue
            mod_paths: list[str] = []
            if isinstance(entry.get("path"), str) and entry["path"].strip():
                mod_paths.append(entry["path"].strip())
            elif isinstance(entry.get("paths"), list):
                mod_paths.extend(
                    p.strip() for p in entry["paths"] if isinstance(p, str) and p.strip()
                )
            deps, dep_depr = _parse_depends_on(entry.get("depends_on"))
            layer_val = entry.get("layer")
            layer_str = layer_val.strip() if isinstance(layer_val, str) and layer_val.strip() else None
            vis = _as_str_tuple(entry.get("visibility"))
            for mpath in mod_paths:
                modules[mpath] = TachModuleRule(
                    path=mpath,
                    depends_on=deps,
                    deprecated_deps=dep_depr,
                    layer=layer_str,
                    utility=bool(entry.get("utility", False)),
                    strict=bool(entry.get("strict", False)),
                    visibility=vis,
                )

    interfaces: list[TachInterfaceRule] = []
    raw_ifaces = data.get("interfaces", [])
    if isinstance(raw_ifaces, list):
        for entry in raw_ifaces:
            if not isinstance(entry, dict):
                continue
            from_mods = _as_str_tuple(entry.get("from")) or ()
            expose_list = _as_str_tuple(entry.get("expose")) or ()
            if not from_mods:
                continue
            interfaces.append(
                TachInterfaceRule(
                    from_modules=from_mods,
                    expose=expose_list,
                    visibility=_as_str_tuple(entry.get("visibility")),
                    exclusive=bool(entry.get("exclusive", False)),
                )
            )

    return TachConfig(
        config_path=config_path,
        config_rel=config_rel,
        config_dir=config_dir,
        source_roots=tuple(dict.fromkeys(roots)),
        layers=layers,
        modules=modules,
        interfaces=tuple(interfaces),
        exclude_patterns=excludes,
    )


def _sr_prefix_for_root(sr: Path, config_dir: Path) -> str:
    if sr == config_dir or not sr.is_relative_to(config_dir):
        return ""
    return ".".join(sr.relative_to(config_dir).parts)


def _dotted_for_file(abs_file: Path, config: TachConfig) -> tuple[str, str, bool] | None:
    resolved = abs_file.resolve()
    for sr in config.source_roots:
        if not resolved.is_relative_to(sr):
            continue
        rel = resolved.relative_to(sr)
        if rel.suffix != ".py":
            return None
        parts = list(rel.with_suffix("").parts)
        is_pkg_init = bool(parts and parts[-1] == "__init__")
        if is_pkg_init:
            parts = parts[:-1]
        dotted = ".".join(parts) if parts else "<root>"
        return dotted, _sr_prefix_for_root(sr, config.config_dir), is_pkg_init
    return None


def resolve_owning_tach_module(
    mod_dotted: str,
    config: TachConfig,
    sr_prefix: str = "",
) -> str | None:
    """Return the most specific declared `tach` module owning `mod_dotted`."""
    if mod_dotted == "<root>":
        return "<root>" if "<root>" in config.modules else None
    candidates = [mod_dotted]
    if sr_prefix and not mod_dotted.startswith(f"{sr_prefix}."):
        candidates.append(f"{sr_prefix}.{mod_dotted}")
    best: str | None = None
    for cand in candidates:
        for declared in config.modules:
            if declared == "<root>":
                continue
            if (cand == declared or cand.startswith(f"{declared}.")) and (
                best is None or len(declared) > len(best)
            ):
                best = declared
        if best is not None:
            return best
    return "<root>" if "<root>" in config.modules else None


def _extract_dunder_all(tree: ast.Module) -> frozenset[str] | None:
    for stmt in tree.body:
        targets: list[ast.expr] = []
        val: ast.expr | None = None
        if isinstance(stmt, ast.Assign):
            targets = list(stmt.targets)
            val = stmt.value
        elif isinstance(stmt, ast.AnnAssign):
            targets = [stmt.target]
            val = stmt.value
        if any(isinstance(t, ast.Name) and t.id == "__all__" for t in targets) and isinstance(
            val, (ast.List, ast.Tuple, ast.Set)
        ):
            items = [
                elt.value
                for elt in val.elts
                if isinstance(elt, ast.Constant) and isinstance(elt.value, str)
            ]
            return frozenset(items)
    return None


def _evaluate_import_boundary(
    *,
    caller_owner: str,
    callee_owner: str,
    target_mod: str,
    rel_member: str | None,
    config: TachConfig,
    pkg_dunder_all: dict[str, frozenset[str] | None],
) -> tuple[str, str, str] | None:
    if caller_owner == callee_owner:
        return None
    caller_rule = config.modules.get(caller_owner)
    callee_rule = config.modules.get(callee_owner)
    if caller_rule is None or callee_rule is None:
        return None

    if callee_rule.visibility is not None and not any(
        _pattern_matches(v, caller_owner) for v in callee_rule.visibility
    ):
        allowed_vis = ", ".join(f"`{v}`" for v in callee_rule.visibility) or "none"
        return (
            f"Forbidden tach import `{caller_owner}` -> `{callee_owner}` (visibility restricted)",
            (
                f"`{caller_owner}` imports `{target_mod}`, but `{callee_owner}` restricts "
                f"visibility in `{config.config_rel}` to: {allowed_vis}."
            ),
            (
                f"Route calls through a module authorized by `{callee_owner}` visibility or "
                f"update `{config.config_rel}` if the architectural boundary changed intentionally."
            ),
        )

    if not callee_rule.utility:
        if caller_rule.depends_on is not None and callee_owner not in caller_rule.depends_on:
            allowed_deps = ", ".join(f"`{d}`" for d in caller_rule.depends_on) or "none"
            return (
                f"Forbidden cross-domain import `{caller_owner}` -> `{callee_owner}`",
                (
                    f"`{caller_owner}` imports `{target_mod}` owned by `{callee_owner}`, which is "
                    f"not in `{caller_owner}` `depends_on` ({allowed_deps}) in "
                    f"`{config.config_rel}`."
                ),
                (
                    f"Remove the cross-domain import from `{caller_owner}` to `{callee_owner}` or "
                    f"expose a shared domain/service contract permitted by `{config.config_rel}`."
                ),
            )
        if (
            config.layers
            and caller_rule.layer in config.layers
            and callee_rule.layer in config.layers
            and config.layers.index(caller_rule.layer) > config.layers.index(callee_rule.layer)
            and callee_owner not in (caller_rule.depends_on or ())
        ):
            return (
                (
                    f"Forbidden upward layer import `{caller_owner}` ({caller_rule.layer}) -> "
                    f"`{callee_owner}` ({callee_rule.layer})"
                ),
                (
                    f"`{caller_owner}` in lower layer `{caller_rule.layer}` imports "
                    f"`{target_mod}` in higher layer `{callee_rule.layer}` (`{config.config_rel}`)."
                ),
                "Invert the dependency so lower layers never import higher presentation/API layers.",
            )

    matching_ifaces = [
        iface
        for iface in config.interfaces
        if any(_pattern_matches(fm, callee_owner) for fm in iface.from_modules)
    ]
    if matching_ifaces:
        visible_ifaces = [
            iface
            for iface in matching_ifaces
            if iface.visibility is None
            or any(_pattern_matches(v, caller_owner) for v in iface.visibility)
        ]
        if not visible_ifaces:
            return (
                f"Unexposed tach interface `{caller_owner}` -> `{callee_owner}`",
                (
                    f"`{callee_owner}` defines `[[interfaces]]` in `{config.config_rel}`, and "
                    f"none are visible to `{caller_owner}`."
                ),
                f"Import only public interfaces visible to `{caller_owner}`.",
            )
        if rel_member is not None:
            exposed_ok = (
                any(exp in ("*", ".*") for iface in visible_ifaces for exp in iface.expose)
                if rel_member == "*"
                else any(
                    _pattern_matches(exp, rel_member)
                    for iface in visible_ifaces
                    for exp in iface.expose
                )
            )
            if not exposed_ok:
                shown = ", ".join(
                    f"`{exp}`" for iface in visible_ifaces for exp in iface.expose
                ) or "none"
                return (
                    f"Import bypasses `{callee_owner}` public `[[interfaces]]` (`{rel_member}`)",
                    (
                        f"`{caller_owner}` imports unexposed member `{callee_owner}.{rel_member}`; "
                        f"`{config.config_rel}` `[[interfaces]]` exposes only: {shown}."
                    ),
                    f"Import via `{callee_owner}`'s exposed public interface symbols ({shown}).",
                )
    elif callee_rule.strict and callee_owner != "<root>":
        deep_sub = target_mod != callee_owner and target_mod.startswith(f"{callee_owner}.")
        init_all = pkg_dunder_all.get(callee_owner)
        unlisted_sym = (
            rel_member is not None
            and "." not in rel_member
            and init_all is not None
            and rel_member not in init_all
        )
        if deep_sub or unlisted_sym:
            member_desc = f"{callee_owner}.{rel_member}" if rel_member else target_mod
            return (
                f"Strict tach module boundary bypassed (`{member_desc}`)",
                (
                    f"`{caller_owner}` imports `{member_desc}` directly, but `{callee_owner}` "
                    f"sets `strict = true` in `{config.config_rel}`."
                ),
                f"Import public symbols exported at `{callee_owner}` package root (`__all__`).",
            )
    return None


def _is_excluded(rel_posix: str, exclude_patterns: tuple[str, ...]) -> bool:
    for pat in exclude_patterns:
        clean = pat.strip().strip("/")
        if not clean:
            continue
        if rel_posix == clean or rel_posix.startswith(f"{clean}/") or _pattern_matches(
            clean, rel_posix
        ):
            return True
    return False


def _sub_prefix_under_owner(base_mod: str, callee_owner: str, sr_prefix: str) -> str:
    if callee_owner == "<root>":
        return "" if base_mod == "<root>" else base_mod
    norm_base = base_mod
    if sr_prefix and callee_owner.startswith(f"{sr_prefix}.") and not base_mod.startswith(
        f"{sr_prefix}."
    ):
        norm_base = f"{sr_prefix}.{base_mod}"
    if norm_base == callee_owner:
        return ""
    if norm_base.startswith(f"{callee_owner}."):
        return norm_base[len(callee_owner) + 1 :]
    return ""


def _iter_ast_import_refs(
    tree: ast.Module,
    mod_dotted: str,
    sr_prefix: str,
    is_pkg_init: bool,
    config: TachConfig,
    known_modules: set[str],
) -> list[tuple[int, str, str, str | None, str | None]]:
    """Return `(lineno, callee_owner, target_mod, rel_member, imported_sym)` for imports."""
    refs: list[tuple[int, str, str, str | None, str | None]] = []
    mod_parts = [] if mod_dotted == "<root>" else mod_dotted.split(".")
    pkg_parts = mod_parts if is_pkg_init else mod_parts[:-1]
    imported_mod_aliases: dict[str, str] = {}

    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            for alias in node.names:
                raw_name = alias.name.strip()
                if not raw_name:
                    continue
                owner = resolve_owning_tach_module(raw_name, config, sr_prefix)
                if owner is None:
                    continue
                sub = _sub_prefix_under_owner(raw_name, owner, sr_prefix)
                refs.append((node.lineno, owner, raw_name, sub or None, None))
                bind_name = alias.asname or raw_name
                imported_mod_aliases[bind_name] = raw_name
        elif isinstance(node, ast.ImportFrom):
            if node.level > 0:
                if node.level - 1 > len(pkg_parts):
                    continue
                anchor = pkg_parts[: len(pkg_parts) - (node.level - 1)]
                tail = node.module.split(".") if node.module else []
                base_mod = ".".join([*anchor, *tail]) or "<root>"
            else:
                if not node.module:
                    continue
                base_mod = node.module.strip()

            for alias in node.names:
                sym = alias.name.strip()
                if not sym:
                    continue
                cand_submod = sym if base_mod == "<root>" else f"{base_mod}.{sym}"
                submod_exists = sym != "*" and (
                    cand_submod in known_modules
                    or cand_submod in config.modules
                    or (bool(sr_prefix) and f"{sr_prefix}.{cand_submod}" in config.modules)
                )
                if submod_exists:
                    owner = resolve_owning_tach_module(cand_submod, config, sr_prefix)
                    if owner is not None:
                        sub = _sub_prefix_under_owner(cand_submod, owner, sr_prefix)
                        refs.append((node.lineno, owner, cand_submod, sub or None, None))
                        imported_mod_aliases[alias.asname or sym] = cand_submod
                    continue

                owner = resolve_owning_tach_module(base_mod, config, sr_prefix)
                if owner is None:
                    continue
                sub = _sub_prefix_under_owner(base_mod, owner, sr_prefix)
                rel_member = f"{sub}.{sym}" if sub else sym
                concrete_sym = None if sym == "*" else sym
                refs.append((node.lineno, owner, base_mod, rel_member, concrete_sym))

    if imported_mod_aliases and config.interfaces:
        for node in ast.walk(tree):
            if not isinstance(node, ast.Attribute):
                continue
            chain = _dotted_expr(node.value)
            if chain is None:
                continue
            aliased_mod = imported_mod_aliases.get(chain)
            if not aliased_mod:
                continue
            owner = resolve_owning_tach_module(aliased_mod, config, sr_prefix)
            if owner is None:
                continue
            sub = _sub_prefix_under_owner(aliased_mod, owner, sr_prefix)
            rel_member = f"{sub}.{node.attr}" if sub else node.attr
            refs.append((node.lineno, owner, aliased_mod, rel_member, None))

    return refs


def _extract_pkg_reexports(tree: ast.Module, pkg_dotted: str) -> dict[str, tuple[str, str]]:
    """Map exported symbol name -> `(target_module_dotted, original_symbol)` in `__init__.py`."""
    pkg_parts = [] if pkg_dotted == "<root>" else pkg_dotted.split(".")
    reexports: dict[str, tuple[str, str]] = {}
    for node in tree.body:
        if not isinstance(node, ast.ImportFrom):
            continue
        if node.level > 0:
            if node.level - 1 > len(pkg_parts):
                continue
            anchor = pkg_parts[: len(pkg_parts) - (node.level - 1)]
            tail = node.module.split(".") if node.module else []
            base_mod = ".".join([*anchor, *tail]) or "<root>"
        else:
            if not node.module:
                continue
            base_mod = node.module.strip()
        for alias in node.names:
            orig_sym = alias.name.strip()
            if not orig_sym or orig_sym == "*":
                continue
            bound = (alias.asname or orig_sym).strip()
            reexports[bound] = (base_mod, orig_sym)
    return reexports


def _resolve_import_target_file(
    target_mod: str,
    imported_sym: str | None,
    sr_prefix: str,
    mod_to_rel: dict[str, str],
    pkg_reexports: dict[str, dict[str, tuple[str, str]]],
    py_nodes_by_file: dict[str, list[AtlasNode]],
) -> tuple[str | None, str | None]:
    cands = [target_mod]
    if sr_prefix and not target_mod.startswith(f"{sr_prefix}."):
        cands.append(f"{sr_prefix}.{target_mod}")
    dst_rel = next((mod_to_rel[m] for m in cands if m in mod_to_rel), None)
    if dst_rel is None:
        return None, imported_sym
    if imported_sym is not None and dst_rel in pkg_reexports:
        re_entry = pkg_reexports[dst_rel].get(imported_sym)
        if re_entry is not None:
            re_mod, orig_sym = re_entry
            re_cands = [re_mod]
            if sr_prefix and not re_mod.startswith(f"{sr_prefix}."):
                re_cands.append(f"{sr_prefix}.{re_mod}")
            re_rel = next((mod_to_rel[m] for m in re_cands if m in mod_to_rel), None)
            if re_rel is not None and (
                dst_rel not in py_nodes_by_file or re_rel in py_nodes_by_file
            ):
                return re_rel, orig_sym
    return dst_rel, imported_sym


def _dotted_expr(expr: ast.AST) -> str | None:
    parts: list[str] = []
    cur = expr
    while isinstance(cur, ast.Attribute):
        parts.append(cur.attr)
        cur = cur.value
    if isinstance(cur, ast.Name):
        parts.append(cur.id)
        return ".".join(reversed(parts))
    return None


_TACH_ROUTER_MOUNT_ATTRS = frozenset(
    {"include_router", "register_blueprint", "add_api_route", "add_url_rule", "mount"}
)


def _extract_top_level_callables(stmts: list[ast.stmt]) -> frozenset[str]:
    names: set[str] = set()
    for stmt in stmts:
        if isinstance(stmt, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef)):
            names.add(stmt.name)
        elif isinstance(stmt, ast.If):
            names.update(_extract_top_level_callables(stmt.body))
            names.update(_extract_top_level_callables(stmt.orelse))
        elif isinstance(stmt, ast.Try):
            names.update(_extract_top_level_callables(stmt.body))
            for handler in stmt.handlers:
                names.update(_extract_top_level_callables(handler.body))
            names.update(_extract_top_level_callables(stmt.orelse))
            names.update(_extract_top_level_callables(stmt.finalbody))
    return frozenset(names)


def _has_router_mount_call(tree: ast.Module) -> bool:
    return any(
        isinstance(node, ast.Call)
        and isinstance(node.func, ast.Attribute)
        and node.func.attr in _TACH_ROUTER_MOUNT_ATTRS
        for node in ast.walk(tree)
    )


def augment_tach_boundaries(
    repo_root: Path,
    backend_subdir: str,
    result: ManipulatorExtractionResult,
) -> None:
    """Annotate Tier-2 nodes with `tach.toml` domains and flag forbidden boundary imports."""
    tach_path = _find_tach_toml(repo_root, backend_subdir)
    if tach_path is None:
        return

    resolved_root = repo_root.resolve()
    try:
        config = parse_tach_toml(tach_path, resolved_root)
    except (OSError, UnicodeError, tomllib.TOMLDecodeError, ValueError) as exc:
        rel_err = tach_path.relative_to(resolved_root).as_posix()
        result.notes.append(f"Tach boundary parse skipped ({rel_err}): {exc}")
        return

    py_files: list[Path] = []
    seen_files: set[Path] = set()
    for sr in config.source_roots:
        found, _ = source_files(sr, {".py"})
        for fp in found:
            resolved_fp = fp.resolve()
            if resolved_fp in seen_files or not resolved_fp.is_relative_to(resolved_root):
                continue
            rel_posix = resolved_fp.relative_to(resolved_root).as_posix()
            if _is_excluded(rel_posix, config.exclude_patterns):
                continue
            seen_files.add(resolved_fp)
            py_files.append(resolved_fp)

    file_meta: dict[str, tuple[str, str, bool, str | None]] = {}
    known_modules: set[str] = set()
    mod_to_rel: dict[str, str] = {}
    pkg_dunder_all: dict[str, frozenset[str] | None] = {}
    pkg_reexports: dict[str, dict[str, tuple[str, str]]] = {}
    parsed_trees: dict[str, ast.Module] = {}
    callable_defs_by_rel: dict[str, frozenset[str]] = {}

    for fp in py_files:
        rel_posix = fp.relative_to(resolved_root).as_posix()
        info = _dotted_for_file(fp, config)
        if info is None:
            continue
        dotted, sr_prefix, is_pkg_init = info
        known_modules.add(dotted)
        mod_to_rel[dotted] = rel_posix
        if sr_prefix and dotted != "<root>":
            known_modules.add(f"{sr_prefix}.{dotted}")
            mod_to_rel[f"{sr_prefix}.{dotted}"] = rel_posix
        elif sr_prefix and dotted == "<root>":
            mod_to_rel[sr_prefix] = rel_posix
        owner = resolve_owning_tach_module(dotted, config, sr_prefix)
        file_meta[rel_posix] = (dotted, sr_prefix, is_pkg_init, owner)
        try:
            tree = ast.parse(fp.read_text(encoding="utf-8-sig"))
        except (OSError, UnicodeError, SyntaxError, ValueError):
            continue
        parsed_trees[rel_posix] = tree
        callable_defs_by_rel[rel_posix] = (
            frozenset() if _has_router_mount_call(tree) else _extract_top_level_callables(tree.body)
        )
        if is_pkg_init:
            pkg_reexports[rel_posix] = _extract_pkg_reexports(tree, dotted)
        if is_pkg_init and owner is not None and (
            dotted == owner or f"{sr_prefix}.{dotted}" == owner
        ):
            pkg_dunder_all[owner] = _extract_dunder_all(tree)

    nodes_by_file: dict[str, list[AtlasNode]] = {}
    py_manip_nodes_by_file: dict[str, list[AtlasNode]] = {}
    node_by_id: dict[str, AtlasNode] = {}
    owner_first_node_id: dict[str, str] = {}
    mapped_node_count = 0

    for idx, node in enumerate(result.nodes):
        node_by_id[node.id] = node
        nodes_by_file.setdefault(node.source_file, []).append(node)
        if node.tier != "manipulate" or not node.source_file.endswith(".py"):
            continue
        meta = file_meta.get(node.source_file)
        owner = meta[3] if meta else None
        if owner is None:
            abs_cand = (resolved_root / PurePosixPath(node.source_file)).resolve()
            info = _dotted_for_file(abs_cand, config) if abs_cand.is_relative_to(resolved_root) else None
            if info is not None:
                owner = resolve_owning_tach_module(info[0], config, info[1])
        if owner is None:
            continue
        mapped_node_count += 1
        owner_first_node_id.setdefault(owner, node.id)
        rule = config.modules.get(owner)
        qualifiers: list[str] = []
        if rule and rule.layer:
            qualifiers.append(f"layer={rule.layer}")
        if rule and rule.utility:
            qualifiers.append("utility")
        qual_str = f" ({', '.join(qualifiers)})" if qualifiers else ""
        tag = f"[tach:{owner}{qual_str}]"
        new_summary = node.summary if tag in node.summary else f"{node.summary} {tag}"
        note_piece = f"tach module `{owner}`"
        prev_note = node.verification_note
        new_note = (
            prev_note
            if prev_note and note_piece in prev_note
            else f"{prev_note}; {note_piece}"
            if prev_note
            else note_piece
        )
        updated = node.model_copy(update={"summary": new_summary, "verification_note": new_note})
        result.nodes[idx] = updated
        node_by_id[updated.id] = updated
        py_manip_nodes_by_file.setdefault(updated.source_file, []).append(updated)

    checked_cross_imports = 0
    violation_count = 0
    emitted_keys: set[tuple[str, str, str | None]] = set()
    ast_checked_pairs: set[tuple[str, str]] = set()
    pair_symbols: dict[tuple[str, str], set[str]] = {}
    pair_wildcards: set[tuple[str, str]] = set()
    owner_pair_symbols: dict[tuple[str, str], set[str]] = {}
    owner_pair_wildcards: set[tuple[str, str]] = set()
    cross_file_targets: dict[tuple[str, str], tuple[str, str, str]] = {}

    for rel_posix, tree in sorted(parsed_trees.items()):
        dotted, sr_prefix, is_pkg_init, caller_owner = file_meta[rel_posix]
        if caller_owner is None:
            continue
        refs = _iter_ast_import_refs(
            tree, dotted, sr_prefix, is_pkg_init, config, known_modules
        )
        for lineno, callee_owner, target_mod, rel_member, imported_sym in refs:
            dst_rel, resolved_sym = _resolve_import_target_file(
                target_mod,
                imported_sym,
                sr_prefix,
                mod_to_rel,
                pkg_reexports,
                py_manip_nodes_by_file,
            )
            is_callable_sym = (
                dst_rel is not None
                and resolved_sym is not None
                and resolved_sym in callable_defs_by_rel.get(dst_rel, frozenset())
            )
            if dst_rel is not None and dst_rel != rel_posix:
                if is_callable_sym and resolved_sym is not None:
                    pair_symbols.setdefault((rel_posix, dst_rel), set()).add(resolved_sym)
                else:
                    pair_wildcards.add((rel_posix, dst_rel))
                if caller_owner != callee_owner:
                    cross_file_targets.setdefault(
                        (rel_posix, dst_rel), (caller_owner, callee_owner, target_mod)
                    )
            if caller_owner == callee_owner:
                continue
            if is_callable_sym and resolved_sym is not None:
                owner_pair_symbols.setdefault((rel_posix, callee_owner), set()).add(resolved_sym)
            else:
                owner_pair_wildcards.add((rel_posix, callee_owner))
            checked_cross_imports += 1
            ast_checked_pairs.add((rel_posix, callee_owner))
            verdict = _evaluate_import_boundary(
                caller_owner=caller_owner,
                callee_owner=callee_owner,
                target_mod=target_mod,
                rel_member=rel_member,
                config=config,
                pkg_dunder_all=pkg_dunder_all,
            )
            if verdict is None:
                continue
            dedup_key = (rel_posix, callee_owner, rel_member)
            if dedup_key in emitted_keys:
                continue
            emitted_keys.add(dedup_key)
            violation_count += 1
            title, detail, remediation = verdict
            file_nodes = nodes_by_file.get(rel_posix, ())
            src_nid = file_nodes[0].id if file_nodes else None
            dst_nid = owner_first_node_id.get(callee_owner)
            result.findings.append(
                RawCandidateFinding(
                    rule_code="MANIP-006",
                    node_id=src_nid,
                    target_node_id=dst_nid,
                    source_file=rel_posix,
                    line=lineno,
                    title=title,
                    detail=detail,
                    remediation=remediation,
                    confidence="confirmed",
                    evidence_strength="structural_match",
                )
            )

    out_total_by_src: dict[str, int] = {}
    out_scoped_by_src: set[str] = set()
    for existing_edge in result.edges:
        if existing_edge.source_id.startswith(("m:dockerfile:", "m:compose:", "m:k8s:")):
            continue
        out_total_by_src[existing_edge.source_id] = (
            out_total_by_src.get(existing_edge.source_id, 0) + 1
        )
        if existing_edge.symbol_links:
            out_scoped_by_src.add(existing_edge.source_id)
    unscoped_only_nodes = {
        nid for nid, cnt in out_total_by_src.items() if cnt > 0 and nid not in out_scoped_by_src
    }

    existing_helper_pairs: set[tuple[str, str]] = set()
    for edge in result.edges:
        if edge.kind != "calls_helper":
            continue
        existing_helper_pairs.add((edge.source_id, edge.target_id))
        src_node = node_by_id.get(edge.source_id)
        dst_node = node_by_id.get(edge.target_id)
        if src_node is None or dst_node is None:
            continue
        if not src_node.source_file.endswith(".py") or not dst_node.source_file.endswith(".py"):
            continue
        src_owner = _resolve_node_owner(src_node.source_file, resolved_root, config, file_meta)
        dst_owner = _resolve_node_owner(dst_node.source_file, resolved_root, config, file_meta)
        if not edge.symbol_links and dst_node.id not in unscoped_only_nodes:
            fpair = (src_node.source_file, dst_node.source_file)
            if fpair in pair_symbols and fpair not in pair_wildcards:
                edge.symbol_links = [f"*->{s}" for s in sorted(pair_symbols[fpair])]
            elif (
                dst_owner is not None
                and fpair not in pair_wildcards
                and (src_node.source_file, dst_owner) in owner_pair_symbols
                and (src_node.source_file, dst_owner) not in owner_pair_wildcards
            ):
                dst_callables = callable_defs_by_rel.get(dst_node.source_file, frozenset())
                valid_syms = sorted(
                    s
                    for s in owner_pair_symbols[(src_node.source_file, dst_owner)]
                    if s in dst_callables
                )
                if valid_syms:
                    edge.symbol_links = [f"*->{s}" for s in valid_syms]
        if src_owner is None or dst_owner is None or src_owner == dst_owner:
            continue
        if (src_node.source_file, dst_owner) in ast_checked_pairs:
            continue
        checked_cross_imports += 1
        verdict = _evaluate_import_boundary(
            caller_owner=src_owner,
            callee_owner=dst_owner,
            target_mod=dst_owner,
            rel_member=None,
            config=config,
            pkg_dunder_all=pkg_dunder_all,
        )
        if verdict is None:
            continue
        dedup_key = (src_node.source_file, dst_owner, None)
        if dedup_key in emitted_keys:
            continue
        emitted_keys.add(dedup_key)
        violation_count += 1
        title, detail, remediation = verdict
        result.findings.append(
            RawCandidateFinding(
                rule_code="MANIP-006",
                node_id=src_node.id,
                target_node_id=dst_node.id,
                source_file=src_node.source_file,
                line=src_node.line,
                title=title,
                detail=detail,
                remediation=remediation,
                confidence="confirmed",
                evidence_strength="structural_match",
            )
        )

    for (src_rel, dst_rel), (c_owner, d_owner, t_mod) in sorted(cross_file_targets.items()):
        src_nodes = py_manip_nodes_by_file.get(src_rel, ())
        dst_nodes = py_manip_nodes_by_file.get(dst_rel, ())
        if not src_nodes or not dst_nodes:
            continue
        fpair = (src_rel, dst_rel)
        slinks = (
            []
            if fpair in pair_wildcards
            else [f"*->{s}" for s in sorted(pair_symbols.get(fpair, ()))]
        )
        for src_node in src_nodes:
            for dst_node in dst_nodes:
                if src_node.id == dst_node.id or (src_node.id, dst_node.id) in existing_helper_pairs:
                    continue
                existing_helper_pairs.add((src_node.id, dst_node.id))
                eff_slinks = [] if dst_node.id in unscoped_only_nodes else list(slinks)
                result.edges.append(
                    AtlasEdge(
                        id=f"e:tach:{src_node.id}->{dst_node.id}",
                        source_id=src_node.id,
                        target_id=dst_node.id,
                        kind="calls_helper",
                        verification="declared",
                        evidence_path=src_rel,
                        evidence_note=(
                            f"Tach module `{c_owner}` imports `{t_mod}` from `{d_owner}`."
                        ),
                        symbol_links=eff_slinks,
                    )
                )

    result.notes.append(
        f"Tach horizontal boundary check ({config.config_rel}): "
        f"{len(config.modules)} declared module(s), {mapped_node_count} node(s) mapped, "
        f"{checked_cross_imports} cross-module dependency reference(s) checked, "
        f"{violation_count} boundary violation(s)."
    )


def _resolve_node_owner(
    rel_file: str,
    resolved_root: Path,
    config: TachConfig,
    file_meta: dict[str, tuple[str, str, bool, str | None]],
) -> str | None:
    meta = file_meta.get(rel_file)
    if meta is not None:
        return meta[3]
    abs_cand = (resolved_root / PurePosixPath(rel_file)).resolve()
    if not abs_cand.is_relative_to(resolved_root):
        return None
    info = _dotted_for_file(abs_cand, config)
    if info is None:
        return None
    return resolve_owning_tach_module(info[0], config, info[1])
