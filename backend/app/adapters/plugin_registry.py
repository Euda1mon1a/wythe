"""Typed companion plugin protocol and deterministic discovery registry for Wythe.

Security boundary:
- Built-in companion plugins (`tach-boundaries`, `container-sources`) and installed
  Python distributions declaring `entry_points(group="wythe.plugins")` are discovered
  deterministically.
- Scanned target repositories are NEVER imported or executed automatically. Loading an
  explicit local module or `.py` file requires both `local_plugin_modules=[...]` AND
  `allow_local_plugins=True`.
"""

from __future__ import annotations

import importlib
import importlib.metadata
import importlib.util
import sys
from collections.abc import Callable, Collection, Sequence
from dataclasses import dataclass, field
from pathlib import Path
from types import ModuleType
from typing import Literal, Protocol, runtime_checkable

from app import __version__ as WYTHE_BUILTIN_VERSION
from app.adapters.base import ManipulatorExtractionResult, RawCandidateFinding
from app.adapters.tach_bridge import augment_tach_boundaries
from app.schemas.atlas import TruthAtlasReport

ENTRY_POINT_GROUP = "wythe.plugins"

PluginKind = Literal["manipulator_augmenter", "post_scan_check"]
PluginOrigin = Literal["builtin", "entry_point", "local_opt_in"]

ManipulatorHookFn = Callable[[Path, str, ManipulatorExtractionResult], None]
PostScanHookFn = Callable[[Path, TruthAtlasReport], object]

_ORIGIN_ORDER: dict[PluginOrigin, int] = {
    "builtin": 0,
    "entry_point": 1,
    "local_opt_in": 2,
}


@runtime_checkable
class ManipulatorAugmenterPlugin(Protocol):
    """Protocol for Tier-2 post-extraction graph/boundary augmenter plugins."""

    name: str

    def augment_manipulator(
        self,
        repo_root: Path,
        backend_subdir: str,
        result: ManipulatorExtractionResult,
    ) -> None: ...


@runtime_checkable
class PostScanCheckPlugin(Protocol):
    """Protocol for post-scan report inspection plugins."""

    name: str

    def check_report(
        self,
        repo_root: Path,
        report: TruthAtlasReport,
    ) -> object: ...


@dataclass(frozen=True)
class WythePluginSpec:
    """Normalized descriptor and callable hook for a registered Wythe plugin."""

    name: str
    kind: PluginKind
    origin: PluginOrigin = "builtin"
    version: str = ""
    description: str = ""
    enabled_by_default: bool = True
    manipulator_hook: ManipulatorHookFn | None = None
    post_scan_hook: PostScanHookFn | None = None

    def to_metadata(self) -> dict[str, object]:
        """Return JSON-serializable plugin metadata for CLI and API inspection."""
        return {
            "name": self.name,
            "kind": self.kind,
            "origin": self.origin,
            "version": self.version or "unknown",
            "description": self.description,
            "enabled_by_default": self.enabled_by_default,
        }


@dataclass(frozen=True)
class PostScanPluginExecution:
    """Aggregated findings and notes returned by `run_post_scan_plugins`."""

    executed_plugins: list[str] = field(default_factory=list)
    findings: list[RawCandidateFinding] = field(default_factory=list)
    notes: list[str] = field(default_factory=list)


def _builtin_plugin_specs() -> list[WythePluginSpec]:
    specs: list[WythePluginSpec] = []
    try:
        from app.adapters.compose_sources import augment_container_sources
    except ImportError:
        augment_container_sources = None

    if augment_container_sources is not None:
        specs.append(
            WythePluginSpec(
                name="container-sources",
                kind="manipulator_augmenter",
                origin="builtin",
                version=WYTHE_BUILTIN_VERSION,
                description=(
                    "Static Dockerfile, .dockerignore, Compose, and Kubernetes manifest "
                    "source lineage and packaging drift verifier."
                ),
                enabled_by_default=True,
                manipulator_hook=augment_container_sources,
            )
        )

    specs.append(
        WythePluginSpec(
            name="tach-boundaries",
            kind="manipulator_augmenter",
            origin="builtin",
            version=WYTHE_BUILTIN_VERSION,
            description=(
                "Native gauge-sh/tach (tach.toml) horizontal module-boundary and "
                "public interface verifier."
            ),
            enabled_by_default=True,
            manipulator_hook=augment_tach_boundaries,
        )
    )
    return specs


def _coerce_plugin_specs(
    raw_obj: object,
    *,
    default_name: str,
    origin: PluginOrigin,
    default_version: str,
) -> list[WythePluginSpec]:
    if isinstance(raw_obj, ModuleType):
        if hasattr(raw_obj, "WYTHE_PLUGINS"):
            raw_obj = raw_obj.WYTHE_PLUGINS
        elif hasattr(raw_obj, "WYTHE_PLUGIN"):
            raw_obj = raw_obj.WYTHE_PLUGIN
        elif callable(getattr(raw_obj, "wythe_plugin", None)):
            raw_obj = raw_obj.wythe_plugin()
        elif callable(getattr(raw_obj, "register_wythe_plugin", None)):
            raw_obj = raw_obj.register_wythe_plugin()
        else:
            raise TypeError(
                f"Module '{raw_obj.__name__}' defines none of WYTHE_PLUGIN, WYTHE_PLUGINS, "
                "wythe_plugin(), or register_wythe_plugin()."
            )
    elif (
        callable(raw_obj)
        and not isinstance(raw_obj, (WythePluginSpec, ManipulatorAugmenterPlugin, PostScanCheckPlugin))
    ):
        raw_obj = raw_obj()

    items = list(raw_obj) if isinstance(raw_obj, (list, tuple)) else [raw_obj]
    specs: list[WythePluginSpec] = []
    for item in items:
        if isinstance(item, WythePluginSpec):
            specs.append(
                WythePluginSpec(
                    name=item.name or default_name,
                    kind=item.kind,
                    origin=origin,
                    version=item.version or default_version,
                    description=item.description,
                    enabled_by_default=item.enabled_by_default,
                    manipulator_hook=item.manipulator_hook,
                    post_scan_hook=item.post_scan_hook,
                )
            )
            continue
        if isinstance(item, ManipulatorAugmenterPlugin):
            specs.append(
                WythePluginSpec(
                    name=getattr(item, "name", default_name) or default_name,
                    kind="manipulator_augmenter",
                    origin=origin,
                    version=str(getattr(item, "version", default_version)),
                    description=str(getattr(item, "description", "")),
                    enabled_by_default=bool(getattr(item, "enabled_by_default", True)),
                    manipulator_hook=item.augment_manipulator,
                )
            )
            continue
        if isinstance(item, PostScanCheckPlugin):
            specs.append(
                WythePluginSpec(
                    name=getattr(item, "name", default_name) or default_name,
                    kind="post_scan_check",
                    origin=origin,
                    version=str(getattr(item, "version", default_version)),
                    description=str(getattr(item, "description", "")),
                    enabled_by_default=bool(getattr(item, "enabled_by_default", True)),
                    post_scan_hook=item.check_report,
                )
            )
            continue
        raise TypeError(
            f"Unsupported Wythe plugin object of type '{type(item).__name__}' for '{default_name}'."
        )
    return specs


def _load_local_plugin_target(target_spec: str) -> tuple[str, object]:
    raw = target_spec.strip()
    if not raw:
        raise ValueError("Empty local plugin module specification.")
    mod_part, sep, attr_part = raw.partition(":")
    cand_path = Path(mod_part)
    if mod_part.endswith(".py") or "/" in mod_part or "\\" in mod_part:
        if cand_path.is_symlink() or not cand_path.is_file():
            raise ValueError(f"Local plugin file '{mod_part}' must be a regular non-symlink .py file.")
        resolved = cand_path.resolve()
        synthetic_mod_name = f"_wythe_optin_plugin_{abs(hash(str(resolved)))}"
        spec = importlib.util.spec_from_file_location(synthetic_mod_name, resolved)
        if spec is None or spec.loader is None:
            raise ImportError(f"Cannot build import spec for '{resolved}'.")
        mod = importlib.util.module_from_spec(spec)
        sys.modules[synthetic_mod_name] = mod
        spec.loader.exec_module(mod)
        loaded = getattr(mod, attr_part) if sep and attr_part else mod
        return resolved.stem, loaded

    mod = importlib.import_module(mod_part)
    loaded = getattr(mod, attr_part) if sep and attr_part else mod
    default_name = attr_part if sep and attr_part else mod_part.rsplit(".", 1)[-1]
    return default_name, loaded


def discover_plugins(
    *,
    repo_root: Path | None = None,
    include_builtins: bool = True,
    include_entry_points: bool = True,
    allow_local_plugins: bool = False,
    local_plugin_modules: Sequence[str] | None = None,
    strict_plugins: bool = False,
    notes_out: list[str] | None = None,
) -> list[WythePluginSpec]:
    """Discover built-in, installed `entry_points`, and explicit opt-in local plugins.

    Note: `repo_root` is accepted so callers can pass scan context uniformly, but Wythe
    NEVER scans or imports Python files from `repo_root` automatically.
    """
    _ = repo_root  # Never auto-imported; untrusted repo code is strictly non-executable.
    if local_plugin_modules and not allow_local_plugins:
        raise PermissionError(
            "Refusing to load local_plugin_modules without allow_local_plugins=True; "
            "Wythe never executes untrusted repository code by default."
        )

    collected: list[WythePluginSpec] = []
    seen_names: set[str] = set()

    def _register_batch(batch: Sequence[WythePluginSpec]) -> None:
        for spec in batch:
            if spec.name in seen_names:
                if notes_out is not None:
                    notes_out.append(
                        f"Plugin '{spec.name}' ({spec.origin}) skipped: name already registered."
                    )
                continue
            seen_names.add(spec.name)
            collected.append(spec)

    if include_builtins:
        builtins_sorted = sorted(_builtin_plugin_specs(), key=lambda s: s.name)
        _register_batch(builtins_sorted)

    if include_entry_points:
        raw_eps = list(importlib.metadata.entry_points(group=ENTRY_POINT_GROUP))
        raw_eps.sort(key=lambda ep: (ep.name, ep.value))
        ep_specs: list[WythePluginSpec] = []
        for ep in raw_eps:
            dist_ver = getattr(getattr(ep, "dist", None), "version", None) or "unknown"
            try:
                loaded_ep = ep.load()
                ep_specs.extend(
                    _coerce_plugin_specs(
                        loaded_ep,
                        default_name=ep.name,
                        origin="entry_point",
                        default_version=str(dist_ver),
                    )
                )
            except Exception as exc:
                if strict_plugins:
                    raise
                if notes_out is not None:
                    notes_out.append(
                        f"Plugin '{ep.name}' (entry_point) failed to load and was isolated: "
                        f"{type(exc).__name__}: {exc}"
                    )
        ep_specs.sort(key=lambda s: s.name)
        _register_batch(ep_specs)

    if allow_local_plugins and local_plugin_modules:
        local_specs: list[WythePluginSpec] = []
        for target_str in local_plugin_modules:
            try:
                default_name, loaded_local = _load_local_plugin_target(target_str)
                local_specs.extend(
                    _coerce_plugin_specs(
                        loaded_local,
                        default_name=default_name,
                        origin="local_opt_in",
                        default_version="local",
                    )
                )
            except Exception as exc:
                if strict_plugins:
                    raise
                if notes_out is not None:
                    notes_out.append(
                        f"Plugin '{target_str}' (local_opt_in) failed to load and was isolated: "
                        f"{type(exc).__name__}: {exc}"
                    )
        _register_batch(local_specs)

    collected.sort(key=lambda s: (_ORIGIN_ORDER.get(s.origin, 99), s.name))
    return collected


def list_registered_plugins(
    *,
    include_builtins: bool = True,
    include_entry_points: bool = True,
    allow_local_plugins: bool = False,
    local_plugin_modules: Sequence[str] | None = None,
) -> list[dict[str, object]]:
    """Return deterministic, JSON-serializable metadata for all registered plugins."""
    specs = discover_plugins(
        include_builtins=include_builtins,
        include_entry_points=include_entry_points,
        allow_local_plugins=allow_local_plugins,
        local_plugin_modules=local_plugin_modules,
        strict_plugins=False,
    )
    return [spec.to_metadata() for spec in specs]


def _is_spec_enabled(
    spec: WythePluginSpec,
    enabled_names: Collection[str] | None,
    disabled_names: Collection[str] | None,
) -> bool:
    if disabled_names and spec.name in disabled_names:
        return False
    if enabled_names is not None:
        return spec.name in enabled_names
    return spec.enabled_by_default


def run_manipulator_plugins(
    repo_root: Path,
    backend_subdir: str,
    result: ManipulatorExtractionResult,
    *,
    plugins: Sequence[WythePluginSpec] | None = None,
    enabled_names: Collection[str] | None = None,
    disabled_names: Collection[str] | None = None,
    allow_local_plugins: bool = False,
    local_plugin_modules: Sequence[str] | None = None,
    strict_plugins: bool = False,
) -> list[str]:
    """Execute enabled Tier-2 manipulator plugins with deterministic ordering & isolation."""
    specs = (
        list(plugins)
        if plugins is not None
        else discover_plugins(
            repo_root=repo_root,
            allow_local_plugins=allow_local_plugins,
            local_plugin_modules=local_plugin_modules,
            strict_plugins=strict_plugins,
            notes_out=result.notes,
        )
    )
    executed: list[str] = []
    for spec in specs:
        if spec.kind != "manipulator_augmenter" or spec.manipulator_hook is None:
            continue
        if not _is_spec_enabled(spec, enabled_names, disabled_names):
            continue
        snap_nodes = list(result.nodes)
        snap_edges = list(result.edges)
        snap_routes = list(result.routes)
        snap_findings = list(result.findings)
        snap_notes = list(result.notes)
        try:
            spec.manipulator_hook(repo_root, backend_subdir, result)
            executed.append(spec.name)
        except Exception as exc:
            if strict_plugins:
                raise
            result.nodes[:] = snap_nodes
            result.edges[:] = snap_edges
            result.routes[:] = snap_routes
            result.findings[:] = snap_findings
            result.notes[:] = snap_notes
            result.notes.append(
                f"Plugin '{spec.name}' ({spec.origin}) failed during manipulator augmentation "
                f"and was isolated: {type(exc).__name__}: {exc}"
            )
    return executed


def run_post_scan_plugins(
    repo_root: Path,
    report: TruthAtlasReport,
    *,
    plugins: Sequence[WythePluginSpec] | None = None,
    enabled_names: Collection[str] | None = None,
    disabled_names: Collection[str] | None = None,
    allow_local_plugins: bool = False,
    local_plugin_modules: Sequence[str] | None = None,
    strict_plugins: bool = False,
) -> PostScanPluginExecution:
    """Execute enabled post-scan check plugins with error isolation."""
    exec_notes: list[str] = []
    specs = (
        list(plugins)
        if plugins is not None
        else discover_plugins(
            repo_root=repo_root,
            allow_local_plugins=allow_local_plugins,
            local_plugin_modules=local_plugin_modules,
            strict_plugins=strict_plugins,
            notes_out=exec_notes,
        )
    )
    executed: list[str] = []
    collected_findings: list[RawCandidateFinding] = []

    for spec in specs:
        if spec.kind != "post_scan_check" or spec.post_scan_hook is None:
            continue
        if not _is_spec_enabled(spec, enabled_names, disabled_names):
            continue
        try:
            outcome = spec.post_scan_hook(repo_root, report)
            executed.append(spec.name)
            if isinstance(outcome, PostScanPluginExecution):
                collected_findings.extend(outcome.findings)
                exec_notes.extend(outcome.notes)
            elif isinstance(outcome, (list, tuple)):
                for item in outcome:
                    if isinstance(item, RawCandidateFinding):
                        collected_findings.append(item)
                    elif isinstance(item, str):
                        exec_notes.append(item)
        except Exception as exc:
            if strict_plugins:
                raise
            exec_notes.append(
                f"Plugin '{spec.name}' ({spec.origin}) failed during post-scan check and was "
                f"isolated: {type(exc).__name__}: {exc}"
            )

    for note in exec_notes:
        if note not in report.scan_notes:
            report.scan_notes.append(note)

    return PostScanPluginExecution(
        executed_plugins=executed,
        findings=collected_findings,
        notes=exec_notes,
    )
