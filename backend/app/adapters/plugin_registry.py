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
import inspect
import sys
from collections.abc import Callable, Collection, Iterator, Sequence
from contextlib import contextmanager
from contextvars import ContextVar
from dataclasses import dataclass, field
from pathlib import Path
from types import ModuleType
from typing import Any, Literal, Protocol, runtime_checkable

from app import __version__ as WYTHE_BUILTIN_VERSION
from app.adapters.base import AdapterRegistry, ManipulatorExtractionResult, RawCandidateFinding
from app.adapters.tach_bridge import augment_tach_boundaries
from app.schemas.atlas import (
    EvidenceSourceKind,
    EvidenceStrength,
    FindingConfidence,
    MicroStratumZoom,
    StratumExpansionResult,
    StratumSummaryBadge,
    TierKind,
    TruthAtlasReport,
)

ENTRY_POINT_GROUP = "wythe.plugins"

PluginKind = Literal[
    "manipulator_augmenter",
    "post_scan_check",
    "stratum_inspector",
    "stack_adapter",
]
PluginOrigin = Literal["builtin", "entry_point", "local_opt_in"]

ManipulatorHookFn = Callable[[Path, str, ManipulatorExtractionResult], None]
PostScanHookFn = Callable[[Path, TruthAtlasReport], object]
StratumBadgeHookFn = Callable[[Path, TruthAtlasReport], dict[str, list[StratumSummaryBadge]]]
StratumExpandHookFn = Callable[
    [Path, TruthAtlasReport, str, MicroStratumZoom],
    StratumExpansionResult,
]

_ORIGIN_ORDER: dict[PluginOrigin, int] = {
    "builtin": 0,
    "entry_point": 1,
    "local_opt_in": 2,
}
_VALID_TIERS = ("truth", "manipulate", "display")
_VALID_SEVERITIES = ("blocking", "warning")
_VALID_CONFIDENCES = ("confirmed", "candidate")
_VALID_STRENGTHS = ("ast_exact", "structural_match", "heuristic")
_VALID_MATURITIES = ("implemented", "experimental")

_ACTIVE_STRATUM_ARTIFACTS: ContextVar[tuple[tuple[str, tuple[str, ...]], ...]] = ContextVar(
    "wythe_active_stratum_artifacts",
    default=(),
)


def _normalize_artifact_tuple(raw_val: object) -> tuple[str, ...]:
    if raw_val is None:
        return ()
    if isinstance(raw_val, (str, Path)):
        cleaned = str(raw_val).strip()
        return (cleaned,) if cleaned else ()
    if isinstance(raw_val, (bytes, bytearray)):
        raise TypeError("Stratum artifact paths must be str or Path sequences, not bytes.")
    if isinstance(raw_val, Sequence):
        items: list[str] = []
        for item in raw_val:
            if item is None:
                continue
            cleaned = str(item).strip()
            if cleaned and cleaned not in items:
                items.append(cleaned)
        return tuple(items)
    cleaned = str(raw_val).strip()
    return (cleaned,) if cleaned else ()


@contextmanager
def stratum_artifacts_scope(**artifact_paths: str | Path | Sequence[str | Path] | None) -> Iterator[dict[str, tuple[str, ...]]]:
    """Bind thread/async-safe read-only artifact paths (`index_store`, `sil`, `binary`, etc.)."""
    merged: dict[str, tuple[str, ...]] = dict(_ACTIVE_STRATUM_ARTIFACTS.get())
    for raw_key, raw_val in artifact_paths.items():
        clean_key = str(raw_key).strip()
        if not clean_key or raw_val is None:
            continue
        norm_vals = _normalize_artifact_tuple(raw_val)
        if norm_vals:
            merged[clean_key] = norm_vals
        else:
            merged.pop(clean_key, None)
    frozen_items = tuple(sorted(merged.items()))
    ctx_handle = _ACTIVE_STRATUM_ARTIFACTS.set(frozen_items)
    try:
        yield dict(frozen_items)
    finally:
        _ACTIVE_STRATUM_ARTIFACTS.reset(ctx_handle)


def get_active_stratum_artifacts() -> dict[str, tuple[str, ...]]:
    """Return a copy of active read-only stratum artifact path tuples in the current context."""
    return {k: tuple(v) for k, v in _ACTIVE_STRATUM_ARTIFACTS.get()}


@dataclass(frozen=True)
class PluginStackProfileSpec:
    """Optional plugin-contributed 3-tier stack profile descriptor."""

    slug: str
    name: str
    truth_adapter: str
    manipulator_adapter: str
    display_adapter: str
    maturity_status: Literal["implemented", "experimental"] = "implemented"
    description: str = ""


@dataclass(frozen=True)
class PluginRuleSpec:
    """Optional plugin-contributed architectural rule policy descriptor."""

    rule_code: str
    tier: TierKind
    title: str
    severity: Literal["blocking", "warning"] = "warning"
    blocks_gate: bool = False
    enabled: bool = True
    confidence: FindingConfidence = "confirmed"
    evidence_strength: EvidenceStrength = "ast_exact"


@dataclass(frozen=True)
class PluginMcpToolSpec:
    """Optional plugin-contributed MCP tool schema and handler."""

    name: str
    definition: dict[str, Any]
    handler: Callable[[Any, dict[str, Any]], Any]


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


@runtime_checkable
class StratumPlugin(Protocol):
    """Protocol for read-only progressive LOD microscope (Zoom 2 / Zoom 3) plugins."""

    name: str
    supported_zooms: tuple[int, ...] = (2, 3)

    def summarize_zoom1_badges(
        self,
        repo_root: Path,
        report: TruthAtlasReport,
    ) -> dict[str, list[StratumSummaryBadge]]: ...

    def expand_node_stratum(
        self,
        repo_root: Path,
        report: TruthAtlasReport,
        node_id: str,
        zoom: Literal[2, 3],
    ) -> StratumExpansionResult: ...


_ALL_INTERACTION_CAPABILITIES: tuple[str, ...] = (
    "findings",
    "structured_evidence",
    "provenance",
    "stable_references",
    "zoom_stratum_projection",
    "viewport_timeline",
    "mcp_tools",
    "cli_companion",
)


@dataclass(frozen=True)
class WythePluginSpec:
    """Normalized descriptor and callable hook for a registered Wythe plugin."""

    name: str
    kind: PluginKind
    origin: PluginOrigin = "builtin"
    version: str = ""
    description: str = ""
    enabled_by_default: bool = True
    supported_zooms: tuple[int, ...] = ()
    manipulator_hook: ManipulatorHookFn | None = None
    post_scan_hook: PostScanHookFn | None = None
    stratum_badge_hook: StratumBadgeHookFn | None = None
    stratum_expand_hook: StratumExpandHookFn | None = None
    rules: tuple[PluginRuleSpec, ...] = ()
    mcp_tools: tuple[PluginMcpToolSpec, ...] = ()
    cli_subcommands: dict[str, Callable[[list[str]], int]] = field(default_factory=dict)
    companion_handlers: dict[str, Callable[..., Any]] = field(default_factory=dict)
    truth_adapters: tuple[Any, ...] = ()
    manipulator_adapters: tuple[Any, ...] = ()
    display_adapters: tuple[Any, ...] = ()
    stack_profiles: tuple[PluginStackProfileSpec, ...] = ()
    interaction_capabilities: tuple[str, ...] = ()
    evidence_source_kinds: tuple[EvidenceSourceKind, ...] = ()

    def resolved_interaction_capabilities(self) -> tuple[list[str], list[str]]:
        """Return `(supported_capabilities, unsupported_capabilities)` for discovery."""
        if self.interaction_capabilities:
            supported = list(dict.fromkeys(self.interaction_capabilities))
        else:
            supported = ["structured_evidence", "provenance", "stable_references"]
            if (
                self.rules
                or self.kind in ("manipulator_augmenter", "post_scan_check", "stack_adapter")
                or self.manipulator_hook is not None
                or self.post_scan_hook is not None
            ):
                supported.insert(0, "findings")
            if (
                self.kind == "stratum_inspector"
                or self.stratum_badge_hook is not None
                or self.stratum_expand_hook is not None
            ):
                supported.append("zoom_stratum_projection")
            if "chronicle" in self.name.lower() or "watch-solver" in self.cli_subcommands:
                supported.append("viewport_timeline")
            if self.mcp_tools:
                supported.append("mcp_tools")
            if self.cli_subcommands or self.companion_handlers:
                supported.append("cli_companion")
        unsupported = [cap for cap in _ALL_INTERACTION_CAPABILITIES if cap not in supported]
        return supported, unsupported

    def resolved_evidence_source_kinds(self) -> list[EvidenceSourceKind]:
        """Return the evidence source regimes (`source_static`, `compiled_artifact`, `runtime_capture`)."""
        if self.evidence_source_kinds:
            return list(dict.fromkeys(self.evidence_source_kinds))
        low = self.name.lower()
        kinds: list[EvidenceSourceKind] = ["source_static"]
        if (
            any(tok in low for tok in ("compiler-ir", "binary", "cpsat", "solver-internals"))
            or bool(self.companion_handlers)
        ):
            kinds.append("compiled_artifact")
        if any(tok in low for tok in ("chronicle", "wiretap", "telemetry")) or "watch-solver" in self.cli_subcommands:
            kinds.append("runtime_capture")
        return kinds

    def to_metadata(self) -> dict[str, object]:
        """Return JSON-serializable plugin metadata for CLI and API inspection."""
        tier_adapter_names = [
            str(getattr(a, "name", ""))
            for a in (*self.truth_adapters, *self.manipulator_adapters, *self.display_adapters)
            if getattr(a, "name", None)
        ]
        supported_caps, unsupported_caps = self.resolved_interaction_capabilities()
        meta: dict[str, object] = {
            "name": self.name,
            "kind": self.kind,
            "origin": self.origin,
            "version": self.version or "unknown",
            "description": self.description,
            "enabled_by_default": self.enabled_by_default,
            "rules": [r.rule_code for r in self.rules],
            "mcp_tools": [t.name for t in self.mcp_tools],
            "cli_subcommands": sorted(self.cli_subcommands),
            "stack_profiles": [p.slug for p in self.stack_profiles],
            "tier_adapters": tier_adapter_names,
            "interaction_capabilities": supported_caps,
            "unsupported_interaction_capabilities": unsupported_caps,
            "evidence_source_kinds": self.resolved_evidence_source_kinds(),
        }
        if (
            self.kind == "stratum_inspector"
            or self.stratum_badge_hook is not None
            or self.stratum_expand_hook is not None
        ):
            meta["supported_zooms"] = list(self.supported_zooms or (2, 3))
        return meta


@dataclass(frozen=True)
class PostScanPluginExecution:
    """Aggregated findings and notes returned by `run_post_scan_plugins`."""

    executed_plugins: list[str] = field(default_factory=list)
    findings: list[RawCandidateFinding] = field(default_factory=list)
    notes: list[str] = field(default_factory=list)


@dataclass(frozen=True)
class StratumBadgePluginExecution:
    """Aggregated Zoom-1 summary badges and notes returned by `run_stratum_badge_plugins`."""

    executed_plugins: list[str] = field(default_factory=list)
    badges_by_node: dict[str, list[StratumSummaryBadge]] = field(default_factory=dict)
    notes: list[str] = field(default_factory=list)


@dataclass(frozen=True)
class StratumExpandPluginExecution:
    """Aggregated Zoom-2/Zoom-3 expansion payloads returned by `run_stratum_expand_plugins`."""

    executed_plugins: list[str] = field(default_factory=list)
    expansions: list[StratumExpansionResult] = field(default_factory=list)
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


def _normalize_supported_zooms(raw_zooms: object) -> tuple[int, ...]:
    if raw_zooms is None:
        return (2, 3)
    if isinstance(raw_zooms, (list, tuple, set, frozenset)):
        cleaned = tuple(
            sorted(
                {
                    int(z)
                    for z in raw_zooms
                    if isinstance(z, int) and not isinstance(z, bool) and z in (2, 3)
                }
            )
        )
        return cleaned or (2, 3)
    return (2, 3)


def _is_stratum_plugin_instance(obj: object) -> bool:
    if isinstance(obj, type):
        return False
    if isinstance(obj, StratumPlugin):
        return True
    return bool(
        getattr(obj, "name", None)
        and callable(getattr(obj, "summarize_zoom1_badges", None))
        and callable(getattr(obj, "expand_node_stratum", None))
    )


def _coerce_rule_specs(raw_rules: object) -> tuple[PluginRuleSpec, ...]:
    if not raw_rules or not isinstance(raw_rules, (list, tuple)):
        return ()
    out: list[PluginRuleSpec] = []
    seen_codes: set[str] = set()
    for entry in raw_rules:
        if isinstance(entry, PluginRuleSpec):
            spec = entry
        elif isinstance(entry, dict):
            code = str(entry.get("rule_code") or "").strip()
            tier = entry.get("tier")
            title = str(entry.get("title") or "").strip()
            if not code or tier not in _VALID_TIERS or not title:
                raise ValueError(
                    f"Invalid plugin rule dict (expected rule_code, valid tier, title): {entry!r}"
                )
            severity = entry.get("severity", "warning")
            if severity not in _VALID_SEVERITIES:
                raise ValueError(f"Invalid plugin rule severity {severity!r} for '{code}'.")
            conf = entry.get("confidence", "confirmed")
            if conf not in _VALID_CONFIDENCES:
                raise ValueError(f"Invalid plugin rule confidence {conf!r} for '{code}'.")
            strength = entry.get("evidence_strength", "ast_exact")
            if strength not in _VALID_STRENGTHS:
                raise ValueError(f"Invalid plugin rule evidence_strength {strength!r} for '{code}'.")
            spec = PluginRuleSpec(
                rule_code=code,
                tier=tier,  # type: ignore[arg-type]
                title=title,
                severity=severity,  # type: ignore[arg-type]
                blocks_gate=bool(entry.get("blocks_gate", False)),
                enabled=bool(entry.get("enabled", True)),
                confidence=conf,  # type: ignore[arg-type]
                evidence_strength=strength,  # type: ignore[arg-type]
            )
        else:
            raise TypeError(f"Unsupported plugin rule descriptor of type '{type(entry).__name__}'.")
        if spec.rule_code not in seen_codes:
            seen_codes.add(spec.rule_code)
            out.append(spec)
    return tuple(out)


def _coerce_mcp_tool_specs(raw_tools: object) -> tuple[PluginMcpToolSpec, ...]:
    if not raw_tools or not isinstance(raw_tools, (list, tuple)):
        return ()
    out: list[PluginMcpToolSpec] = []
    seen_names: set[str] = set()
    for entry in raw_tools:
        if isinstance(entry, PluginMcpToolSpec):
            t_def = dict(entry.definition)
            t_def.setdefault("name", entry.name)
            spec = PluginMcpToolSpec(name=entry.name, definition=t_def, handler=entry.handler)
        elif isinstance(entry, dict):
            raw_def = entry.get("definition") or entry.get("schema")
            if not isinstance(raw_def, dict):
                raise TypeError(f"Plugin MCP tool dict missing 'definition' dict: {entry!r}")
            t_name = str(entry.get("name") or raw_def.get("name") or "").strip()
            handler = entry.get("handler")
            if not t_name or not callable(handler):
                raise ValueError(f"Plugin MCP tool dict requires 'name' and callable 'handler': {entry!r}")
            t_def = dict(raw_def)
            t_def.setdefault("name", t_name)
            spec = PluginMcpToolSpec(name=t_name, definition=t_def, handler=handler)
        else:
            raise TypeError(f"Unsupported plugin MCP tool descriptor of type '{type(entry).__name__}'.")
        if spec.name not in seen_names:
            seen_names.add(spec.name)
            out.append(spec)
    return tuple(out)


def _coerce_callable_map(raw_map: object, *, label: str) -> dict[str, Callable[..., Any]]:
    if not raw_map:
        return {}
    if not isinstance(raw_map, dict):
        raise TypeError(f"Plugin '{label}' must be a dict mapping string keys to callables.")
    out: dict[str, Callable[..., Any]] = {}
    for k, fn in raw_map.items():
        clean_k = str(k).strip()
        if not clean_k or not callable(fn):
            raise ValueError(f"Invalid entry {k!r} in plugin '{label}'; expected non-empty str -> callable.")
        out[clean_k] = fn
    return out


def _coerce_tier_adapters(raw_adapters: object, *, label: str) -> tuple[Any, ...]:
    if not raw_adapters:
        return ()
    if not isinstance(raw_adapters, (list, tuple)):
        raise TypeError(f"Plugin '{label}' must be a list or tuple of tier adapter objects.")
    out: list[Any] = []
    seen_names: set[str] = set()
    for entry in raw_adapters:
        inst = entry() if isinstance(entry, type) else entry
        a_name = str(getattr(inst, "name", "") or "").strip()
        if not a_name or not callable(getattr(inst, "extract", None)):
            raise ValueError(
                f"Invalid adapter in '{label}': expected non-empty .name and callable .extract(...)."
            )
        if a_name not in seen_names:
            seen_names.add(a_name)
            out.append(inst)
    return tuple(out)


def _coerce_stack_profile_specs(raw_profiles: object) -> tuple[PluginStackProfileSpec, ...]:
    if not raw_profiles:
        return ()
    if not isinstance(raw_profiles, (list, tuple)):
        raise TypeError("Plugin 'stack_profiles' must be a list or tuple.")
    out: list[PluginStackProfileSpec] = []
    seen_slugs: set[str] = set()
    for entry in raw_profiles:
        if isinstance(entry, PluginStackProfileSpec):
            prof = entry
        elif isinstance(entry, dict):
            slug = str(entry.get("slug") or "").strip()
            name = str(entry.get("name") or entry.get("label") or "").strip()
            t_ad = str(entry.get("truth_adapter") or "").strip()
            m_ad = str(entry.get("manipulator_adapter") or "").strip()
            d_ad = str(entry.get("display_adapter") or "").strip()
            if not (slug and name and t_ad and m_ad and d_ad):
                raise ValueError(f"Invalid PluginStackProfileSpec dict: {entry!r}")
            mat = entry.get("maturity_status", "implemented")
            if mat not in _VALID_MATURITIES:
                raise ValueError(f"Invalid PluginStackProfileSpec maturity_status {mat!r}")
            prof = PluginStackProfileSpec(
                slug=slug,
                name=name,
                truth_adapter=t_ad,
                manipulator_adapter=m_ad,
                display_adapter=d_ad,
                maturity_status=mat,  # type: ignore[arg-type]
                description=str(entry.get("description") or ""),
            )
        else:
            raise TypeError(
                f"Unsupported stack_profiles entry of type '{type(entry).__name__}'."
            )
        if prof.slug not in seen_slugs:
            seen_slugs.add(prof.slug)
            out.append(prof)
    return tuple(out)


def _has_plugin_extension_attrs(obj: object) -> bool:
    return bool(
        getattr(obj, "plugin_rules", None)
        or getattr(obj, "rules", None)
        or getattr(obj, "mcp_tools", None)
        or getattr(obj, "cli_subcommands", None)
        or getattr(obj, "companion_handlers", None)
        or getattr(obj, "truth_adapters", None)
        or getattr(obj, "manipulator_adapters", None)
        or getattr(obj, "display_adapters", None)
        or getattr(obj, "stack_profiles", None)
    )


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
    elif isinstance(raw_obj, type) or (
        callable(raw_obj)
        and not isinstance(
            raw_obj,
            (WythePluginSpec, ManipulatorAugmenterPlugin, PostScanCheckPlugin, StratumPlugin),
        )
        and not _is_stratum_plugin_instance(raw_obj)
        and not _has_plugin_extension_attrs(raw_obj)
    ):
        raw_obj = raw_obj()

    items = list(raw_obj) if isinstance(raw_obj, (list, tuple)) else [raw_obj]
    specs: list[WythePluginSpec] = []
    for item in items:
        if isinstance(item, type):
            item = item()
        if isinstance(item, WythePluginSpec):
            has_stratum_hooks = (
                item.kind == "stratum_inspector"
                or item.stratum_badge_hook is not None
                or item.stratum_expand_hook is not None
            )
            zooms = (
                _normalize_supported_zooms(item.supported_zooms or None)
                if has_stratum_hooks
                else item.supported_zooms
            )
            raw_spec_rules = item.rules or getattr(item, "plugin_rules", ())
            specs.append(
                WythePluginSpec(
                    name=item.name or default_name,
                    kind=item.kind,
                    origin=origin,
                    version=item.version or default_version,
                    description=item.description,
                    enabled_by_default=item.enabled_by_default,
                    supported_zooms=zooms,
                    manipulator_hook=item.manipulator_hook,
                    post_scan_hook=item.post_scan_hook,
                    stratum_badge_hook=item.stratum_badge_hook,
                    stratum_expand_hook=item.stratum_expand_hook,
                    rules=_coerce_rule_specs(raw_spec_rules),
                    mcp_tools=_coerce_mcp_tool_specs(item.mcp_tools),
                    cli_subcommands=_coerce_callable_map(item.cli_subcommands, label="cli_subcommands"),
                    companion_handlers=_coerce_callable_map(
                        item.companion_handlers, label="companion_handlers"
                    ),
                    truth_adapters=_coerce_tier_adapters(
                        item.truth_adapters, label="truth_adapters"
                    ),
                    manipulator_adapters=_coerce_tier_adapters(
                        item.manipulator_adapters, label="manipulator_adapters"
                    ),
                    display_adapters=_coerce_tier_adapters(
                        item.display_adapters, label="display_adapters"
                    ),
                    stack_profiles=_coerce_stack_profile_specs(item.stack_profiles),
                )
            )
            continue

        has_stratum = _is_stratum_plugin_instance(item)
        has_manip = isinstance(item, ManipulatorAugmenterPlugin) or callable(
            getattr(item, "augment_manipulator", None)
        )
        has_post = isinstance(item, PostScanCheckPlugin) or callable(
            getattr(item, "check_report", None)
        )
        rules = _coerce_rule_specs(
            getattr(item, "plugin_rules", None) or getattr(item, "rules", ())
        )
        mcp_tools = _coerce_mcp_tool_specs(getattr(item, "mcp_tools", ()))
        cli_subcommands = _coerce_callable_map(
            getattr(item, "cli_subcommands", {}), label="cli_subcommands"
        )
        companion_handlers = _coerce_callable_map(
            getattr(item, "companion_handlers", {}), label="companion_handlers"
        )
        t_adapters = _coerce_tier_adapters(
            getattr(item, "truth_adapters", ()), label="truth_adapters"
        )
        m_adapters = _coerce_tier_adapters(
            getattr(item, "manipulator_adapters", ()), label="manipulator_adapters"
        )
        d_adapters = _coerce_tier_adapters(
            getattr(item, "display_adapters", ()), label="display_adapters"
        )
        s_profiles = _coerce_stack_profile_specs(getattr(item, "stack_profiles", ()))
        has_stack = bool(t_adapters or m_adapters or d_adapters or s_profiles)

        if not (
            has_stratum
            or has_manip
            or has_post
            or has_stack
            or rules
            or mcp_tools
            or cli_subcommands
            or companion_handlers
        ):
            raise TypeError(
                f"Unsupported Wythe plugin object of type '{type(item).__name__}' for '{default_name}'."
            )

        explicit_kind = getattr(item, "kind", None)
        if explicit_kind in (
            "manipulator_augmenter",
            "post_scan_check",
            "stratum_inspector",
            "stack_adapter",
        ):
            primary_kind: PluginKind = explicit_kind
        elif has_stack:
            primary_kind = "stack_adapter"
        elif has_stratum:
            primary_kind = "stratum_inspector"
        elif has_manip:
            primary_kind = "manipulator_augmenter"
        else:
            primary_kind = "post_scan_check"

        specs.append(
            WythePluginSpec(
                name=str(getattr(item, "name", default_name) or default_name),
                kind=primary_kind,
                origin=origin,
                version=str(getattr(item, "version", default_version) or default_version),
                description=str(getattr(item, "description", "")),
                enabled_by_default=bool(getattr(item, "enabled_by_default", True)),
                supported_zooms=(
                    _normalize_supported_zooms(getattr(item, "supported_zooms", (2, 3)))
                    if has_stratum
                    else ()
                ),
                manipulator_hook=(
                    item.augment_manipulator if has_manip else None  # type: ignore[attr-defined]
                ),
                post_scan_hook=(
                    item.check_report if has_post else None  # type: ignore[attr-defined]
                ),
                stratum_badge_hook=(
                    item.summarize_zoom1_badges if has_stratum else None  # type: ignore[attr-defined]
                ),
                stratum_expand_hook=(
                    item.expand_node_stratum if has_stratum else None  # type: ignore[attr-defined]
                ),
                rules=rules,
                mcp_tools=mcp_tools,
                cli_subcommands=cli_subcommands,
                companion_handlers=companion_handlers,
                truth_adapters=t_adapters,
                manipulator_adapters=m_adapters,
                display_adapters=d_adapters,
                stack_profiles=s_profiles,
            )
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
        if spec.manipulator_hook is None:
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


def _coerce_raw_finding(item: object) -> RawCandidateFinding | None:
    if isinstance(item, RawCandidateFinding):
        return item
    if isinstance(item, dict) and item.get("rule_code"):
        valid_fields = set(RawCandidateFinding.__dataclass_fields__)
        filtered = {k: v for k, v in item.items() if k in valid_fields}
        return RawCandidateFinding(**filtered)
    return None


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
        if spec.post_scan_hook is None:
            continue
        if not _is_spec_enabled(spec, enabled_names, disabled_names):
            continue
        try:
            outcome = spec.post_scan_hook(repo_root, report.model_copy(deep=True))
            executed.append(spec.name)
            if isinstance(outcome, PostScanPluginExecution):
                collected_findings.extend(outcome.findings)
                exec_notes.extend(outcome.notes)
            elif isinstance(outcome, dict):
                raw_f = outcome.get("findings")
                if isinstance(raw_f, (list, tuple)):
                    for f_item in raw_f:
                        coerced_f = _coerce_raw_finding(f_item)
                        if coerced_f is not None:
                            collected_findings.append(coerced_f)
                raw_n = outcome.get("notes")
                if isinstance(raw_n, (list, tuple)):
                    exec_notes.extend(str(n) for n in raw_n if isinstance(n, str) and n)
                elif isinstance(raw_n, str) and raw_n:
                    exec_notes.append(raw_n)
            elif isinstance(outcome, (list, tuple)):
                for item in outcome:
                    coerced_f = _coerce_raw_finding(item)
                    if coerced_f is not None:
                        collected_findings.append(coerced_f)
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


def has_enabled_stratum_plugins(
    *,
    plugins: Sequence[WythePluginSpec] | None = None,
    enabled_names: Collection[str] | None = None,
    disabled_names: Collection[str] | None = None,
    allow_local_plugins: bool = False,
    local_plugin_modules: Sequence[str] | None = None,
) -> bool:
    """Return True when at least one `stratum_inspector` plugin is discovered and enabled."""
    specs = (
        list(plugins)
        if plugins is not None
        else discover_plugins(
            allow_local_plugins=allow_local_plugins,
            local_plugin_modules=local_plugin_modules,
            strict_plugins=False,
        )
    )
    return any(
        (
            spec.kind == "stratum_inspector"
            or spec.stratum_badge_hook is not None
            or spec.stratum_expand_hook is not None
        )
        and _is_spec_enabled(spec, enabled_names, disabled_names)
        for spec in specs
    )


def run_stratum_badge_plugins(
    repo_root: Path,
    report: TruthAtlasReport,
    *,
    plugins: Sequence[WythePluginSpec] | None = None,
    enabled_names: Collection[str] | None = None,
    disabled_names: Collection[str] | None = None,
    allow_local_plugins: bool = False,
    local_plugin_modules: Sequence[str] | None = None,
    strict_plugins: bool = False,
) -> StratumBadgePluginExecution:
    """Collect compact Zoom-1 badges from enabled `StratumPlugin`s with fault & mutation isolation."""
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
    merged: dict[str, list[StratumSummaryBadge]] = {}

    for spec in specs:
        if spec.stratum_badge_hook is None:
            continue
        if not _is_spec_enabled(spec, enabled_names, disabled_names):
            continue
        try:
            isolated_report = report.model_copy(deep=True)
            raw_badges = spec.stratum_badge_hook(repo_root, isolated_report)
            executed.append(spec.name)
            if isinstance(raw_badges, dict):
                for nid, badge_list in raw_badges.items():
                    if not isinstance(nid, str) or not isinstance(badge_list, (list, tuple)):
                        continue
                    dest = merged.setdefault(nid, [])
                    for badge in badge_list:
                        if isinstance(badge, StratumSummaryBadge):
                            dest.append(badge)
                        elif isinstance(badge, dict):
                            dest.append(StratumSummaryBadge.model_validate(badge))
        except Exception as exc:
            if strict_plugins:
                raise
            exec_notes.append(
                f"Plugin '{spec.name}' ({spec.origin}) failed during Zoom-1 stratum badge "
                f"summary and was isolated: {type(exc).__name__}: {exc}"
            )

    return StratumBadgePluginExecution(
        executed_plugins=executed,
        badges_by_node=merged,
        notes=exec_notes,
    )


def run_stratum_expand_plugins(
    repo_root: Path,
    report: TruthAtlasReport,
    node_id: str,
    zoom: MicroStratumZoom,
    *,
    plugins: Sequence[WythePluginSpec] | None = None,
    enabled_names: Collection[str] | None = None,
    disabled_names: Collection[str] | None = None,
    allow_local_plugins: bool = False,
    local_plugin_modules: Sequence[str] | None = None,
    strict_plugins: bool = False,
) -> StratumExpandPluginExecution:
    """Execute enabled `StratumPlugin.expand_node_stratum` hooks with fault & mutation isolation."""
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
    expansions: list[StratumExpansionResult] = []

    for spec in specs:
        if spec.stratum_expand_hook is None:
            continue
        if not _is_spec_enabled(spec, enabled_names, disabled_names):
            continue
        supported = spec.supported_zooms or (2, 3)
        if zoom not in supported:
            continue
        try:
            isolated_report = report.model_copy(deep=True)
            res = spec.stratum_expand_hook(repo_root, isolated_report, node_id, zoom)
            executed.append(spec.name)
            if isinstance(res, StratumExpansionResult):
                expansions.append(res)
            elif isinstance(res, dict):
                expansions.append(StratumExpansionResult.model_validate(res))
        except Exception as exc:
            if strict_plugins:
                raise
            exec_notes.append(
                f"Plugin '{spec.name}' ({spec.origin}) failed during Zoom-{zoom} stratum "
                f"expansion for '{node_id}' and was isolated: {type(exc).__name__}: {exc}"
            )

    return StratumExpandPluginExecution(
        executed_plugins=executed,
        expansions=expansions,
        notes=exec_notes,
    )


def collect_enabled_plugin_rules(
    *,
    repo_root: Path | None = None,
    plugins: Sequence[WythePluginSpec] | None = None,
    enabled_names: Collection[str] | None = None,
    disabled_names: Collection[str] | None = None,
    allow_local_plugins: bool = False,
    local_plugin_modules: Sequence[str] | None = None,
    strict_plugins: bool = False,
    notes_out: list[str] | None = None,
) -> list[PluginRuleSpec]:
    """Collect deduplicated `PluginRuleSpec` descriptors from enabled plugins."""
    specs = (
        list(plugins)
        if plugins is not None
        else discover_plugins(
            repo_root=repo_root,
            allow_local_plugins=allow_local_plugins,
            local_plugin_modules=local_plugin_modules,
            strict_plugins=strict_plugins,
            notes_out=notes_out,
        )
    )
    out: list[PluginRuleSpec] = []
    seen_codes: set[str] = set()
    for spec in specs:
        if not _is_spec_enabled(spec, enabled_names, disabled_names):
            continue
        for rule in spec.rules:
            if rule.rule_code not in seen_codes:
                seen_codes.add(rule.rule_code)
                out.append(rule)
    return out


def collect_enabled_plugin_mcp_tools(
    *,
    plugins: Sequence[WythePluginSpec] | None = None,
    enabled_names: Collection[str] | None = None,
    disabled_names: Collection[str] | None = None,
    allow_local_plugins: bool = False,
    local_plugin_modules: Sequence[str] | None = None,
    strict_plugins: bool = False,
    notes_out: list[str] | None = None,
) -> list[PluginMcpToolSpec]:
    """Collect deduplicated `PluginMcpToolSpec` definitions from enabled plugins."""
    specs = (
        list(plugins)
        if plugins is not None
        else discover_plugins(
            allow_local_plugins=allow_local_plugins,
            local_plugin_modules=local_plugin_modules,
            strict_plugins=strict_plugins,
            notes_out=notes_out,
        )
    )
    out: list[PluginMcpToolSpec] = []
    seen_names: set[str] = set()
    for spec in specs:
        if not _is_spec_enabled(spec, enabled_names, disabled_names):
            continue
        for tool in spec.mcp_tools:
            if tool.name not in seen_names:
                seen_names.add(tool.name)
                out.append(tool)
    return out


def dispatch_plugin_cli_subcommand(
    subcmd: str,
    argv: Sequence[str],
    *,
    plugins: Sequence[WythePluginSpec] | None = None,
    enabled_names: Collection[str] | None = None,
    disabled_names: Collection[str] | None = None,
    allow_local_plugins: bool = False,
    local_plugin_modules: Sequence[str] | None = None,
    strict_plugins: bool = False,
    notes_out: list[str] | None = None,
) -> int | None:
    """Invoke the first enabled plugin CLI handler registered for `subcmd`, or return `None`."""
    specs = (
        list(plugins)
        if plugins is not None
        else discover_plugins(
            allow_local_plugins=allow_local_plugins,
            local_plugin_modules=local_plugin_modules,
            strict_plugins=strict_plugins,
            notes_out=notes_out,
        )
    )
    for spec in specs:
        if not _is_spec_enabled(spec, enabled_names, disabled_names):
            continue
        handler = spec.cli_subcommands.get(subcmd)
        if handler is not None:
            return int(handler(list(argv)))
    return None


def register_plugin_tier_adapters(
    registry: AdapterRegistry,
    *,
    repo_root: Path | None = None,
    plugins: Sequence[WythePluginSpec] | None = None,
    enabled_names: Collection[str] | None = None,
    disabled_names: Collection[str] | None = None,
    allow_local_plugins: bool = False,
    local_plugin_modules: Sequence[str] | None = None,
    strict_plugins: bool = False,
    notes_out: list[str] | None = None,
) -> list[str]:
    """Register Truth, Manipulate, and Display tier adapters from enabled `wythe.plugins`."""
    specs = (
        list(plugins)
        if plugins is not None
        else discover_plugins(
            repo_root=repo_root,
            allow_local_plugins=allow_local_plugins,
            local_plugin_modules=local_plugin_modules,
            strict_plugins=strict_plugins,
            notes_out=notes_out,
        )
    )
    registered: list[str] = []
    for spec in specs:
        if not _is_spec_enabled(spec, enabled_names, disabled_names):
            continue
        try:
            for t_ad in spec.truth_adapters:
                inst = t_ad() if isinstance(t_ad, type) else t_ad
                registry.register_truth(inst)
                registered.append(str(inst.name))
            for m_ad in spec.manipulator_adapters:
                inst = m_ad() if isinstance(m_ad, type) else m_ad
                registry.register_manipulator(inst)
                registered.append(str(inst.name))
            for d_ad in spec.display_adapters:
                inst = d_ad() if isinstance(d_ad, type) else d_ad
                registry.register_display(inst)
                registered.append(str(inst.name))
        except Exception as exc:
            if strict_plugins:
                raise
            if notes_out is not None:
                notes_out.append(
                    f"Plugin '{spec.name}' ({spec.origin}) tier adapter registration failed "
                    f"and was isolated: {type(exc).__name__}: {exc}"
                )
    return registered


def collect_enabled_plugin_stack_profiles(
    *,
    repo_root: Path | None = None,
    plugins: Sequence[WythePluginSpec] | None = None,
    enabled_names: Collection[str] | None = None,
    disabled_names: Collection[str] | None = None,
    allow_local_plugins: bool = False,
    local_plugin_modules: Sequence[str] | None = None,
    strict_plugins: bool = False,
    notes_out: list[str] | None = None,
) -> list[PluginStackProfileSpec]:
    """Collect deduplicated `PluginStackProfileSpec` descriptors from enabled plugins."""
    specs = (
        list(plugins)
        if plugins is not None
        else discover_plugins(
            repo_root=repo_root,
            allow_local_plugins=allow_local_plugins,
            local_plugin_modules=local_plugin_modules,
            strict_plugins=strict_plugins,
            notes_out=notes_out,
        )
    )
    out: list[PluginStackProfileSpec] = []
    seen_slugs: set[str] = set()
    for spec in specs:
        if not _is_spec_enabled(spec, enabled_names, disabled_names):
            continue
        for prof in spec.stack_profiles:
            if prof.slug not in seen_slugs:
                seen_slugs.add(prof.slug)
                out.append(prof)
    return out


def _filter_companion_kwargs(handler: Callable[..., Any], kwargs: dict[str, Any]) -> dict[str, Any]:
    if not kwargs:
        return {}
    try:
        sig = inspect.signature(handler)
    except (TypeError, ValueError):
        return kwargs
    if any(p.kind == inspect.Parameter.VAR_KEYWORD for p in sig.parameters.values()):
        return kwargs
    accepted = {
        name
        for name, p in sig.parameters.items()
        if p.kind in (inspect.Parameter.POSITIONAL_OR_KEYWORD, inspect.Parameter.KEYWORD_ONLY)
    }
    return {k: v for k, v in kwargs.items() if k in accepted}


def run_plugin_companion_handlers(
    repo_root: Path,
    report: TruthAtlasReport,
    *,
    handler_key: str | None = None,
    handler_kwargs: dict[str, Any] | None = None,
    plugins: Sequence[WythePluginSpec] | None = None,
    enabled_names: Collection[str] | None = None,
    disabled_names: Collection[str] | None = None,
    allow_local_plugins: bool = False,
    local_plugin_modules: Sequence[str] | None = None,
    strict_plugins: bool = False,
    notes_out: list[str] | None = None,
    **extra_kwargs: Any,
) -> dict[str, Any]:
    """Execute enabled plugin companion handlers against a deep-copied `report`."""
    specs = (
        list(plugins)
        if plugins is not None
        else discover_plugins(
            repo_root=repo_root,
            allow_local_plugins=allow_local_plugins,
            local_plugin_modules=local_plugin_modules,
            strict_plugins=strict_plugins,
            notes_out=notes_out,
        )
    )
    merged_kwargs: dict[str, Any] = {}
    if handler_kwargs:
        merged_kwargs.update(handler_kwargs)
    merged_kwargs.update(extra_kwargs)

    results: dict[str, Any] = {}
    for spec in specs:
        if not _is_spec_enabled(spec, enabled_names, disabled_names):
            continue
        for key, handler in sorted(spec.companion_handlers.items()):
            if handler_key is not None and key != handler_key:
                continue
            if key in results:
                continue
            try:
                isolated_report = report.model_copy(deep=True)
                call_kwargs = _filter_companion_kwargs(handler, merged_kwargs)
                results[key] = handler(repo_root, isolated_report, **call_kwargs)
            except Exception as exc:
                if strict_plugins:
                    raise
                if notes_out is not None:
                    notes_out.append(
                        f"Plugin '{spec.name}' ({spec.origin}) companion handler '{key}' "
                        f"failed and was isolated: {type(exc).__name__}: {exc}"
                    )
    return results
