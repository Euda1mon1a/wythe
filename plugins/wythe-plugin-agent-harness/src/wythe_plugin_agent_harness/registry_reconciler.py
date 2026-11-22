"""Tier-1 declarative JSON/YAML tool-registry discovery, SLM budget & shadow-drift reconciler."""

from __future__ import annotations

import json
import os
from dataclasses import dataclass
from pathlib import Path, PurePosixPath

import yaml

from app.adapters.base import ManipulatorExtractionResult, RawCandidateFinding
from app.adapters.registry_sources import extract_registry_truth_nodes
from app.schemas.atlas import AtlasEdge, AtlasNode, PolicyFieldConsumption
from wythe_plugin_agent_harness.python_inspector import (
    EXCLUDED_DIR_NAMES,
    MAX_FILE_BYTES,
    HarnessConfig,
    HarnessInspectionBundle,
    RegistryLoadRecord,
    _read_bounded_regular_text,
    is_safe_regular_file,
)

_GATING_POLICY_KEYS = frozenset(
    {
        "enabled",
        "disabled",
        "allowlist",
        "denylist",
        "slice",
        "slices",
        "scopes",
        "permissions",
        "mode",
        "max_tokens",
        "max_slm_tools",
    }
)


@dataclass(frozen=True)
class DeclarativeToolRegistry:
    rel_path: str
    cataloged_tools: tuple[str, ...]
    columns: tuple[str, ...]
    policy_columns: tuple[str, ...]


def _load_bounded_yaml(raw_text: str, *, max_nodes: int = 4096, max_depth: int = 64) -> object:
    """Parse YAML safely while capping node count, alias expansions, merge size, and depth."""

    class _BoundedSafeLoader(yaml.SafeLoader):
        def __init__(self, stream: object) -> None:
            super().__init__(stream)
            self._node_count = 0
            self._alias_count = 0
            self._merge_steps = 0
            self._cur_depth = 0

        def compose_node(self, parent: object, index: object) -> object:
            if self.check_event(yaml.AliasEvent):
                self._alias_count += 1
                if (self._node_count + self._alias_count) > max_nodes:
                    raise yaml.YAMLError(
                        f"YAML alias expansion exceeds budget ({max_nodes})."
                    )
                return super().compose_node(parent, index)
            self._node_count += 1
            if (self._node_count + self._alias_count) > max_nodes:
                raise yaml.YAMLError(f"YAML node count exceeds budget ({max_nodes}).")
            self._cur_depth += 1
            if self._cur_depth > max_depth:
                raise yaml.YAMLError(
                    f"YAML structure exceeds maximum nesting depth ({max_depth})."
                )
            try:
                return super().compose_node(parent, index)
            finally:
                self._cur_depth -= 1

        def flatten_mapping(self, node: object) -> None:
            self._merge_steps += 1
            if self._merge_steps > max_nodes:
                raise yaml.YAMLError(
                    f"YAML mapping merge exceeds budget ({max_nodes})."
                )
            super().flatten_mapping(node)
            if len(getattr(node, "value", ())) > max_nodes:
                raise yaml.YAMLError(
                    f"YAML merged mapping exceeds budget ({max_nodes})."
                )

        def construct_yaml_int(self, node: object) -> int:
            raw_val = getattr(node, "value", None)
            if isinstance(raw_val, str) and len(raw_val) > 4096:
                raise yaml.YAMLError("YAML integer exceeds maximum bit length")
            val = super().construct_yaml_int(node)
            if isinstance(val, int) and not isinstance(val, bool) and val.bit_length() > 4096:
                raise yaml.YAMLError("YAML integer exceeds maximum bit length")
            return val

    _BoundedSafeLoader.add_constructor(
        "tag:yaml.org,2002:int", _BoundedSafeLoader.construct_yaml_int
    )
    return yaml.load(raw_text, Loader=_BoundedSafeLoader)


def _extract_catalog_entries(section: object) -> tuple[list[str], list[str]]:
    names: list[str] = []
    entry_keys: list[str] = []
    if isinstance(section, list):
        for item in section[:500]:
            if isinstance(item, str) and item.strip():
                names.append(item.strip())
            elif isinstance(item, dict):
                raw_nm = item.get("name") or item.get("id") or item.get("tool")
                if isinstance(raw_nm, str) and raw_nm.strip():
                    names.append(raw_nm.strip())
                for k in item:
                    ks = str(k)
                    if ks not in entry_keys:
                        entry_keys.append(ks)
    elif isinstance(section, dict):
        for k, val in list(section.items())[:500]:
            ks = str(k).strip()
            if ks:
                names.append(ks)
            if isinstance(val, dict):
                for sub_k in val:
                    sk = str(sub_k)
                    if sk not in entry_keys:
                        entry_keys.append(sk)
    return list(dict.fromkeys(names)), entry_keys


def discover_tool_registries(
    repo_root: Path,
) -> tuple[list[DeclarativeToolRegistry], list[str]]:
    """Discover `config/*.{json,yaml,yml}` & `configs/*.{json,yaml,yml}` tool/capability catalogs."""
    try:
        if repo_root.is_symlink():
            return [], [f"{repo_root}: symlinked repository root"]
        if not repo_root.exists():
            return [], []
        real_root = repo_root.resolve()
    except OSError as exc:
        return [], [f"{repo_root}: {type(exc).__name__}"]

    registries: list[DeclarativeToolRegistry] = []
    errors: list[str] = []

    def _rel_label(path: Path, fallback: str) -> str:
        try:
            return path.relative_to(repo_root).as_posix()
        except ValueError:
            try:
                return path.resolve().relative_to(real_root).as_posix()
            except (OSError, ValueError):
                return fallback

    for dirname in ("config", "configs"):
        cfg_dir = repo_root / dirname
        try:
            if cfg_dir.is_symlink():
                errors.append(f"{dirname}: symlink directory skipped")
                continue
            if not cfg_dir.is_dir():
                continue
            if not cfg_dir.resolve().is_relative_to(real_root):
                errors.append(f"{dirname}: escapes repository root")
                continue
        except (OSError, ValueError) as exc:
            errors.append(f"{dirname}: {type(exc).__name__}")
            continue

        candidate_files: list[Path] = []

        def _on_walk_err(exc: OSError, *, _dir: str = dirname) -> None:
            err_name = Path(exc.filename).name if exc.filename else _dir
            err_rel = _rel_label(Path(exc.filename), err_name) if exc.filename else _dir
            errors.append(f"{err_rel}: {type(exc).__name__}")

        for parent, dirs, names in os.walk(cfg_dir, followlinks=False, onerror=_on_walk_err):
            parent_path = Path(parent)
            kept_dirs: list[str] = []
            for dname in sorted(dirs):
                if dname in EXCLUDED_DIR_NAMES or dname.startswith("."):
                    continue
                dpath = parent_path / dname
                try:
                    if dpath.is_symlink() or not dpath.resolve().is_relative_to(real_root):
                        errors.append(f"{_rel_label(dpath, dname)}: unsafe or symlink directory skipped")
                        continue
                except (OSError, ValueError) as exc:
                    errors.append(f"{_rel_label(dpath, dname)}: {type(exc).__name__}")
                    continue
                kept_dirs.append(dname)
            dirs[:] = kept_dirs

            for fname in sorted(names):
                cand = parent_path / fname
                if cand.suffix.lower() not in {".json", ".yaml", ".yml"}:
                    continue
                if not is_safe_regular_file(cand, real_root):
                    errors.append(
                        f"{_rel_label(cand, fname)}: unsafe, symlink, or oversized registry file skipped"
                    )
                    continue
                candidate_files.append(cand)

        for cand in sorted(candidate_files):
            rel = _rel_label(cand, cand.name)
            try:
                rel = cand.resolve().relative_to(real_root).as_posix()
                raw_text = _read_bounded_regular_text(
                    cand,
                    max_bytes=MAX_FILE_BYTES,
                    real_root=real_root,
                    encoding="utf-8",
                )
                data = (
                    json.loads(raw_text)
                    if cand.suffix.lower() == ".json"
                    else _load_bounded_yaml(raw_text)
                )
                if not isinstance(data, dict):
                    continue
                if not (set(data.keys()) & {"tools", "capabilities"}):
                    continue

                cat_names: list[str] = []
                cols: list[str] = [str(k) for k in data]
                for sec_key in ("tools", "capabilities"):
                    if sec_key in data:
                        sec_names, sec_keys = _extract_catalog_entries(data[sec_key])
                        for n in sec_names:
                            if n not in cat_names:
                                cat_names.append(n)
                        for k in sec_keys:
                            if k not in cols:
                                cols.append(k)

                pol_cols = [c for c in cols if c.lower() in _GATING_POLICY_KEYS]
                if not pol_cols:
                    pol_cols = [c for c in cols if c in ("tools", "capabilities")]
            except (OSError, UnicodeError, ValueError, TypeError, yaml.YAMLError, RecursionError) as exc:
                errors.append(f"{rel}: {type(exc).__name__}")
                continue

            registries.append(
                DeclarativeToolRegistry(
                    rel_path=rel,
                    cataloged_tools=tuple(cat_names),
                    columns=tuple(cols),
                    policy_columns=tuple(pol_cols),
                )
            )

    return registries, errors


def ensure_manipulator_node_for_file(
    result: ManipulatorExtractionResult,
    rel_path: str,
    line: int = 1,
) -> AtlasNode:
    """Return closest existing Manipulate `AtlasNode` for `rel_path`, or create a deterministic one."""
    matching = [n for n in result.nodes if n.source_file == rel_path and n.tier == "manipulate"]
    if matching:
        preceding = [n for n in matching if n.line <= line]
        if preceding:
            return max(preceding, key=lambda n: n.line)
        return min(matching, key=lambda n: n.line)

    nid = f"m:agent:{rel_path}"
    for n in result.nodes:
        if n.id == nid:
            return n

    created = AtlasNode(
        id=nid,
        tier="manipulate",
        subkind="service",
        label=PurePosixPath(rel_path).stem or rel_path,
        source_file=rel_path,
        line=1,
        status="clean",
        cluster="agent_harness",
        summary=f"Agent harness module `{rel_path}`.",
    )
    result.nodes.append(created)
    return created


def _match_registry(
    hint: str,
    registries: list[DeclarativeToolRegistry],
) -> DeclarativeToolRegistry | None:
    norm = hint.strip().replace("\\", "/").removeprefix("./")
    while norm.startswith("../"):
        norm = norm[3:]
    for reg in registries:
        if norm == reg.rel_path or norm.endswith("/" + reg.rel_path):
            return reg
    leaf = PurePosixPath(norm).name
    leaf_matches = [r for r in registries if PurePosixPath(r.rel_path).name == leaf]
    return leaf_matches[0] if len(leaf_matches) == 1 else None


def _build_load_pfc(
    load_rec: RegistryLoadRecord,
    reg: DeclarativeToolRegistry,
) -> PolicyFieldConsumption:
    pol_cols = list(reg.policy_columns)
    gating = {
        c
        for c in pol_cols
        if c.lower()
        in {"enabled", "disabled", "allowlist", "denylist", "slice", "slices", "scopes", "permissions", "mode"}
    }
    accessed = set(load_rec.accessed_keys)
    known = set(reg.columns) | set(pol_cols)
    consumed_known = sorted(accessed & known)
    consumed_gating = sorted(accessed & gating) if gating else sorted(accessed & set(pol_cols))

    if consumed_gating and not load_rec.returns_hardcoded_tools:
        uncons = sorted(set(pol_cols) - accessed)
        return PolicyFieldConsumption(
            state="consumed",
            mechanism="field_controls_result",
            reader_scopes=[load_rec.scope_name],
            policy_columns=pol_cols,
            consumed_columns=consumed_known,
            unconsumed_policy_columns=uncons,
            note=(
                f"`{load_rec.scope_name}` reads `{reg.rel_path}` and enforces policy field(s) "
                f"{', '.join(f'`{k}`' for k in consumed_gating)}."
            ),
        )
    if load_rec.has_dynamic_lookup and not load_rec.returns_hardcoded_tools:
        return PolicyFieldConsumption(
            state="unresolved",
            mechanism="dynamic_or_opaque_flow",
            reader_scopes=[load_rec.scope_name],
            policy_columns=pol_cols,
            consumed_columns=consumed_known,
            unconsumed_policy_columns=sorted(set(pol_cols) - accessed),
            note=f"`{load_rec.scope_name}` accesses `{reg.rel_path}` via dynamic key lookup.",
        )

    uncons = sorted(set(pol_cols) - set(consumed_gating))
    return PolicyFieldConsumption(
        state="bypassed",
        mechanism="constant_or_fallback_wins",
        reader_scopes=[load_rec.scope_name],
        policy_columns=pol_cols,
        consumed_columns=consumed_known,
        unconsumed_policy_columns=uncons,
        substituted_constants=list(load_rec.substituted_symbols),
        fallback_constants=list(load_rec.fallback_symbols),
        note=(
            f"`{load_rec.scope_name}` loads `{reg.rel_path}` without enforcing policy field(s) "
            f"{', '.join(f'`{k}`' for k in uncons[:6])}."
        ),
    )


def reconcile_manifests_and_registries(
    repo_root: Path,
    config: HarnessConfig,
    bundle: HarnessInspectionBundle,
    result: ManipulatorExtractionResult,
) -> tuple[list[DeclarativeToolRegistry], int]:
    """Evaluate `AGENT-002` budgets, shadow tools, `reads_truth` edges & `PolicyFieldConsumption`."""
    registries, reg_errors = discover_tool_registries(repo_root)
    if reg_errors:
        bundle.parse_errors.extend(reg_errors)
        object.__setattr__(result, "coverage_complete", False)

    already_ran_reg_sources = any(
        n.startswith(
            (
                "JSON command source coverage:",
                "YAML command source coverage:",
                "JSON/YAML ",
            )
        )
        for n in result.notes
    )
    preexisting_truth_ids: set[str] = set()
    if already_ran_reg_sources:
        t_nodes, _ = extract_registry_truth_nodes(repo_root)
        preexisting_truth_ids = {n.id for n in t_nodes}

    existing_node_ids = {n.id for n in result.nodes}
    reg_nodes_by_rel: dict[str, AtlasNode] = {}
    for reg in registries:
        tid = f"t:registry:{reg.rel_path}"
        tnode = next((n for n in result.nodes if n.id == tid), None)
        if tnode is None:
            tnode = AtlasNode(
                id=tid,
                tier="truth",
                subkind="table",
                label=f"registry:{reg.rel_path}",
                source_file=reg.rel_path,
                line=1,
                status="clean",
                role="policy",
                cluster="registries",
                summary=(
                    f"Declarative tool/capability registry `{reg.rel_path}` "
                    f"({len(reg.cataloged_tools)} cataloged entries)."
                ),
                columns=list(reg.columns),
                policy_columns=list(reg.policy_columns),
            )
            if tid not in existing_node_ids and tid not in preexisting_truth_ids:
                existing_node_ids.add(tid)
                result.nodes.append(tnode)
        reg_nodes_by_rel[reg.rel_path] = tnode

    # 1. SLM schema token & tool-count budget checks
    for manifest in bundle.manifests:
        exempt = manifest.has_progressive_discovery or (
            manifest.has_slice_selector and not manifest.is_explicit_slm_slice
        )
        if exempt:
            continue
        over_tools = manifest.tool_count > config.max_slm_tools
        over_tokens = manifest.approx_tokens > config.max_slm_schema_tokens
        if over_tools or over_tokens:
            mnode = ensure_manipulator_node_for_file(result, manifest.rel_path, manifest.line)
            result.findings.append(
                RawCandidateFinding(
                    rule_code="AGENT-002",
                    node_id=mnode.id,
                    source_file=manifest.rel_path,
                    line=manifest.line,
                    title=(
                        f"Tool manifest `{manifest.manifest_name}` ({manifest.tool_count} tools, "
                        f"~{manifest.approx_tokens} tokens) exceeds SLM schema budget"
                    ),
                    detail=(
                        f"`{manifest.rel_path}:{manifest.line}` mounts `{manifest.manifest_name}` with "
                        f"{manifest.tool_count} tool(s) (max {config.max_slm_tools}) and "
                        f"{manifest.byte_len} JSON bytes (~{manifest.approx_tokens} tokens, max "
                        f"{config.max_slm_schema_tokens}) without progressive discovery "
                        "(`search_tools` / `discover_capabilities`) or `--slice` / `slice_mode`."
                    ),
                    remediation=(
                        "Expose a compact SLM slice (`<=5` tools and `<=1,000` schema tokens via "
                        "`--slice` / `slice_mode`) or mount progressive capability discovery."
                    ),
                    confidence="confirmed",
                    evidence_strength="structural_match",
                )
            )

    if not registries:
        return registries, 0

    # 2. Declarative registry shadow-tool drift & loader policy consumption
    all_cataloged = {t for r in registries for t in r.cataloged_tools}
    primary_reg = registries[0]
    shadow_total = 0

    for manifest in bundle.manifests:
        shadows = [t for t in manifest.tool_names if t and t not in all_cataloged]
        if not shadows:
            continue
        shadow_total += len(shadows)
        mnode = ensure_manipulator_node_for_file(result, manifest.rel_path, manifest.line)
        mnode.status = "duplicated_truth"
        shown = ", ".join(f"`{s}`" for s in shadows[:6])
        more = f" (+{len(shadows) - 6} more)" if len(shadows) > 6 else ""
        result.findings.append(
            RawCandidateFinding(
                rule_code="AGENT-002",
                node_id=mnode.id,
                target_node_id=f"t:registry:{primary_reg.rel_path}",
                source_file=manifest.rel_path,
                line=manifest.line,
                title=(
                    f"Hardcoded manifest `{manifest.manifest_name}` defines {len(shadows)} "
                    f"uncataloged shadow tool(s) absent from `{primary_reg.rel_path}`"
                ),
                detail=(
                    f"`{manifest.rel_path}:{manifest.line}` hardcodes {shown}{more} in "
                    f"`{manifest.manifest_name}`, diverging from declarative Tier-1 registry "
                    f"`{primary_reg.rel_path}` ({len(all_cataloged)} cataloged tool(s))."
                ),
                remediation=(
                    f"Register all exposed tools in `{primary_reg.rel_path}` and derive active "
                    "tool manifests from its declarative `enabled` / `allowlist` policy."
                ),
                confidence="confirmed",
                evidence_strength="structural_match",
            )
        )

    edges_by_pair: dict[tuple[str, str], AtlasEdge] = {
        (e.source_id, e.target_id): e for e in result.edges if e.kind == "reads_truth"
    }
    for load_rec in bundle.registry_loads:
        matched_reg = _match_registry(load_rec.registry_hint, registries)
        if matched_reg is None:
            continue
        tid = f"t:registry:{matched_reg.rel_path}"
        tnode = reg_nodes_by_rel[matched_reg.rel_path]
        mnode = ensure_manipulator_node_for_file(result, load_rec.rel_path, load_rec.line)
        pfc = _build_load_pfc(load_rec, matched_reg)
        slink = f"{load_rec.scope_name}->*"

        existing_edge = edges_by_pair.get((mnode.id, tid))
        if existing_edge is not None:
            if slink not in existing_edge.symbol_links:
                existing_edge.symbol_links.append(slink)
            existing_edge.policy_field_consumption = pfc
        else:
            new_edge = AtlasEdge(
                id=f"e:agent:{load_rec.rel_path}:{load_rec.scope_name}:reads_truth:{tid}",
                source_id=mnode.id,
                target_id=tid,
                kind="reads_truth",
                verification="verified",
                evidence_path=f"{load_rec.rel_path}:{load_rec.line}",
                evidence_note=(
                    f"Agent loader `{load_rec.scope_name}` reads declarative tool registry "
                    f"`{matched_reg.rel_path}` (policy_field_consumption={pfc.state})."
                ),
                symbol_links=[slink],
                policy_field_consumption=pfc,
            )
            result.edges.append(new_edge)
            edges_by_pair[(mnode.id, tid)] = new_edge

        mnode.policy_field_consumption = pfc
        tnode.policy_field_consumption = pfc
        if pfc.state == "bypassed":
            if mnode.status in ("clean", "unwired"):
                mnode.status = "policy_in_code"
            uncons_str = ", ".join(f"`{c}`" for c in pfc.unconsumed_policy_columns[:4]) or "`enabled`"
            subst_note = (
                f" and substitutes hardcoded `{', '.join(pfc.substituted_constants)}`"
                if pfc.substituted_constants
                else ""
            )
            result.findings.append(
                RawCandidateFinding(
                    rule_code="AGENT-002",
                    node_id=mnode.id,
                    target_node_id=tid,
                    source_file=load_rec.rel_path,
                    line=load_rec.line,
                    title=(
                        f"Agent loader `{load_rec.scope_name}` bypasses `{matched_reg.rel_path}` "
                        "policy controls"
                    ),
                    detail=(
                        f"`{load_rec.rel_path}:{load_rec.line}` (`{load_rec.scope_name}`) reads "
                        f"`{matched_reg.rel_path}` but ignores declarative {uncons_str} policy "
                        f"fields{subst_note}."
                    ),
                    remediation=(
                        f"Filter exposed tools using `{matched_reg.rel_path}`'s `enabled` and "
                        "`allowlist` fields instead of substituting hardcoded Python/TypeScript lists."
                    ),
                    confidence="confirmed",
                    evidence_strength="structural_match",
                )
            )

    return registries, shadow_total
