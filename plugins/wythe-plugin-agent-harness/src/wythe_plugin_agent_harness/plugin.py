"""Entry-point companion plugin `wythe-plugin-agent-harness` (`AGENT-001..003`)."""

from __future__ import annotations

from dataclasses import asdict
from typing import TYPE_CHECKING

from app.adapters.base import ManipulatorExtractionResult, RawCandidateFinding
from app.schemas.atlas import AtlasEdge, TruthAtlasReport
from wythe_plugin_agent_harness.python_inspector import (
    HarnessConfig,
    HarnessInspectionBundle,
    inspect_python_files,
    load_harness_config,
)
from wythe_plugin_agent_harness.registry_reconciler import (
    DeclarativeToolRegistry,
    _match_registry,
    ensure_manipulator_node_for_file,
    reconcile_manifests_and_registries,
)
from wythe_plugin_agent_harness.ts_inspector import inspect_ts_files

if TYPE_CHECKING:
    from pathlib import Path


def _evaluate_agent_001(
    bundle: HarnessInspectionBundle,
    result: ManipulatorExtractionResult,
) -> int:
    frozen = [p for p in bundle.prompts if not p.is_volatile]
    volatile = [p for p in bundle.prompts if p.is_volatile]
    split_brain_pairs = 0

    for vol in volatile:
        mnode = ensure_manipulator_node_for_file(result, vol.rel_path, vol.line)
        siblings = sorted(
            (s for s in frozen if (s.rel_path, s.line) != (vol.rel_path, vol.line)),
            key=lambda s: (
                0 if s.has_tail_turn_context else 1,
                0 if s.rel_path.rsplit("/", 1)[0] == vol.rel_path.rsplit("/", 1)[0] else 1,
                s.rel_path,
                s.line,
            ),
        )
        sib = siblings[0] if siblings else None
        reasons_str = ", ".join(f"`{r}`" for r in vol.volatile_reasons[:4]) or "per-turn state"

        if sib is not None:
            split_brain_pairs += 1
            tail_clause = (
                " and appends dynamic `[TURN CONTEXT]` in `messages[-1]`"
                if sib.has_tail_turn_context
                else ""
            )
            title = (
                f"Split-brain system-prompt prefix volatility between `{vol.rel_path}:{vol.line}` "
                f"and frozen sibling `{sib.rel_path}:{sib.line}`"
            )
            detail = (
                f"`{vol.rel_path}:{vol.line}` (`{vol.scope_name}`) injects volatile {reasons_str} "
                f"into `{vol.mechanism}` ahead of static instructions, busting KV-cache prefix reuse "
                "(cf. `ml-explore/mlx@fc344c986c4169d99f76b5d95ae6b4a58a359a63`), whereas sibling "
                f"route `{sib.rel_path}:{sib.line}` (`{sib.scope_name}`) preserves a frozen "
                f"`system` prefix{tail_clause}."
            )
        else:
            title = (
                f"System-prompt prefix at `{vol.rel_path}:{vol.line}` injects volatile "
                "per-turn values ahead of static instructions"
            )
            detail = (
                f"`{vol.rel_path}:{vol.line}` (`{vol.scope_name}`) interpolates volatile "
                f"{reasons_str} inside `{vol.mechanism}`, invalidating local KV-cache prefixes "
                "on every turn (`ml-explore/mlx@fc344c986c4169d99f76b5d95ae6b4a58a359a63`)."
            )

        result.findings.append(
            RawCandidateFinding(
                rule_code="AGENT-001",
                node_id=mnode.id,
                source_file=vol.rel_path,
                line=vol.line,
                title=title,
                detail=detail,
                remediation=(
                    "Keep `messages[0]` / `system` byte-identical across turns and append "
                    "per-turn timestamps or `[TURN CONTEXT]` metadata to the tail `user` message."
                ),
                confidence="confirmed",
                evidence_strength="ast_exact",
            )
        )
    return split_brain_pairs


def _evaluate_agent_003(
    config: HarnessConfig,
    bundle: HarnessInspectionBundle,
    result: ManipulatorExtractionResult,
) -> None:
    for loop in bundle.loops:
        defects: list[str] = []
        if loop.is_unbounded:
            defects.append("unbounded `while True` loop without an explicit round ceiling")
        elif (
            loop.max_rounds is not None
            and loop.max_rounds > config.max_un_timed_loop_rounds
            and not loop.has_step_timeout
        ):
            defects.append(
                f"high ceiling ({loop.max_rounds} > {config.max_un_timed_loop_rounds} rounds) "
                "without a per-step `timeout`"
            )
        if not loop.has_duplicate_brake:
            defects.append(
                "missing consecutive duplicate-call `(tool_name, canonical_args)` circuit breaker"
            )
        if loop.premature_stop_reasons:
            defects.extend(loop.premature_stop_reasons)

        if not defects:
            continue

        mnode = ensure_manipulator_node_for_file(result, loop.rel_path, loop.line)
        result.findings.append(
            RawCandidateFinding(
                rule_code="AGENT-003",
                node_id=mnode.id,
                source_file=loop.rel_path,
                line=loop.line,
                title=f"Agent tool loop in `{loop.scope_name}` lacks execution guardrails",
                detail=(
                    f"`{loop.rel_path}:{loop.line}` (`{loop.scope_name}`) runs an agent "
                    f"tool-execution loop with: {'; '.join(defects)}."
                ),
                remediation=(
                    "Bound tool loops with an explicit round cap and per-step timeout, abort on "
                    "consecutive duplicate `(tool_name, canonical_args)` signatures, and require "
                    "a deterministic verification/receipt gate before returning completion."
                ),
                confidence="confirmed",
                evidence_strength="ast_exact",
            )
        )

    canonical_rels = sorted({c.rel_path for c in bundle.canonical_clients})
    if canonical_rels:
        canon_primary = canonical_rels[0]
        canon_node = ensure_manipulator_node_for_file(result, canon_primary, 1)
        for raw_call in bundle.raw_http_calls:
            if raw_call.rel_path in canonical_rels:
                continue
            mnode = ensure_manipulator_node_for_file(result, raw_call.rel_path, raw_call.line)
            result.findings.append(
                RawCandidateFinding(
                    rule_code="AGENT-003",
                    node_id=mnode.id,
                    target_node_id=canon_node.id,
                    source_file=raw_call.rel_path,
                    line=raw_call.line,
                    title=(
                        f"Direct `{raw_call.callee}` call to `{raw_call.endpoint}` bypasses "
                        f"canonical adapter `{canon_primary}`"
                    ),
                    detail=(
                        f"`{raw_call.rel_path}:{raw_call.line}` (`{raw_call.scope_name}`) invokes "
                        f"`{raw_call.callee}` against `{raw_call.endpoint}` directly instead of "
                        f"routing through canonical LLM client module `{canon_primary}`."
                    ),
                    remediation=(
                        f"Route all model-completion requests through `{canon_primary}` so timeout, "
                        "prompt-cache, and retry policies stay enforced in one adapter."
                    ),
                    confidence="confirmed",
                    evidence_strength="ast_exact",
                )
            )


def _wire_harness_helper_edges(
    bundle: HarnessInspectionBundle,
    registries: list[DeclarativeToolRegistry],
    result: ManipulatorExtractionResult,
) -> None:
    provider_by_sym: dict[str, str] = {}
    for c in bundle.canonical_clients:
        provider_by_sym.setdefault(c.symbol_name, c.rel_path)
    for r in bundle.registry_loads:
        if r.scope_name != "*" and _match_registry(r.registry_hint, registries) is not None:
            provider_by_sym.setdefault(r.scope_name, r.rel_path)

    seen_edge_ids = {e.id for e in result.edges}
    for hcall in bundle.helper_calls:
        target_rel = provider_by_sym.get(hcall.callee_symbol)
        if not target_rel or target_rel == hcall.rel_path:
            continue
        src_node = ensure_manipulator_node_for_file(result, hcall.rel_path, hcall.line)
        tgt_node = ensure_manipulator_node_for_file(result, target_rel, 1)
        eid = f"e:agent:{hcall.rel_path}:{hcall.caller_scope}:calls_helper:{tgt_node.id}"
        if eid in seen_edge_ids:
            continue
        seen_edge_ids.add(eid)
        result.edges.append(
            AtlasEdge(
                id=eid,
                source_id=src_node.id,
                target_id=tgt_node.id,
                kind="calls_helper",
                verification="verified",
                evidence_path=f"{hcall.rel_path}:{hcall.line}",
                evidence_note=(
                    f"`{hcall.caller_scope}` invokes harness helper `{hcall.callee_symbol}` "
                    f"in `{target_rel}`."
                ),
                symbol_links=[
                    f"{hcall.caller_scope}->*",
                    f"{hcall.caller_scope}->{hcall.callee_symbol}",
                ],
            )
        )


def _run_harness_analysis(
    repo_root: Path,
    result: ManipulatorExtractionResult,
) -> dict[str, object]:
    config = load_harness_config(repo_root)
    bundle = inspect_python_files(repo_root)
    bundle.merge(inspect_ts_files(repo_root))

    before_count = len(result.findings)
    split_brain_pairs = _evaluate_agent_001(bundle, result)
    registries, shadow_tools = reconcile_manifests_and_registries(
        repo_root, config, bundle, result
    )
    _evaluate_agent_003(config, bundle, result)
    _wire_harness_helper_edges(bundle, registries, result)

    added_findings = result.findings[before_count:]
    rule_counts = {
        code: sum(1 for f in added_findings if f.rule_code == code)
        for code in ("AGENT-001", "AGENT-002", "AGENT-003")
    }
    note = (
        f"agent-harness: inspected {len(bundle.prompts)} prompt surface(s), "
        f"{len(bundle.manifests)} tool manifest(s), {len(registries)} registry file(s), "
        f"and {len(bundle.loops)} agent loop(s) "
        f"(AGENT-001={rule_counts['AGENT-001']}, AGENT-002={rule_counts['AGENT-002']}, "
        f"AGENT-003={rule_counts['AGENT-003']})."
    )
    if bundle.parse_errors:
        note += f" Skipped {len(bundle.parse_errors)} malformed file(s)."
    result.notes.append(note)

    return {
        "prompt_surfaces": len(bundle.prompts),
        "volatile_prefixes": sum(1 for p in bundle.prompts if p.is_volatile),
        "split_brain_pairs": split_brain_pairs,
        "tool_manifests": len(bundle.manifests),
        "registries": len(registries),
        "shadow_tools": shadow_tools,
        "agent_loops": len(bundle.loops),
        "canonical_clients": len(bundle.canonical_clients),
        "parse_errors": list(bundle.parse_errors),
        "rule_counts": rule_counts,
    }


class AgentHarnessPlugin:
    """Optional Wythe plugin verifying prompt-cache prefixes, SLM tool budgets, and agent loops."""

    name = "agent-harness"
    version = "0.1.0"
    description = (
        "Static LLM/SLM/MCP prompt-prefix KV-cache stability, tool-manifest schema budget, "
        "declarative registry drift, and bounded agent-loop verifier."
    )
    enabled_by_default = True

    plugin_rules = (
        {
            "rule_code": "AGENT-001",
            "tier": "manipulate",
            "title": "System-prompt prefix injects volatile per-turn values ahead of static instructions or splits router cache prefixes",
            "severity": "warning",
            "blocks_gate": False,
            "confidence": "confirmed",
            "evidence_strength": "ast_exact",
        },
        {
            "rule_code": "AGENT-002",
            "tier": "manipulate",
            "title": "Agent tool manifest exceeds SLM schema budget or diverges from declarative Tier-1 tool registry",
            "severity": "warning",
            "blocks_gate": False,
            "confidence": "confirmed",
            "evidence_strength": "structural_match",
        },
        {
            "rule_code": "AGENT-003",
            "tier": "manipulate",
            "title": "Agent tool-execution loop lacks bounded ceiling, duplicate-call circuit breaker, verification gate, or canonical adapter",
            "severity": "warning",
            "blocks_gate": False,
            "confidence": "confirmed",
            "evidence_strength": "ast_exact",
        },
    )

    def augment_manipulator(
        self,
        repo_root: Path,
        backend_subdir: str,
        result: ManipulatorExtractionResult,
    ) -> None:
        _ = backend_subdir
        _run_harness_analysis(repo_root, result)

    def check_report(
        self,
        repo_root: Path,
        report: TruthAtlasReport,
    ) -> dict[str, object]:
        scratch = ManipulatorExtractionResult(
            nodes=[n.model_copy(deep=True) for n in report.nodes],
            edges=[e.model_copy(deep=True) for e in report.edges],
            routes=[],
        )
        summary = _run_harness_analysis(repo_root, scratch)
        already_augmented = any(
            n.startswith("agent-harness:") for n in report.scan_notes
        ) or any(f.rule_code in {"AGENT-001", "AGENT-002", "AGENT-003"} for f in report.findings)
        return {
            "plugin": self.name,
            "version": self.version,
            "already_augmented": already_augmented,
            "findings": [] if already_augmented else scratch.findings,
            "notes": [] if already_augmented else scratch.notes,
            "candidate_findings": [asdict(f) for f in scratch.findings],
            "summary": summary,
        }


WYTHE_PLUGIN = AgentHarnessPlugin()


def register_wythe_plugin() -> AgentHarnessPlugin:
    """Entry-point factory registered under `[project.entry-points.\"wythe.plugins\"]`."""
    return WYTHE_PLUGIN
