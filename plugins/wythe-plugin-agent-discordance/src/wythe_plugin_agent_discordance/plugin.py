"""Wythe entry-point plugin registration for `wythe-plugin-agent-discordance` (#117)."""

from __future__ import annotations

import json
from dataclasses import asdict
from pathlib import Path
from typing import Any, Final

from app.adapters.base import ManipulatorExtractionResult, RawCandidateFinding
from app.adapters.plugin_registry import PluginMcpToolSpec, PluginRuleSpec, WythePluginSpec
from app.schemas.atlas import AtlasNode
from app.services.mcp_service import _resolve_target_for_mcp
from wythe_plugin_agent_discordance.evaluator import (
    evaluate_agent_discordance,
    load_repo_discordance_artifacts,
)

DISC_001_RULE = PluginRuleSpec(
    rule_code="DISC-001",
    tier="manipulate",
    title="Equivalent same-agent routes fragment identity, continuity canary, or policy version",
    severity="blocking",
    blocks_gate=True,
    enabled=True,
    confidence="confirmed",
    evidence_strength="structural_match",
)

DISC_002_RULE = PluginRuleSpec(
    rule_code="DISC-002",
    tier="manipulate",
    title="Distinct agents or principal scopes leak context, tasks, or permissions across an isolation boundary",
    severity="blocking",
    blocks_gate=True,
    enabled=True,
    confidence="confirmed",
    evidence_strength="structural_match",
)

MCP_AGENT_DISCORDANCE_DEFINITION: Final[dict[str, Any]] = {
    "name": "wythe_agent_discordance",
    "description": (
        "Evaluate cross-channel agent continuity (`DISC-001`), cross-agent isolation (`DISC-002`), "
        "hop-only observations, and missing SDK caller/authorization receipts (`unverified`) "
        "for a registered target or inline synthetic manifest/receipts bundle (#117)."
    ),
    "annotations": {
        "readOnlyHint": True,
        "destructiveHint": False,
        "idempotentHint": True,
        "openWorldHint": False,
    },
    "inputSchema": {
        "type": "object",
        "properties": {
            "target": {
                "type": "string",
                "description": "Optional registered target slug or repository path.",
            },
            "routes_manifest": {
                "type": "object",
                "description": "Optional inline declarative route-to-agent continuity manifest.",
            },
            "receipts_bundle": {
                "type": "object",
                "description": "Optional inline redacted SDK continuity/authorization receipts.",
            },
        },
        "additionalProperties": False,
    },
}


def _ensure_manifest_node(result: ManipulatorExtractionResult, rel_path: str) -> AtlasNode:
    node_id = f"m:agent_routes:{rel_path}"
    for existing in result.nodes:
        if existing.id == node_id:
            return existing
    node = AtlasNode(
        id=node_id,
        tier="manipulate",
        subkind="service",
        label=f"agent-routes:{Path(rel_path).name}",
        cluster="agent-continuity",
        source_file=rel_path,
        line=1,
        summary="Declarative cross-channel agent continuity & isolation manifest (#117).",
    )
    result.nodes.append(node)
    return node


def augment_agent_discordance(
    repo_root: Path,
    _backend_subdir: str,
    result: ManipulatorExtractionResult,
) -> None:
    """Inspect `.wythe/agent_routes.json` + `.wythe/agent_receipts.json` when present."""
    routes_doc, receipts_doc, routes_rel, load_notes = load_repo_discordance_artifacts(repo_root)
    result.notes.extend(load_notes)
    if routes_doc is None:
        return
    mnode = _ensure_manifest_node(result, routes_rel)
    eval_rep = evaluate_agent_discordance(routes_doc, receipts_doc, source_file=routes_rel)
    result.notes.extend(eval_rep.notes)
    if eval_rep.unverified_routes or eval_rep.hop_only_routes:
        result.notes.append(
            f"agent-discordance: unverified_routes={eval_rep.unverified_routes}, "
            f"hop_only_routes={eval_rep.hop_only_routes} (missing receipts never treated as passed)."
        )
    for viol in eval_rep.violations:
        result.findings.append(
            RawCandidateFinding(
                rule_code=viol.rule_code,
                node_id=mnode.id,
                source_file=viol.source_file,
                line=viol.line,
                title=viol.title,
                detail=viol.detail,
                remediation=viol.remediation,
                confidence="confirmed",
                evidence_strength="structural_match",
            )
        )


def handle_mcp_agent_discordance(session: Any, args: dict[str, Any]) -> str:
    """MCP handler for `wythe_agent_discordance`."""
    if not isinstance(args, dict):
        raise TypeError("`arguments` must be a JSON object.")
    unknown = sorted(set(args) - {"target", "routes_manifest", "receipts_bundle"})
    if unknown:
        raise ValueError(f"Unsupported argument(s): {', '.join(unknown)}")

    routes_doc = args.get("routes_manifest")
    receipts_doc = args.get("receipts_bundle")
    routes_rel = "inline:agent_routes"
    load_notes: list[str] = []

    target_arg = args.get("target")
    if isinstance(target_arg, str) and target_arg.strip():
        target = _resolve_target_for_mcp(session, target_arg.strip())
        repo_root = Path(target.repo_path).resolve()
        r_doc, rc_doc, r_rel, notes = load_repo_discordance_artifacts(repo_root)
        load_notes.extend(notes)
        if routes_doc is None:
            routes_doc = r_doc
            routes_rel = r_rel
        if receipts_doc is None:
            receipts_doc = rc_doc

    if not isinstance(routes_doc, dict):
        return json.dumps(
            {
                "status": "unverified",
                "reason": "No declarative agent_routes manifest found or supplied.",
                "notes": load_notes,
            },
            indent=2,
        )
    if receipts_doc is not None and not isinstance(receipts_doc, dict):
        raise TypeError("`receipts_bundle` must be a JSON object when provided.")

    rep = evaluate_agent_discordance(routes_doc, receipts_doc, source_file=routes_rel)
    payload = asdict(rep)
    payload["notes"] = [*load_notes, *rep.notes]
    payload["automated_security_audit"] = False
    payload["target_code_executed"] = False
    return json.dumps(payload, indent=2)


PLUGIN_SPEC = WythePluginSpec(
    name="agent-discordance",
    kind="manipulator_augmenter",
    origin="entry_point",
    version="0.1.0",
    description=(
        "Read-only cross-channel agent continuity (`DISC-001`), cross-agent isolation (`DISC-002`), "
        "and missing-receipt (`unverified` / `hop_only`) verifier (#117)."
    ),
    enabled_by_default=True,
    manipulator_hook=augment_agent_discordance,
    rules=(DISC_001_RULE, DISC_002_RULE),
    mcp_tools=(
        PluginMcpToolSpec(
            name="wythe_agent_discordance",
            definition=MCP_AGENT_DISCORDANCE_DEFINITION,
            handler=handle_mcp_agent_discordance,
        ),
    ),
    interaction_capabilities=(
        "findings",
        "structured_evidence",
        "provenance",
        "stable_references",
        "mcp_tools",
    ),
    evidence_source_kinds=("source_static", "runtime_capture"),
)

WYTHE_PLUGIN = PLUGIN_SPEC


def register_wythe_plugin() -> WythePluginSpec:
    """Entry-point factory registered under `[project.entry-points.\"wythe.plugins\"]`."""
    return PLUGIN_SPEC
