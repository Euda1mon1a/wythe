"""Read-only cross-channel continuity & cross-agent isolation plugin for Wythe (#117)."""

from wythe_plugin_agent_discordance.evaluator import (
    DiscordanceEvaluationReport,
    RouteContinuityObservation,
    evaluate_agent_discordance,
    load_repo_discordance_artifacts,
)
from wythe_plugin_agent_discordance.plugin import (
    DISC_001_RULE,
    DISC_002_RULE,
    PLUGIN_SPEC,
    WYTHE_PLUGIN,
    register_wythe_plugin,
)

__all__ = [
    "DISC_001_RULE",
    "DISC_002_RULE",
    "PLUGIN_SPEC",
    "WYTHE_PLUGIN",
    "DiscordanceEvaluationReport",
    "RouteContinuityObservation",
    "evaluate_agent_discordance",
    "load_repo_discordance_artifacts",
    "register_wythe_plugin",
]
