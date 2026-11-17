"""Optional Wythe companion plugin for LLM, SLM, and MCP agent-harness verification."""

from __future__ import annotations

from wythe_plugin_agent_harness.plugin import (
    WYTHE_PLUGIN,
    AgentHarnessPlugin,
    register_wythe_plugin,
)

__version__ = "0.1.0"

__all__ = [
    "WYTHE_PLUGIN",
    "AgentHarnessPlugin",
    "__version__",
    "register_wythe_plugin",
]
