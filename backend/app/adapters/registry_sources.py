"""Conservative references from JSON command registries, without inferring admission."""

from __future__ import annotations

import json
from pathlib import Path

from app.adapters.base import ManipulatorExtractionResult
from app.adapters.deployment_sources import normalize_home
from app.adapters.launchd_sources import shell_references
from app.adapters.service_sources import script_id, source_files, source_reference
from app.schemas.atlas import AtlasEdge, AtlasNode

_COMMAND_KEYS = {"command", "argv", "script", "script_path", "entrypoint"}


def _commands(value):
    if isinstance(value, dict):
        for key, child in value.items():
            if key in _COMMAND_KEYS:
                if isinstance(child, str):
                    yield child
                elif isinstance(child, list):
                    yield from (item for item in child if isinstance(item, str))
            yield from _commands(child)
    elif isinstance(value, list):
        for child in value:
            yield from _commands(child)


def add_registry_sources(
    repo_root: Path, result: ManipulatorExtractionResult, deployments: dict[str, set[str]]
) -> None:
    paths = {n.source_file for n in result.nodes if n.id.startswith("m:script:")}
    declarations = linked = unreadable = 0
    for dirname in ("config", "configs"):
        files, _ = source_files(repo_root / dirname, {".json"})
        for path in files:
            rel = path.relative_to(repo_root).as_posix()
            try:
                data = json.loads(path.read_text(encoding="utf-8"))
            except (OSError, ValueError, UnicodeError):
                unreadable += 1
                continue
            commands = list(_commands(data))
            if not commands:
                continue
            declarations += 1
            targets = set()
            for command in commands:
                for candidate in {command, *shell_references(command)}:
                    mapped = deployments.get(normalize_home(candidate), set())
                    if mapped:
                        targets.update(mapped & paths)
                    else:
                        target = source_reference(candidate, rel, paths)
                        if target:
                            targets.add(target)
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
    result.notes.append(
        f"JSON command source coverage: {declarations} config/configs files with command fields, "
        f"{linked} with source links, {unreadable} unreadable files. Custom registry schemas, "
        "variable substitutions and admission rules are not evaluated; disabled entries are retained."
    )
