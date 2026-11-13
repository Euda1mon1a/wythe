"""Static launchd declarations. No launchctl calls, shell execution, or runtime reads."""

from __future__ import annotations

import plistlib
import re
import shlex
from pathlib import Path
from xml.parsers.expat import ExpatError

from app.adapters.base import ManipulatorExtractionResult, RawCandidateFinding
from app.adapters.deployment_sources import normalize_home
from app.adapters.service_sources import script_id, source_files, source_reference
from app.schemas.atlas import AtlasEdge, AtlasNode

_SCRIPT_TOKEN = re.compile(r"[^\s\"'<>;|&()]+\.(?:py|sh)$")


def shell_references(text: str) -> set[str]:
    """Literal script tokens, including conditional commands, but never comments."""
    refs: set[str] = set()
    for line in text.splitlines():
        try:
            lexer = shlex.shlex(line, posix=True, punctuation_chars=";&|()<>")
            lexer.whitespace_split = True
            tokens = list(lexer)
        except ValueError:
            continue
        for token in tokens:
            # Shell assignments are declarations too (SCRIPT="worker.py").
            value = token.split("=", 1)[-1] if "=" in token else token
            if _SCRIPT_TOKEN.fullmatch(value):
                refs.add(value)
    return refs


def add_launchd_sources(
    repo_root: Path,
    result: ManipulatorExtractionResult,
    deployments: dict[str, set[str]] | None = None,
) -> None:
    deployments = deployments or {}
    paths = {n.source_file for n in result.nodes if n.id.startswith("m:script:")}
    files, _ = source_files(repo_root, {".plist"})
    declarations = linked = unresolved = 0
    for path in files:
        rel = path.relative_to(repo_root).as_posix()
        try:
            data = plistlib.loads(path.read_bytes())
        except (OSError, ValueError, plistlib.InvalidFileException, ExpatError):
            if "launchagents" in path.parts or "LaunchAgents" in path.parts:
                result.notes.append(
                    f"Could not parse launchd source {rel}; command evidence absent."
                )
            continue
        if not isinstance(data, dict) or not {"Program", "ProgramArguments"} & data.keys():
            continue
        declarations += 1
        nid = f"m:launchd:{rel}"
        result.nodes.append(
            AtlasNode(
                id=nid,
                tier="manipulate",
                subkind="cli",
                label=path.stem,
                source_file=rel,
                cluster="launchd",
                summary=(
                    "Disabled launchd declaration. "
                    if data.get("Disabled") is True
                    else "Launchd command declaration. "
                )
                + "Source presence does not establish host installation, admission, or liveness.",
            )
        )
        program = data.get("Program")
        args = data.get("ProgramArguments", [])
        problem = None
        if not isinstance(args, list) or any(not isinstance(a, str) for a in args):
            problem = "ProgramArguments must be an array of strings."
            args = []
        if program is not None and (not isinstance(program, str) or not program):
            problem = "Program must be a nonempty executable path."
            program = None
        if not program and (not args or not args[0]):
            problem = "No executable is supplied by Program or ProgramArguments."
        command = program or (args[0] if args else "")
        # Program selects the executable; argv[0] may be an arbitrary process name.
        if command.startswith(("~", "$")):
            problem = "The executable path requires expansion, but launchd does not invoke a shell."
        candidates = {command} if command else set()
        # Non-Python tools can load scripts too (for example a plugin flag). These
        # are references, not proof that launchd directly executes the script.
        candidates.update(a for a in args[1:] if _SCRIPT_TOKEN.fullmatch(a))
        executable = Path(command).name
        if executable in {"sh", "bash", "zsh", "dash", "ksh"}:
            for index, arg in enumerate(args[1:], 1):
                if arg.startswith("-") and "c" in arg[1:]:
                    if index + 1 < len(args):
                        candidates.update(shell_references(args[index + 1]))
                    break
            else:
                candidates.update(a for a in args[1:] if a.endswith(".sh"))
        elif re.fullmatch(r"python(?:\d+(?:\.\d+)*)?", executable):
            # Only the interpreter's script operand matters; later args are application data.
            for arg in args[1:]:
                if arg in {"-c", "-m", "-W", "-X"}:
                    break  # unsupported modes/options with operands remain unobserved
                if arg.startswith("-"):
                    continue
                if arg.endswith(".py"):
                    candidates.add(arg)
                    if arg.startswith(("~", "$")):
                        problem = "The Python script path is literal; launchd does not expand home or environment variables."
                break
        if problem:
            result.findings.append(
                RawCandidateFinding(
                    rule_code="MANIP-004",
                    node_id=nid,
                    source_file=rel,
                    line=1,
                    title="Review invalid launchd command declaration",
                    detail=problem,
                    remediation="Check installation-time rendering; use concrete arguments or an explicit shell wrapper. Verify on the owning host before changing a service.",
                )
            )
        targets = set()
        for candidate in candidates:
            mapped = deployments.get(normalize_home(candidate), set())
            if mapped:
                targets.update(mapped & paths)
            else:
                target = source_reference(candidate, rel, paths)
                if target:
                    targets.add(target)
        if not targets:
            unresolved += 1
        else:
            linked += 1
        for target in sorted(targets):
            result.edges.append(
                AtlasEdge(
                    id=f"e:launchd:{rel}:{target}",
                    source_id=nid,
                    target_id=script_id(target),
                    kind="calls_helper",
                    verification="declared",
                    evidence_path=f"{rel}:1",
                    evidence_note="Launchd command references a matching source path; deployed-path suffix matching does not prove execution.",
                )
            )
    result.notes.append(
        f"Launchd source coverage: {declarations} declarations, {linked} with source references, "
        f"{unresolved} with external or unresolved commands. Shell variables, -m entry points, "
        "installation templates and runtime registration are not fully resolved; no services were queried."
    )
