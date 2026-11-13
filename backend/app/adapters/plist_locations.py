"""Locate top-level launchd command values in XML plists without executing anything."""

from __future__ import annotations

from dataclasses import dataclass, field
from xml.parsers.expat import ExpatError, ParserCreate


@dataclass
class _Element:
    tag: str
    line: int
    text: list[str] = field(default_factory=list)
    value_line: int | None = None
    argument_index: int | None = None


def command_locations(raw: bytes) -> tuple[dict[str, int], list[int]]:
    """Return field and argument locations; binary plists have no XML line positions."""
    parser = ParserCreate()
    stack: list[_Element] = []
    fields: dict[str, int] = {}
    arguments: list[int] = []
    key = ""

    def start(tag, attrs):
        element = _Element(tag, parser.CurrentLineNumber)
        stack.append(element)
        if len(stack) == 3 and tag != "key" and key in {"Program", "ProgramArguments"}:
            fields[key] = element.line
            if key == "ProgramArguments":
                arguments.clear()  # plist dictionaries use the final duplicate key
        if len(stack) == 4 and stack[-2].tag == "array" and key == "ProgramArguments":
            element.argument_index = len(arguments)
            arguments.append(element.line)

    def text(value):
        if not stack:
            return
        element = stack[-1]
        element.text.append(value)
        if element.value_line is None and value.strip():
            leading = value[: len(value) - len(value.lstrip())]
            element.value_line = parser.CurrentLineNumber + leading.count("\n")

    def end(tag):
        nonlocal key
        element = stack[-1]
        if len(stack) == 3:
            if tag == "key":
                key = "".join(element.text)
            elif key in fields and element.value_line is not None:
                fields[key] = element.value_line
        if element.argument_index is not None and element.value_line is not None:
            arguments[element.argument_index] = element.value_line
        stack.pop()

    parser.StartElementHandler = start
    parser.CharacterDataHandler = text
    parser.EndElementHandler = end
    try:
        parser.Parse(raw, True)
    except ExpatError:
        return {}, []
    return fields, arguments
