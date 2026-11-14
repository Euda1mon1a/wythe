"""Conservative TypeScript import execution and dynamic export selection.

Unknown selectors keep every export reachable. Refinement is enabled only with
a valid CST; importing a selected export still evaluates the other modules in
its barrel, including their top-level initializers and registration calls.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any

from app.adapters.treesitter_engine import _get_parser, _unwrap_cst_expr, has_treesitter


def _parse(source: str) -> tuple[bytes, Any] | None:
    if not has_treesitter():
        return None
    raw = source.encode("utf-8")
    root = _get_parser("tsx").parse(raw).root_node
    return None if root.has_error else (raw, root)


def _text(raw: bytes, node: Any) -> str:
    return raw[node.start_byte:node.end_byte].decode("utf-8")


@dataclass
class ModuleExecution:
    eager_symbols: set[str]
    statements: str
    ranges: list[tuple[str, int, int]]
    bodies: dict[str, str]
    exports: dict[str, str]


def module_execution(source: str) -> ModuleExecution | None:
    """Return eager declaration names and top-level statements, excluding lazy functions."""
    parsed = _parse(source)
    if parsed is None:
        return None
    raw, root = parsed
    eager: set[str] = set()
    statements: list[str] = []
    ranges: list[tuple[str, int, int]] = []
    bodies: dict[str, str] = {}
    exports: dict[str, str] = {}
    for statement in root.named_children:
        node = statement
        exported = node.type == "export_statement"
        default = exported and any(child.type == "default" for child in statement.children)
        if node.type == "export_statement":
            node = node.child_by_field_name("declaration")
            if node is None:
                # Default expressions can execute at import time too.
                value = statement.child_by_field_name("value")
                if value is not None:
                    unwrapped = _unwrap_cst_expr(value)
                    if unwrapped.type not in ("identifier", "arrow_function", "function_expression"):
                        statements.append(_text(raw, value))
                    ranges.append(("default", statement.start_point[0] + 1, statement.end_point[0] + 1))
                    bodies["default"] = _text(raw, statement)
                    exports["default"] = "default"
                continue
        name = node.child_by_field_name("name")
        if name is not None and name.type in ("identifier", "type_identifier"):
            symbol = _text(raw, name)
            ranges.append((symbol, statement.start_point[0] + 1, statement.end_point[0] + 1))
            bodies[symbol] = _text(raw, statement)
            if exported:
                exports["default" if default else symbol] = symbol
        if node.type in ("lexical_declaration", "variable_declaration"):
            for decl in node.named_children:
                if decl.type != "variable_declarator":
                    continue
                name = decl.child_by_field_name("name")
                if name is not None and name.type == "identifier":
                    symbol = _text(raw, name)
                    ranges.append((symbol, decl.start_point[0] + 1, decl.end_point[0] + 1))
                    bodies[symbol] = "const " + _text(raw, decl) + ";"
                    if exported:
                        exports[symbol] = symbol
                value = decl.child_by_field_name("value")
                if value is None:
                    continue
                value = _unwrap_cst_expr(value)
                if value.type in ("arrow_function", "function_expression", "generator_function"):
                    continue
                if name is not None and name.type == "identifier":
                    eager.add(_text(raw, name))
                else:
                    statements.append(_text(raw, decl))
        elif node.type in ("class_declaration", "abstract_class_declaration"):
            # Class bodies hold lazy methods, while decorators, static initializers, static blocks,
            # and heritage expressions run at module evaluation time.
            decorators = [c for c in (*statement.children, *node.children) if c.type == "decorator"]
            for dec in decorators:
                statements.append(_text(raw, dec))
            heritage = next((c for c in node.children if c.type == "class_heritage"), None)
            if heritage is not None:
                statements.append(_text(raw, heritage))
            cls_name = _text(raw, name) if name is not None else ""
            cls_body = node.child_by_field_name("body")
            if cls_body is not None:
                for member in cls_body.named_children:
                    for dec in member.children:
                        if dec.type == "decorator":
                            statements.append(_text(raw, dec))
                    if member.type == "class_static_block":
                        statements.append(_text(raw, member))
                    elif member.type in ("public_field_definition", "field_definition"):
                        is_static = any(tok.type == "static" for tok in member.children)
                        init_val = member.child_by_field_name("value")
                        if is_static and init_val is not None:
                            statements.append(_text(raw, init_val))
                    elif member.type == "method_definition" and cls_name:
                        m_name_node = member.child_by_field_name("name")
                        if m_name_node is not None and m_name_node.type == "property_identifier":
                            qual = f"{cls_name}.{_text(raw, m_name_node)}"
                            ranges.append((qual, member.start_point[0] + 1, member.end_point[0] + 1))
                            bodies[qual] = _text(raw, member)
                            if exported and not default:
                                exports[qual] = qual
        elif node.type not in (
            "import_statement", "comment", "function_declaration",
            "generator_function_declaration", "interface_declaration",
            "type_alias_declaration", "ambient_declaration",
        ):
            statements.append(_text(raw, node))
    return ModuleExecution(eager, "\n".join(statements), ranges, bodies, exports)


def _selected_export(raw: bytes, import_node: Any) -> str:
    member = import_node.parent
    if member is None or member.type != "member_expression":
        return "*"
    prop = member.child_by_field_name("property")
    if prop is None or _text(raw, prop) != "then":
        return "*"
    call = member.parent
    if call is None or call.type != "call_expression":
        return "*"
    args = call.child_by_field_name("arguments")
    callbacks = [n for n in args.named_children if n.type != "comment"] if args else []
    if len(callbacks) != 1 or callbacks[0].type != "arrow_function":
        return "*"
    callback = callbacks[0]
    param = callback.child_by_field_name("parameter")
    if param is None:
        params = callback.child_by_field_name("parameters")
        parts = [n for n in params.named_children if n.type != "comment"] if params else []
        if len(parts) != 1:
            return "*"
        param = parts[0]
        if param.type == "required_parameter":
            param = param.child_by_field_name("pattern")
    if param is None or param.type != "identifier":
        return "*"
    value = callback.child_by_field_name("body")
    if value is None:
        return "*"
    if value.type == "statement_block":
        stmts = [n for n in value.named_children if n.type != "comment"]
        if len(stmts) != 1 or stmts[0].type != "return_statement":
            return "*"
        values = [n for n in stmts[0].named_children if n.type != "comment"]
        if len(values) != 1:
            return "*"
        value = values[0]
    value = _unwrap_cst_expr(value)
    if value.type != "member_expression":
        return "*"
    obj, prop = value.child_by_field_name("object"), value.child_by_field_name("property")
    if obj is None or prop is None or obj.type != "identifier":
        return "*"
    if _text(raw, obj) != _text(raw, param) or prop.type != "property_identifier":
        return "*"
    return _text(raw, prop)


def dynamic_imports(source: str) -> list[tuple[str | None, str]] | None:
    """Return (literal module or unknown, selected export or wildcard) for dynamic imports."""
    parsed = _parse(source)
    if parsed is None:
        return None
    raw, root = parsed
    result: list[tuple[str | None, str]] = []

    def walk(node: Any) -> None:
        if node.type == "call_expression":
            function = node.child_by_field_name("function")
            if function is not None and (
                function.type == "import" or
                (function.type == "identifier" and _text(raw, function) == "require")
            ):
                args = node.child_by_field_name("arguments")
                values = [n for n in args.named_children if n.type != "comment"] if args else []
                spec = None
                if values and values[0].type == "string":
                    literal = _text(raw, values[0])
                    # Escaped specifiers require JS decoding; leave them unresolved.
                    if "\\" not in literal:
                        spec = literal[1:-1]
                result.append((spec, _selected_export(raw, node) if function.type == "import" else "*"))
        for child in node.named_children:
            walk(child)

    walk(root)
    return result
