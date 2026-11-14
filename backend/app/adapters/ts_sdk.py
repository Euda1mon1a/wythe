"""Shared TypeScript workspace SDK lineage parser (oazapfts fetch-client + barrel exports)."""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from pathlib import Path
from urllib.parse import urlparse

from app.adapters.treesitter_engine import _get_parser, has_treesitter
from app.adapters.ts_workspace import (
    TS_SOURCE_EXTS,
    WorkspaceResolver,
    _parse_clause_names,
    extract_ts_import_bindings,
)

_HTTP_METHODS = frozenset({"GET", "POST", "PUT", "PATCH", "DELETE", "HEAD", "OPTIONS"})
_FETCH_CALLEE_RE = re.compile(
    r"""(?<![\w$.])(?:(?P<alias>[A-Za-z_$][\w$]*)\s*\.\s*)?(?P<method>fetchJson|fetchText|fetchBlob)\b"""
)
_RUNTIME_ALIAS_RE = re.compile(r"""\bconst\s+(?P<alias>[A-Za-z_$][\w$]*)\s*=\s*Oazapfts\.runtime\s*\(""")
_BASE_URL_RE = re.compile(r"""\bbaseUrl\s*:\s*(?P<q>['"`])(?P<val>[^'"`\n]*)(?P=q)""")
_DEFAULTS_BLOCK_RE = re.compile(r"""export\s+const\s+defaults\b[^=]*=\s*\{(?P<body>[^}]*)\}""")
_OPT_METHOD_RE = re.compile(r"""\bmethod\s*:\s*(?P<rhs>[^,\r\n\}]+)""")
_STR_LIT_RE = re.compile(r"""^\s*(?P<q>['"])(?P<val>[A-Za-z]+)(?P=q)\s*$""")
_TYPE_IMPORT_RE = re.compile(
    r"""(?:^|[;\r\n])[ \t]*import\s+type\b[^;\r\n]*?\s+from\s+['"](?P<spec>[^'"]+)['"]"""
)
_INLINE_TYPE_SPEC_RE = re.compile(r"""^\s*type\s+[A-Za-z_$][\w$]*(?:\s+as\s+[A-Za-z_$][\w$]*)?\s*$""")
_IMPORT_LINE_RE = re.compile(
    r"""(?:^|[;\r\n])[ \t]*import\s+(?!type\b)(?P<body>[^;\r\n]*?)\s+from\s+['"](?P<spec>[^'"]+)['"]""",
    re.DOTALL,
)
_REEXPORT_STAR_RE = re.compile(r"""(?:^|[;\r\n])[ \t]*export\s+\*\s+from\s+['"](?P<spec>[^'"]+)['"]""")
_REEXPORT_NAMED_RE = re.compile(
    r"""(?:^|[;\r\n])[ \t]*export\s+(?!type\b)\{(?P<clause>[^}]+)\}\s+from\s+['"](?P<spec>[^'"]+)['"]""",
    re.DOTALL,
)
_EXPORT_FN_RE = re.compile(
    r"""(?:^|[;\r\n])[ \t]*export\s+(?:async\s+)?function\s+(?P<name>[A-Za-z_$][\w$]*)\s*(?:<[^()\n;]*>)?\s*\(""",
)
_EXPORT_ARROW_RE = re.compile(
    r"""(?:^|[;\r\n])[ \t]*export\s+const\s+(?P<name>[A-Za-z_$][\w$]*)\s*(?::[^=\n]+)?=\s*(?:async\s+)?(?:<[^()\n;]*>)?\s*(?:\([^)]*\)|[A-Za-z_$][\w$]*)\s*(?::[^=>\n]+)?=>""",
)


@dataclass(frozen=True)
class SdkEndpoint:
    """Typed frontend SDK endpoint metadata resolved to an HTTP verb and normalized path."""

    name: str
    verb: str
    path: str
    source_file: Path
    line: int


def _skip_string(text: str, pos: int) -> int:
    q = text[pos]
    n = len(text)
    i = pos + 1
    while i < n:
        ch = text[i]
        if ch == "\\":
            i += 2
            continue
        if q == "`" and ch == "$" and i + 1 < n and text[i + 1] == "{":
            end = _find_matching(text, i + 1, "{", "}")
            if end < 0:
                return n
            i = end + 1
            continue
        if ch == q:
            return i + 1
        i += 1
    return n


def _skip_non_code(text: str, pos: int) -> int:
    n = len(text)
    ch = text[pos]
    if ch in ("'", '"', "`"):
        return _skip_string(text, pos)
    if ch == "/" and pos + 1 < n:
        nxt = text[pos + 1]
        if nxt == "/":
            nl = text.find("\n", pos + 2)
            return n if nl < 0 else nl + 1
        if nxt == "*":
            end = text.find("*/", pos + 2)
            return n if end < 0 else end + 2
    return pos


def _find_matching(text: str, open_pos: int, open_ch: str, close_ch: str) -> int:
    n = len(text)
    if open_pos < 0 or open_pos >= n or text[open_pos] != open_ch:
        return -1
    depth = 0
    i = open_pos
    while i < n:
        nxt = _skip_non_code(text, i)
        if nxt > i:
            i = nxt
            continue
        ch = text[i]
        if ch == open_ch:
            depth += 1
        elif ch == close_ch:
            depth -= 1
            if depth == 0:
                return i
        i += 1
    return -1


def _skip_balanced_angles(text: str, pos: int) -> int:
    n = len(text)
    i = pos
    while i < n and text[i].isspace():
        i += 1
    if i >= n or text[i] != "<":
        return pos
    depth = 0
    while i < n:
        nxt = _skip_non_code(text, i)
        if nxt > i:
            i = nxt
            continue
        ch = text[i]
        if ch == "<":
            depth += 1
        elif ch == ">" and (i == 0 or text[i - 1] != "="):
            depth -= 1
            if depth == 0:
                return i + 1
        i += 1
    return pos


def _split_top_level_args(inner: str) -> list[str]:
    args: list[str] = []
    paren = brace = bracket = 0
    start = 0
    i = 0
    n = len(inner)
    while i < n:
        nxt = _skip_non_code(inner, i)
        if nxt > i:
            i = nxt
            continue
        ch = inner[i]
        if ch == "(":
            paren += 1
        elif ch == ")":
            paren = max(0, paren - 1)
        elif ch == "{":
            brace += 1
        elif ch == "}":
            brace = max(0, brace - 1)
        elif ch == "[":
            bracket += 1
        elif ch == "]":
            bracket = max(0, bracket - 1)
        elif ch == "," and paren == 0 and brace == 0 and bracket == 0:
            part = inner[start:i].strip()
            if part:
                args.append(part)
            start = i + 1
        i += 1
    tail = inner[start:].strip()
    if tail:
        args.append(tail)
    return args


def _normalize_base_url(raw: str) -> str:
    val = raw.strip()
    if not val:
        return ""
    if val.startswith(("http://", "https://")):
        val = urlparse(val).path or ""
    val = "/" + val.strip("/") if val.strip("/") else ""
    return val


def _is_oazapfts_module(source: str) -> bool:
    if "fetchJson" not in source and "fetchText" not in source and "fetchBlob" not in source:
        return False
    return "oazapfts" in source or "Oazapfts" in source or ("defaults" in source and "baseUrl" in source)


def _extract_oazapfts_base_url(source: str) -> str:
    dm = _DEFAULTS_BLOCK_RE.search(source)
    if dm:
        bm = _BASE_URL_RE.search(dm.group("body"))
        if bm:
            return _normalize_base_url(bm.group("val"))
    bm = _BASE_URL_RE.search(source)
    return _normalize_base_url(bm.group("val")) if bm else ""
def _normalize_oazapfts_url_expr(expr: str, base_url: str) -> str | None:
    raw = expr.strip()
    while raw.startswith("(") and raw.endswith(")"):
        raw = raw[1:-1].strip()
    if not raw:
        return None
    if raw[0] in ("'", '"') and len(raw) >= 2 and raw[-1] == raw[0]:
        out = raw[1:-1]
    elif raw[0] == "`" and len(raw) >= 2 and raw[-1] == "`":
        inner = raw[1:-1]
        parts: list[str] = []
        i = 0
        n = len(inner)
        while i < n:
            if inner[i] == "\\" and i + 1 < n:
                parts.append(inner[i + 1])
                i += 2
                continue
            if inner[i] == "$" and i + 1 < n and inner[i + 1] == "{":
                end = _find_matching(inner, i + 1, "{", "}")
                if end < 0:
                    return None
                expr_part = inner[i + 2 : end].strip()
                is_query = (
                    expr_part.startswith(("QS.", "qs.", "queryString"))
                    or ".query(" in expr_part
                    or ".explode(" in expr_part
                    or (parts and "".join(parts).endswith("?"))
                )
                if not is_query:
                    parts.append("{param}")
                i = end + 1
                continue
            parts.append(inner[i])
            i += 1
        out = "".join(parts)
    else:
        return None

    out = out.split("?", 1)[0].strip()
    if not out:
        return None
    if out.startswith(("http://", "https://")):
        out = urlparse(out).path or "/"
    if not out.startswith("/"):
        out = "/" + out
    out = re.sub(r"/{2,}", "/", out)
    if base_url and out != base_url and not out.startswith(base_url + "/"):
        out = f"{base_url}{out}"
    return re.sub(r"/{2,}", "/", out)


def _extract_oazapfts_method(opts_expr: str | None) -> str | None:
    if not opts_expr:
        return "GET"
    m = _OPT_METHOD_RE.search(opts_expr)
    if not m:
        return "GET"
    lit = _STR_LIT_RE.match(m.group("rhs"))
    if not lit:
        return None
    verb = lit.group("val").upper()
    return verb if verb in _HTTP_METHODS else None


def _extract_endpoint_from_fn_body(
    name: str,
    body: str,
    lineno: int,
    aliases: frozenset[str],
    base_url: str,
    source_file: Path,
) -> SdkEndpoint | None:
    for m in _FETCH_CALLEE_RE.finditer(body):
        alias = m.group("alias")
        if alias is not None and alias not in aliases:
            continue
        pos = _skip_balanced_angles(body, m.end())
        while pos < len(body) and body[pos].isspace():
            pos += 1
        if pos >= len(body) or body[pos] != "(":
            continue
        close_pos = _find_matching(body, pos, "(", ")")
        if close_pos < 0:
            continue
        args = _split_top_level_args(body[pos + 1 : close_pos])
        if not args:
            continue
        path = _normalize_oazapfts_url_expr(args[0], base_url)
        if not path:
            continue
        verb = _extract_oazapfts_method(args[1] if len(args) >= 2 else None)
        if not verb:
            continue
        return SdkEndpoint(name=name, verb=verb, path=path, source_file=source_file, line=lineno)
    return None


def _scan_stmt_expr_end(text: str, start: int) -> int:
    paren = brace = bracket = 0
    i = start
    n = len(text)
    while i < n:
        nxt = _skip_non_code(text, i)
        if nxt > i:
            i = nxt
            continue
        ch = text[i]
        if ch == "(":
            paren += 1
        elif ch == ")":
            paren = max(0, paren - 1)
        elif ch == "{":
            brace += 1
        elif ch == "}":
            brace = max(0, brace - 1)
        elif ch == "[":
            bracket += 1
        elif ch == "]":
            bracket = max(0, bracket - 1)
        elif ch == ";" and paren == 0 and brace == 0 and bracket == 0:
            return i
        i += 1
    return n


def extract_oazapfts_endpoints(source: str, source_file: Path) -> dict[str, SdkEndpoint]:
    """Extract exported oazapfts fetch-client endpoint mappings from a TypeScript/JS module."""
    if not _is_oazapfts_module(source):
        return {}
    base_url = _extract_oazapfts_base_url(source)
    aliases = frozenset({"oazapfts", *(m.group("alias") for m in _RUNTIME_ALIAS_RE.finditer(source))})
    endpoints: dict[str, SdkEndpoint] = {}

    if has_treesitter():
        parser = _get_parser("tsx" if source_file.suffix in (".tsx", ".jsx") else "ts")
        if parser is not None:
            raw = source.encode("utf-8")
            tree = parser.parse(raw)
            for ch in tree.root_node.children:
                if ch.type != "export_statement":
                    continue
                for sub in ch.named_children:
                    if sub.type == "function_declaration":
                        nm_n = sub.child_by_field_name("name")
                        body_n = sub.child_by_field_name("body")
                        if nm_n is not None and body_n is not None:
                            name = raw[nm_n.start_byte : nm_n.end_byte].decode("utf-8", errors="replace")
                            body = raw[body_n.start_byte : body_n.end_byte].decode("utf-8", errors="replace")
                            ep = _extract_endpoint_from_fn_body(
                                name, body, sub.start_point[0] + 1, aliases, base_url, source_file
                            )
                            if ep is not None:
                                endpoints[name] = ep
                    elif sub.type == "lexical_declaration":
                        for decl in sub.named_children:
                            if decl.type != "variable_declarator":
                                continue
                            nm_n = decl.child_by_field_name("name")
                            val_n = decl.child_by_field_name("value")
                            if nm_n is None or val_n is None:
                                continue
                            if val_n.type not in ("arrow_function", "function_expression"):
                                continue
                            body_n = val_n.child_by_field_name("body")
                            if body_n is None:
                                continue
                            name = raw[nm_n.start_byte : nm_n.end_byte].decode("utf-8", errors="replace")
                            body = raw[body_n.start_byte : body_n.end_byte].decode("utf-8", errors="replace")
                            ep = _extract_endpoint_from_fn_body(
                                name, body, decl.start_point[0] + 1, aliases, base_url, source_file
                            )
                            if ep is not None:
                                endpoints[name] = ep
            return endpoints

    for fm in _EXPORT_FN_RE.finditer(source):
        close_paren = _find_matching(source, fm.end() - 1, "(", ")")
        if close_paren < 0:
            continue
        pos = close_paren + 1
        n_src = len(source)
        while pos < n_src and source[pos].isspace():
            pos += 1
        if pos < n_src and source[pos] == ":":
            pos += 1
            while pos < n_src:
                while pos < n_src and source[pos].isspace():
                    pos += 1
                if pos >= n_src:
                    break
                ch = source[pos]
                if ch == "{":
                    end_obj = _find_matching(source, pos, "{", "}")
                    if end_obj < 0:
                        break
                    nxt_pos = end_obj + 1
                    while nxt_pos < n_src and source[nxt_pos].isspace():
                        nxt_pos += 1
                    if nxt_pos < n_src and source[nxt_pos] in ("|", "&", "{", "["):
                        pos = nxt_pos
                        continue
                    break
                if ch == "<":
                    nxt = _skip_balanced_angles(source, pos)
                    pos = nxt if nxt > pos else pos + 1
                elif ch == "(":
                    end_p = _find_matching(source, pos, "(", ")")
                    pos = end_p + 1 if end_p >= 0 else pos + 1
                elif ch == "[":
                    end_b = _find_matching(source, pos, "[", "]")
                    pos = end_b + 1 if end_b >= 0 else pos + 1
                else:
                    nxt = _skip_non_code(source, pos)
                    pos = nxt if nxt > pos else pos + 1
        while pos < n_src and source[pos].isspace():
            pos += 1
        if pos >= n_src or source[pos] != "{":
            continue
        open_brace = pos
        close_brace = _find_matching(source, open_brace, "{", "}")
        if close_brace < 0:
            continue
        name = fm.group("name")
        body = source[open_brace : close_brace + 1]
        lineno = source.count("\n", 0, fm.start()) + 1
        ep = _extract_endpoint_from_fn_body(name, body, lineno, aliases, base_url, source_file)
        if ep is not None:
            endpoints[name] = ep

    for am in _EXPORT_ARROW_RE.finditer(source):
        pos = am.end()
        while pos < len(source) and source[pos].isspace():
            pos += 1
        if pos >= len(source):
            continue
        if source[pos] == "{":
            end_pos = _find_matching(source, pos, "{", "}")
            if end_pos < 0:
                continue
            body = source[pos : end_pos + 1]
        else:
            end_pos = _scan_stmt_expr_end(source, pos)
            body = source[pos:end_pos]
        name = am.group("name")
        if name in endpoints:
            continue
        lineno = source.count("\n", 0, am.start()) + 1
        ep = _extract_endpoint_from_fn_body(name, body, lineno, aliases, base_url, source_file)
        if ep is not None:
            endpoints[name] = ep

    return endpoints
def _blank_non_code_preserving_lines(text: str) -> str:
    """Replace comments and non-interpolation string text with spaces, preserving newlines and `${...}` code."""
    out: list[str] = []
    n = len(text)
    i = 0
    tpl_brace_stack: list[int] = []

    def _emit_blank(ch: str) -> None:
        out.append("\n" if ch == "\n" else " ")

    def _consume_template_literal(start_idx: int) -> int:
        k = start_idx
        while k < n:
            ch = text[k]
            if ch == "\\":
                _emit_blank(ch)
                if k + 1 < n:
                    _emit_blank(text[k + 1])
                    k += 2
                else:
                    k += 1
                continue
            if ch == "$" and k + 1 < n and text[k + 1] == "{":
                out.extend((" ", " "))
                tpl_brace_stack.append(1)
                return k + 2
            if ch == "`":
                out.append(" ")
                return k + 1
            _emit_blank(ch)
            k += 1
        return n

    while i < n:
        ch = text[i]
        if tpl_brace_stack:
            if ch == "{":
                tpl_brace_stack[-1] += 1
                out.append(ch)
                i += 1
                continue
            if ch == "}":
                tpl_brace_stack[-1] -= 1
                if tpl_brace_stack[-1] == 0:
                    tpl_brace_stack.pop()
                    out.append(" ")
                    i = _consume_template_literal(i + 1)
                    continue
                out.append(ch)
                i += 1
                continue
        if ch in ("'", '"'):
            q = ch
            out.append(" ")
            i += 1
            while i < n:
                c = text[i]
                if c == "\\":
                    _emit_blank(c)
                    if i + 1 < n:
                        _emit_blank(text[i + 1])
                        i += 2
                    else:
                        i += 1
                    continue
                _emit_blank(c)
                i += 1
                if c == q:
                    break
            continue
        if ch == "`":
            out.append(" ")
            i = _consume_template_literal(i + 1)
            continue
        if ch == "/" and i + 1 < n and text[i + 1] == "/":
            out.extend((" ", " "))
            i += 2
            while i < n and text[i] != "\n":
                out.append(" ")
                i += 1
            continue
        if ch == "/" and i + 1 < n and text[i + 1] == "*":
            out.extend((" ", " "))
            i += 2
            while i < n:
                c = text[i]
                if c == "*" and i + 1 < n and text[i + 1] == "/":
                    out.extend((" ", " "))
                    i += 2
                    break
                _emit_blank(c)
                i += 1
            continue
        out.append(ch)
        i += 1
    return "".join(out)


def _inline_type_locals(source: str) -> dict[str, set[str]]:
    """Collect local symbol names imported inline with `type` (e.g. `import { type Foo } from '...'`)."""
    out: dict[str, set[str]] = {}
    for m in _IMPORT_LINE_RE.finditer(source):
        spec = m.group("spec")
        body = m.group("body")
        bm = re.search(r"\{([^}]*)\}", body)
        if not bm:
            continue
        for raw_item in bm.group(1).split(","):
            item = raw_item.strip()
            if _INLINE_TYPE_SPEC_RE.match(item):
                trimmed = re.sub(r"^\s*type\s+", "", item)
                if " as " in trimmed:
                    _, dst = trimmed.split(" as ", 1)
                    out.setdefault(spec, set()).add(dst.strip())
                else:
                    out.setdefault(spec, set()).add(trimmed.strip())
    return out


@dataclass
class WorkspaceSdkIndex:
    """Lazy, memoized workspace index of typed frontend SDK endpoints (oazapfts + barrels)."""

    repo_root: Path
    ws_resolver: WorkspaceResolver
    _module_cache: dict[Path, dict[str, SdkEndpoint]] = field(default_factory=dict, repr=False)
    _sdk_flag_cache: dict[Path, bool] = field(default_factory=dict, repr=False)

    @classmethod
    def build(cls, repo_root: Path, ws_resolver: WorkspaceResolver) -> WorkspaceSdkIndex:
        return cls(repo_root=repo_root.resolve(), ws_resolver=ws_resolver)

    def _scan_module(self, mod_path: Path, _visiting: frozenset[Path] = frozenset()) -> tuple[dict[str, SdkEndpoint], bool]:
        rp = mod_path.resolve()
        if rp in self._module_cache:
            return self._module_cache[rp], self._sdk_flag_cache.get(rp, False)
        if rp in _visiting or not rp.is_file():
            return {}, False
        try:
            text = rp.read_text(encoding="utf-8", errors="replace")
        except (OSError, UnicodeError):
            return {}, False

        visiting = _visiting | {rp}
        endpoints = dict(extract_oazapfts_endpoints(text, rp))
        is_sdk = _is_oazapfts_module(text) or bool(endpoints)

        for sm in _REEXPORT_STAR_RE.finditer(text):
            target = self.ws_resolver.resolve_import(sm.group("spec"), rp, exts=TS_SOURCE_EXTS)
            if target is not None and target != rp:
                child_eps, child_is_sdk = self._scan_module(target, visiting)
                if child_is_sdk:
                    is_sdk = True
                for k, ep in child_eps.items():
                    endpoints.setdefault(k, ep)

        for nm in _REEXPORT_NAMED_RE.finditer(text):
            target = self.ws_resolver.resolve_import(nm.group("spec"), rp, exts=TS_SOURCE_EXTS)
            if target is None or target == rp:
                continue
            child_eps, child_is_sdk = self._scan_module(target, visiting)
            if child_is_sdk:
                is_sdk = True
            inames, lnames = _parse_clause_names(nm.group("clause"))
            for src_name, dst_name in zip(inames, lnames):
                if src_name in child_eps:
                    endpoints.setdefault(dst_name, child_eps[src_name])

        self._module_cache[rp] = endpoints
        self._sdk_flag_cache[rp] = is_sdk
        return endpoints, is_sdk

    def module_endpoints(self, mod_path: Path) -> dict[str, SdkEndpoint]:
        return self._scan_module(mod_path)[0]

    def is_sdk_module(self, mod_path: Path) -> bool:
        return self._scan_module(mod_path)[1]

    def extract_caller_sdk_calls(
        self,
        fpath: Path,
        source: str,
        *,
        is_tsx: bool = False,
    ) -> tuple[list[tuple[str, str, int]], bool]:
        """Resolve imported SDK calls in `source` to `(VERB, /path, lineno)` plus `uses_typed_sdk`."""
        uses_typed_sdk = False
        inline_types = _inline_type_locals(source)

        for tm in _TYPE_IMPORT_RE.finditer(source):
            target = self.ws_resolver.resolve_import(tm.group("spec"), fpath, exts=TS_SOURCE_EXTS)
            if target is not None and self.is_sdk_module(target):
                uses_typed_sdk = True

        direct_calls: dict[str, SdkEndpoint] = {}
        ns_calls: dict[str, dict[str, SdkEndpoint]] = {}
        for imp in extract_ts_import_bindings(source, is_tsx=is_tsx):
            target = self.ws_resolver.resolve_import(imp.spec, fpath, exts=TS_SOURCE_EXTS)
            if target is None:
                continue
            endpoints, is_sdk = self._scan_module(target)
            if is_sdk:
                uses_typed_sdk = True
            if not endpoints:
                continue
            skipped_locals = inline_types.get(imp.spec, set())
            for src_name, dst_name in zip(imp.imported_names, imp.local_names):
                if dst_name in skipped_locals:
                    continue
                if src_name in endpoints:
                    direct_calls[dst_name] = endpoints[src_name]
            for ns in imp.namespace_names:
                ns_calls[ns] = endpoints

        if not direct_calls and not ns_calls:
            return [], uses_typed_sdk

        blanked = _blank_non_code_preserving_lines(source)
        found: list[tuple[str, str, int]] = []
        seen: set[tuple[str, str, int]] = set()
        n = len(blanked)

        if direct_calls:
            fn_alts = "|".join(re.escape(k) for k in sorted(direct_calls, key=len, reverse=True))
            direct_re = re.compile(rf"(?<![\w$.])(?P<fn>{fn_alts})\b")
            for m in direct_re.finditer(blanked):
                prefix = blanked[: m.start()].rstrip()
                if re.search(r"\bfunction\*?$", prefix):
                    continue
                pos = _skip_balanced_angles(blanked, m.end())
                while pos < n and blanked[pos].isspace():
                    pos += 1
                if pos < n and blanked[pos] == "(":
                    ep = direct_calls[m.group("fn")]
                    lineno = source.count("\n", 0, m.start()) + 1
                    item = (ep.verb, ep.path, lineno)
                    if item not in seen:
                        seen.add(item)
                        found.append(item)

        if ns_calls:
            ns_alts = "|".join(re.escape(k) for k in sorted(ns_calls, key=len, reverse=True))
            ns_re = re.compile(rf"(?<![\w$.])(?P<ns>{ns_alts})\s*\.\s*(?P<fn>[A-Za-z_$][\w$]*)\b")
            for m in ns_re.finditer(blanked):
                ep = ns_calls[m.group("ns")].get(m.group("fn"))
                if ep is None:
                    continue
                pos = _skip_balanced_angles(blanked, m.end())
                while pos < n and blanked[pos].isspace():
                    pos += 1
                if pos < n and blanked[pos] == "(":
                    lineno = source.count("\n", 0, m.start()) + 1
                    item = (ep.verb, ep.path, lineno)
                    if item not in seen:
                        seen.add(item)
                        found.append(item)

        return found, uses_typed_sdk
