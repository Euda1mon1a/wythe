"""Symbol-level reachability for TypeScript/JavaScript display code.

Answers "does any entry point (a Next.js page, layout, ...) reach this top-level symbol?"
so an unbacked HTTP call inside an exported hook nothing imports can be told apart from
one a user can actually trigger. The analysis is deliberately conservative: whenever it
cannot follow an import precisely it marks more code live, never less, so a real defect
is not demoted to dead code by a parsing gap.
"""

from __future__ import annotations

import json
import re
from collections import deque
from collections.abc import Callable
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from app.adapters.ts_execution import dynamic_imports, module_execution

GRAPH_SUFFIXES = (".ts", ".tsx", ".js", ".jsx", ".mjs")
_SKIP_DIRS = frozenset(
    {"node_modules", ".next", "out", "ui_dist", "dist", "build", "coverage", "public", "storybook-static"}
)
_NEXT_APP_ENTRY_STEMS = frozenset(
    {"page", "layout", "template", "loading", "error", "global-error", "not-found", "default"}
)
_REACT_SPA_ROOT_STEMS = frozenset(
    {"main", "index", "app", "root", "entry.client", "entry.server", "router", "routes"}
)
MODULE_SYMBOL = "<module>"

_IDENT_RE = re.compile(r"[A-Za-z_$][\w$]*")
_QUAL_MEMBER_RE = re.compile(
    r"(?<![.\w$])(?P<obj>[A-Za-z_$][\w$]*)\s*(?:\?\.)?\.\s*(?P<prop>[A-Za-z_$][\w$]*)\b"
)
_DECL_RE = re.compile(
    r"^(?P<export>export\s+)?(?P<default>default\s+)?(?:declare\s+)?(?:abstract\s+)?(?:async\s+)?"
    r"(?:function\s*\*?|const|let|var|class|enum|interface|type)\s+(?P<name>[A-Za-z_$][\w$]*)"
)
_EXPORT_DEFAULT_RE = re.compile(r"^export\s+default\b")
_IMPORT_FROM_RE = re.compile(
    r"""^[ \t]*import\s+(?P<type>type\s+)?(?P<clause>[^'";]*?)\s+from\s+['"](?P<spec>[^'"]+)['"]""",
    re.MULTILINE,
)
_IMPORT_SIDE_EFFECT_RE = re.compile(r"""^[ \t]*import\s+['"](?P<spec>[^'"]+)['"]""", re.MULTILINE)
_REEXPORT_NAMED_RE = re.compile(
    r"""^[ \t]*export\s+(?P<type>type\s+)?\{(?P<names>[^}]*)\}\s*from\s+['"](?P<spec>[^'"]+)['"]""",
    re.MULTILINE,
)
_REEXPORT_STAR_RE = re.compile(
    r"""^[ \t]*export\s+(?:type\s+)?\*\s*(?:as\s+(?P<ns>[\w$]+)\s*)?from\s+['"](?P<spec>[^'"]+)['"]""",
    re.MULTILINE,
)
_EXPORT_LIST_RE = re.compile(r"""^[ \t]*export\s+(?:type\s+)?\{(?P<names>[^}]*)\}(?!\s*from)""", re.MULTILINE)
_DYNAMIC_IMPORT_RE = re.compile(
    r"""\b(?:import|require)\(\s*['"`](?P<spec>[^'"`$]+)['"`]\s*\)"""
)


@dataclass
class _ModuleInfo:
    path: Path
    decl_ranges: list[tuple[str, int, int]] = field(default_factory=list)  # name, first, last line
    bodies: dict[str, str] = field(default_factory=dict)
    module_body: str = ""
    exports: dict[str, str] = field(default_factory=dict)  # exported name -> local name
    reexports: dict[str, tuple[str, str]] = field(default_factory=dict)  # exported -> (spec, imported)
    star_specs: list[str] = field(default_factory=list)
    bindings: dict[str, tuple[str, str]] = field(default_factory=dict)  # local -> (spec, imported|"*")
    side_effect_specs: list[str] = field(default_factory=list)
    # Names exported as types only (`export type {...}`, `export { type X }`): known, never runtime.
    type_exports: set[str] = field(default_factory=set)
    eager_symbols: set[str] = field(default_factory=set)
    execution_known: bool = False


def _blank_spans(text: str, spans: list[tuple[int, int]]) -> str:
    chars = list(text)
    for start, end in spans:
        for k in range(start, min(end, len(chars))):
            if chars[k] != "\n":
                chars[k] = " "
    return "".join(chars)


def _split_names(raw: str, all_types: bool = False) -> list[tuple[str, str, bool]]:
    """Parse `a, b as c, type T` into [(imported, local, is_type_only)] triples."""
    triples: list[tuple[str, str, bool]] = []
    for item in raw.split(","):
        item = " ".join(item.split())
        if not item:
            continue
        is_type = all_types or item.startswith("type ")
        item = item.removeprefix("type ")
        if " as " in item:
            left, right = item.split(" as ", 1)
            triples.append((left.strip(), right.strip(), is_type))
        else:
            triples.append((item, item, is_type))
    return triples


def parse_module(path: Path, text: str) -> _ModuleInfo:
    """Extract declarations, exports, imports and per-declaration bodies from cleaned source."""
    info = _ModuleInfo(path=path)
    statement_spans: list[tuple[int, int]] = []

    for m in _IMPORT_FROM_RE.finditer(text):
        statement_spans.append(m.span())
        if m.group("type"):
            continue
        clause = m.group("clause").strip()
        spec = m.group("spec")
        ns = re.search(r"\*\s*as\s+([A-Za-z_$][\w$]*)", clause)
        if ns:
            info.bindings[ns.group(1)] = (spec, "*")
        braces = re.search(r"\{([^}]*)\}", clause)
        if braces:
            for imported, local, is_type in _split_names(braces.group(1)):
                if not is_type:
                    info.bindings[local] = (spec, imported)
        head = re.sub(r"\{[^}]*\}|\*\s*as\s+[A-Za-z_$][\w$]*", "", clause).strip().strip(",").strip()
        if head and re.fullmatch(r"[A-Za-z_$][\w$]*", head):
            info.bindings[head] = (spec, "default")
    for m in _IMPORT_SIDE_EFFECT_RE.finditer(text):
        statement_spans.append(m.span())
        info.side_effect_specs.append(m.group("spec"))
    for m in _REEXPORT_NAMED_RE.finditer(text):
        statement_spans.append(m.span())
        for imported, exported, is_type in _split_names(m.group("names"), bool(m.group("type"))):
            if is_type:
                info.type_exports.add(exported)
            else:
                info.reexports[exported] = (m.group("spec"), imported)
    for m in _REEXPORT_STAR_RE.finditer(text):
        statement_spans.append(m.span())
        if m.group(0).lstrip().startswith("export type"):
            continue
        if m.group("ns"):
            info.reexports[m.group("ns")] = (m.group("spec"), "*")
        else:
            info.star_specs.append(m.group("spec"))
    for m in _EXPORT_LIST_RE.finditer(text):
        statement_spans.append(m.span())
        list_is_type = m.group(0).lstrip().startswith("export type")
        for local, exported, is_type in _split_names(m.group("names"), list_is_type):
            if is_type:
                info.type_exports.add(exported)
            else:
                info.exports[exported] = local

    blanked = _blank_spans(text, statement_spans)
    lines = blanked.split("\n")

    starts: list[tuple[str, int, bool, bool]] = []  # name, 1-based line, exported, default
    for idx, line in enumerate(lines, start=1):
        if not line or line[0].isspace():
            continue
        dm = _DECL_RE.match(line)
        if dm:
            starts.append((dm.group("name"), idx, bool(dm.group("export")), bool(dm.group("default"))))
        elif _EXPORT_DEFAULT_RE.match(line):
            starts.append(("default", idx, True, True))

    first_decl_line = starts[0][1] if starts else len(lines) + 1
    info.module_body = "\n".join(lines[: first_decl_line - 1])
    for pos, (name, start, exported, is_default) in enumerate(starts):
        end = starts[pos + 1][1] - 1 if pos + 1 < len(starts) else len(lines)
        body = "\n".join(lines[start - 1 : end])
        info.bodies[name] = (info.bodies[name] + "\n" + body) if name in info.bodies else body
        info.decl_ranges.append((name, start, end))
        if exported and not is_default:
            info.exports.setdefault(name, name)
        if is_default:
            info.exports["default"] = name
    execution = module_execution(text)
    if execution is not None:
        info.execution_known = True
        info.eager_symbols = execution.eager_symbols
        info.module_body += "\n" + execution.statements
        ranges = execution.ranges
        exact_names = {name for name, _, _ in ranges}
        info.decl_ranges = ranges + [r for r in info.decl_ranges if r[0] not in exact_names]
        info.bodies.update(execution.bodies)
        info.exports.update(execution.exports)
    return info


def _strip_json_comments(raw: str) -> str:
    out: list[str] = []
    i = 0
    n = len(raw)
    in_str = False
    while i < n:
        ch = raw[i]
        if in_str:
            out.append(ch)
            if ch == "\\" and i + 1 < n:
                out.append(raw[i + 1])
                i += 2
                continue
            if ch == '"':
                in_str = False
            i += 1
            continue
        if ch == '"':
            in_str = True
            out.append(ch)
            i += 1
            continue
        if raw.startswith("//", i):
            while i < n and raw[i] != "\n":
                i += 1
            continue
        if raw.startswith("/*", i):
            end = raw.find("*/", i + 2)
            i = n if end < 0 else end + 2
            continue
        out.append(ch)
        i += 1
    return re.sub(r",(\s*[}\]])", r"\1", "".join(out))


def load_tsconfig_paths(fe_dir: Path) -> tuple[Path | None, list[tuple[str, list[Path]]]]:
    """Return (baseUrl dir, [(alias pattern, [target patterns])]) from tsconfig/jsconfig, if present."""
    for name in ("tsconfig.json", "jsconfig.json"):
        cfg = fe_dir / name
        if not cfg.is_file():
            continue
        try:
            data = json.loads(_strip_json_comments(cfg.read_text(encoding="utf-8")))
        except (OSError, UnicodeError, ValueError):
            return None, []
        opts = data.get("compilerOptions") or {}
        base_url = opts.get("baseUrl")
        base_dir = (fe_dir / base_url).resolve() if isinstance(base_url, str) else None
        anchor = base_dir or fe_dir.resolve()
        aliases: list[tuple[str, list[Path]]] = []
        paths = opts.get("paths") or {}
        if isinstance(paths, dict):
            for pattern, targets in paths.items():
                if isinstance(pattern, str) and isinstance(targets, list):
                    aliases.append((pattern, [anchor / t for t in targets if isinstance(t, str)]))
        aliases.sort(key=lambda a: len(a[0]), reverse=True)
        return base_dir, aliases
    return None, []


def make_resolver(
    fe_dir: Path,
    src_root: Path,
    known_files: set[Path],
    *,
    ws_resolver: Any | None = None,
) -> Callable[[str, Path], Path | None]:
    """Build a spec resolver honoring relative imports, tsconfig `paths`, `@/`, and `baseUrl`."""
    base_dir, aliases = load_tsconfig_paths(fe_dir)

    def _probe(base: Path) -> Path | None:
        candidates = [base, *(Path(f"{base}{ext}") for ext in GRAPH_SUFFIXES)]
        candidates += [base / f"index{ext}" for ext in GRAPH_SUFFIXES]
        for cand in candidates:
            try:
                resolved = cand.resolve()
            except OSError:
                continue
            if resolved in known_files:
                return resolved
        return None

    cache: dict[tuple[str, Path], Path | None] = {}

    def resolve_import_spec(spec: str, current_file: Path) -> Path | None:
        key = (spec, current_file.parent)
        if key in cache:
            return cache[key]
        result: Path | None = None
        if spec.startswith("."):
            result = _probe(current_file.parent / spec)
        else:
            for pattern, targets in aliases:
                if pattern.endswith("*"):
                    prefix = pattern[:-1]
                    if not spec.startswith(prefix):
                        continue
                    rest = spec[len(prefix) :]
                    for tgt in targets:
                        result = _probe(Path(str(tgt).replace("*", rest)))
                        if result:
                            break
                elif spec == pattern:
                    for tgt in targets:
                        result = _probe(tgt)
                        if result:
                            break
                if result:
                    break
            if result is None and spec.startswith("@/"):
                result = _probe(src_root / spec[2:])
            if result is None and base_dir is not None:
                result = _probe(base_dir / spec)
            if result is None and ws_resolver is not None:
                ws_hit = ws_resolver.resolve_import(spec, current_file, exts=GRAPH_SUFFIXES)
                if ws_hit is not None and ws_hit.resolve() in known_files:
                    result = ws_hit.resolve()
        cache[key] = result
        return result

    return resolve_import_spec


def collect_graph_files(fe_dir: Path) -> list[Path]:
    """All runtime JS/TS modules under the frontend dir, excluding tests, stories and build output."""
    found: list[Path] = []
    for fpath in sorted(fe_dir.rglob("*")):
        if fpath.suffix not in GRAPH_SUFFIXES or not fpath.is_file():
            continue
        rel_parts = fpath.relative_to(fe_dir).parts
        if any(p in _SKIP_DIRS for p in rel_parts) or "__tests__" in rel_parts:
            continue
        name = fpath.name
        if (
            name.endswith(".d.ts")
            or any(tag in name for tag in (".test.", ".spec.", ".stories."))
            or name == "api-generated.ts"
        ):
            continue
        found.append(fpath.resolve())
    return found


def _app_relative(path: Path, src_root: Path, fe_dir: Path) -> tuple[str, ...] | None:
    for root in (src_root, fe_dir):
        try:
            return path.relative_to(root.resolve()).parts
        except ValueError:
            continue
    return None


def is_nextjs_entry(path: Path, src_root: Path, fe_dir: Path) -> bool:
    """Next.js renders these files without anyone importing them."""
    parts = _app_relative(path, src_root, fe_dir)
    if not parts:
        return False
    if parts[0] == "app":
        return path.stem in _NEXT_APP_ENTRY_STEMS
    if parts[0] == "pages":
        return len(parts) < 2 or parts[1] != "api"
    return False


def nextjs_route_handler_patterns(files: list[Path], src_root: Path, fe_dir: Path) -> list[str]:
    """Regexes for paths served by App Router `route.ts` handlers and Pages Router `pages/api/*`."""
    patterns: list[str] = []
    for path in files:
        parts = _app_relative(path, src_root, fe_dir)
        if not parts:
            continue
        if path.stem in ("[trpc]", "[[...trpc]]") or any(p in ("[trpc]", "[[...trpc]]") for p in parts):
            continue
        if parts[0] == "app" and path.stem == "route":
            segs = list(parts[1:-1])
        elif parts[0] == "pages" and len(parts) >= 2 and parts[1] == "api":
            segs = list(parts[:-1]) + ([] if path.stem == "index" else [path.stem])
            segs = segs[1:]  # drop "pages"
        else:
            continue
        rx = ""
        for seg in segs:
            if (seg.startswith("(") and seg.endswith(")")) or seg.startswith("@"):
                continue
            if seg.startswith("[[...") and seg.endswith("]]"):
                rx += r"(?:/.*)?"
            elif seg.startswith("[...") and seg.endswith("]"):
                rx += r"/.+"
            elif seg.startswith("[") and seg.endswith("]"):
                rx += r"/[^/]+"
            else:
                rx += "/" + re.escape(seg)
        patterns.append(rf"^{rx or '/'}/?$")
    return sorted(set(patterns))


class ReachabilityIndex:
    """Forward symbol liveness from entry modules over the import graph."""

    def __init__(
        self,
        modules: dict[Path, _ModuleInfo],
        roots: set[Path],
        resolve: Callable[[str, Path], Path | None],
        display_root: Path,
        unreadable: set[Path] | None = None,
    ) -> None:
        self._modules = modules
        self._resolve = resolve
        self._display_root = display_root
        self._unreadable = unreadable or set()
        self._roots = set(roots)
        self.has_roots = bool(roots)
        self._live: dict[tuple[Path, str], tuple[Path, str] | None] = {}
        self._parents: dict[tuple[Path, str], set[tuple[Path, str]]] = {}
        self._queue: deque[tuple[Path, str]] = deque()
        self._dynamic_sites: set[tuple[Path, str, str, str]] = set()
        for root in sorted(roots):
            self._mark(root, MODULE_SYMBOL, None)
            info = modules.get(root)
            if info is not None:
                for name in info.bodies:
                    self._mark(root, name, (root, MODULE_SYMBOL))
        self._run()

    def _mark(self, path: Path, sym: str, parent: tuple[Path, str] | None) -> None:
        key = (path, sym)
        if parent is not None:
            self._parents.setdefault(key, set()).add(parent)
        if key not in self._live:
            self._live[key] = parent
            self._queue.append(key)

    def _mark_import(self, from_path: Path, spec: str, name: str, parent: tuple[Path, str]) -> None:
        target = self._resolve(spec, from_path)
        if target is not None:
            self._mark_export(target, name, parent, set())

    def _exports_name(self, path: Path, name: str, seen: set[Path]) -> bool:
        if path in seen:
            return False
        seen.add(path)
        info = self._modules.get(path)
        if info is None:
            return False
        base_name, dot, _member = name.partition(".")
        candidates = (name, base_name) if dot else (name,)
        if any(c in info.exports or c in info.reexports or c in info.type_exports for c in candidates):
            return True
        for spec in info.star_specs:
            nxt = self._resolve(spec, path)
            if nxt is not None and any(self._exports_name(nxt, c, seen) for c in candidates):
                return True
        return False

    def _mark_export(self, target: Path, name: str, parent: tuple[Path, str], seen: set[Path]) -> None:
        if target in seen:
            return
        seen.add(target)
        info = self._modules.get(target)
        if info is None:
            return
        self._mark(target, MODULE_SYMBOL, parent)
        if name == "*":
            for decl in info.bodies:
                self._mark(target, decl, parent)
            for spec, imported in info.reexports.values():
                self._mark_import(target, spec, imported, parent)
            for spec in info.star_specs:
                self._mark_import(target, spec, "*", parent)
            return
        if "." in name and name not in info.exports and name not in info.bodies and name not in info.reexports:
            base_name, _, member = name.partition(".")
            local_cls = info.exports.get(base_name)
            if local_cls is None and base_name in info.bodies:
                local_cls = base_name
            if local_cls is not None:
                qual_local = f"{local_cls}.{member}"
                if qual_local in info.bodies:
                    self._mark(target, qual_local, parent)
                    return
                if local_cls in info.bodies:
                    self._mark(target, local_cls, parent)
                    return
                if local_cls in info.bindings:
                    spec, imported = info.bindings[local_cls]
                    forwarded = f"{imported}.{member}" if imported not in ("*", "default") else imported
                    self._mark_import(target, spec, forwarded, parent)
                    return
            if base_name in info.reexports:
                spec, imported = info.reexports[base_name]
                forwarded = f"{imported}.{member}" if imported not in ("*", "default") else imported
                self._mark_import(target, spec, forwarded, parent)
                return
            if base_name in info.type_exports:
                return
            matched = False
            for spec in info.star_specs:
                nxt = self._resolve(spec, target)
                if nxt is not None and self._exports_name(nxt, base_name, set()):
                    matched = True
                    self._mark_export(nxt, name, parent, seen)
            if not matched:
                for decl in info.bodies:
                    self._mark(target, decl, parent)
                for spec in info.star_specs:
                    self._mark_import(target, spec, "*", parent)
            return
        local = info.exports.get(name)
        if local is None and name in info.bodies:
            local = name
        if local is not None and local in info.bodies:
            self._mark(target, local, parent)
            return
        if local is not None:
            class_methods = [k for k in info.bodies if k.startswith(f"{local}.")]
            if class_methods:
                for m in class_methods:
                    self._mark(target, m, parent)
                return
        if local is not None and local in info.bindings:
            spec, imported = info.bindings[local]
            self._mark_import(target, spec, imported, parent)
            return
        if name in info.reexports:
            spec, imported = info.reexports[name]
            self._mark_import(target, spec, imported, parent)
            return
        if name in info.type_exports:
            return  # a type: nothing runs
        matched = False
        for spec in info.star_specs:
            nxt = self._resolve(spec, target)
            if nxt is not None and self._exports_name(nxt, name, set()):
                matched = True
                self._mark_export(nxt, name, parent, seen)
        if not matched:
            # Unknown export: stay conservative and treat everything the module offers as used.
            for decl in info.bodies:
                self._mark(target, decl, parent)
            for spec in info.star_specs:
                self._mark_import(target, spec, "*", parent)

    def _run(self) -> None:
        while self._queue:
            path, sym = self._queue.popleft()
            info = self._modules.get(path)
            if info is None:
                continue
            if sym != MODULE_SYMBOL:
                self._mark(path, MODULE_SYMBOL, (path, sym))
                if "." not in sym:
                    for m in info.bodies:
                        if m.startswith(f"{sym}."):
                            self._mark(path, m, (path, sym))
                body = info.bodies.get(sym, "")
            else:
                body = info.module_body
                for name in info.eager_symbols if info.execution_known else info.bodies:
                    self._mark(path, name, (path, sym))
                # Even a selective barrel import evaluates all its runtime dependencies.
                specs = {s for s, _ in info.bindings.values()}
                specs.update(s for s, _ in info.reexports.values())
                specs.update(info.star_specs)
                for spec in sorted(specs):
                    target = self._resolve(spec, path)
                    if target is not None:
                        self._mark(target, MODULE_SYMBOL, (path, sym))
                for spec in info.side_effect_specs:
                    self._mark_import(path, spec, "*", (path, sym))
            imports = dynamic_imports(body)
            if imports is None:
                imports = [(m.group("spec"), "*") for m in _DYNAMIC_IMPORT_RE.finditer(body)]
                if len(re.findall(r"\b(?:import|require)\s*\(", body)) > len(imports):
                    imports.append((None, "*"))
            for spec, selected in imports:
                self._dynamic_sites.add((path, sym, spec or "<runtime specifier>", selected))
                if spec is not None:
                    self._mark_import(path, spec, selected, (path, sym))
            qual_obj_spans: set[tuple[int, int]] = set()
            for qm in _QUAL_MEMBER_RE.finditer(body):
                obj = qm.group("obj")
                prop = qm.group("prop")
                qual_obj_spans.add(qm.span("obj"))
                qual_same = f"{obj}.{prop}"
                if qual_same != sym and qual_same in info.bodies:
                    self._mark(path, qual_same, (path, sym))
                elif obj != sym and obj in info.bodies and not any(k.startswith(f"{obj}.") for k in info.bodies):
                    self._mark(path, obj, (path, sym))
                binding = info.bindings.get(obj)
                if binding is not None:
                    spec, imported = binding
                    if imported == "*":
                        self._mark_import(path, spec, prop, (path, sym))
                    elif imported == "default":
                        self._mark_import(path, spec, "default", (path, sym))
                    else:
                        self._mark_import(path, spec, f"{imported}.{prop}", (path, sym))
            bare_tokens: set[str] = set()
            for tm in _IDENT_RE.finditer(body):
                start, end = tm.span()
                if (start, end) in qual_obj_spans:
                    continue
                if start > 0 and body[start - 1] == ".":
                    continue
                bare_tokens.add(tm.group(0))
            for tok in bare_tokens:
                if tok != sym:
                    if tok in info.bodies:
                        self._mark(path, tok, (path, sym))
                    for m in info.bodies:
                        if m.startswith(f"{tok}."):
                            self._mark(path, m, (path, sym))
                binding = info.bindings.get(tok)
                if binding is not None:
                    self._mark_import(path, binding[0], binding[1], (path, sym))

    def import_edges(self) -> list[tuple[Path, Path]]:
        """Cross-file import paths, including dynamic imports and barrel initialization."""
        edges: set[tuple[Path, Path]] = set()
        for path, symbol in self._live:
            info = self._modules.get(path)
            if info is None or (symbol == MODULE_SYMBOL and not info.module_body.strip()):
                continue
            seen: set[tuple[Path, str]] = set()
            pending = list(self._parents.get((path, symbol), set()))
            # Walk through barrel/module evaluation hops to the importing declaration.
            while pending:
                parent = pending.pop()
                if parent in seen:
                    continue
                seen.add(parent)
                if parent[0] != path and parent[1] != MODULE_SYMBOL:
                    edges.add((parent[0], path))
                else:
                    pending.extend(self._parents.get(parent, set()))
        return sorted(edges)

    def node_summary(self, path: Path) -> str:
        if not self.has_roots:
            return "Entry-point reachability is unknown (no entry modules discovered)."
        if any(p == path and s != MODULE_SYMBOL for p, s in self._live):
            return "An entry path reaches declarations here (including eager initialization)."
        if (path, MODULE_SYMBOL) in self._live:
            return "Imported for module evaluation; no declaration use was discovered."
        if self._unreadable:
            return "Entry-point reachability is unknown because some source files could not be read."
        return "No discovered entry path; external callers and runtime registration remain unproven."

    def analysis_notes(self) -> list[str]:
        notes = [
            ("Display reachability is static evidence, not removal approval. Import-time initializers "
            "and barrel dependencies are retained; external entry points and runtime registration "
            "require separate checks. Blast radius follows the extracted graph, including declared import edges.")
        ]
        for path in sorted(self._unreadable):
            notes.append(f"Unreadable source {path.relative_to(self._display_root)}: absence of a caller is unresolved.")
        for path, symbol, spec, selected in sorted(self._dynamic_sites):
            mode = "all exports conservatively retained" if selected == "*" else f"selected export {selected}"
            if spec == "<runtime specifier>":
                mode = "target unresolved; absence of an edge is not evidence of no caller"
            notes.append(f"Dynamic import {path.relative_to(self._display_root)}#{symbol}: {spec}; {mode}.")
        return notes

    def enclosing_symbol(self, path: Path, line: int) -> str:
        info = self._modules.get(path)
        if info is not None:
            matches = [(name, first, last) for name, first, last in info.decl_ranges if first <= line <= last]
            if len(matches) == 1:
                return matches[0][0]
            if len(matches) == 2:
                # A class declaration spans its own static/instance methods; pick the nested method.
                (n1, f1, l1), (n2, f2, l2) = matches
                if n2.startswith(f"{n1}.") and f1 <= f2 and l2 <= l1:
                    return n2
                if n1.startswith(f"{n2}.") and f2 <= f1 and l1 <= l2:
                    return n1
            # Calls currently carry line numbers, not columns. Shared-line declarations
            # cannot be separated reliably and must retain module-level reachability.
        return MODULE_SYMBOL

    def is_live(self, path: Path, sym: str) -> bool | None:
        if (path, sym) in self._live:
            return True
        if self._unreadable:
            return None
        if any(spec == "<runtime specifier>" for _, _, spec, _ in self._dynamic_sites):
            return None  # A runtime-selected module could be this one; do not assert dead code.
        return False

    def reaching_roots(
        self,
        path: Path,
        sym: str,
        stop_paths: set[Path] | None = None,
    ) -> list[Path]:
        """Return entry/page file paths whose execution graph actually reaches `(path, sym)`."""
        start = (path, sym)
        if start not in self._live:
            return []
        stops = stop_paths or set()
        if path in stops:
            return [path]
        found: set[Path] = set()
        seen: set[tuple[Path, str]] = {start}
        queue: deque[tuple[Path, str]] = deque([start])
        while queue:
            cur = queue.popleft()
            parents = self._parents.get(cur, set())
            if not parents:
                if cur[0] in self._roots or cur[0] in stops:
                    found.add(cur[0])
                continue
            for parent in parents:
                p_path = parent[0]
                if p_path != path and p_path in stops:
                    found.add(p_path)
                    continue
                if parent not in seen:
                    seen.add(parent)
                    queue.append(parent)
        return sorted(found)

    def trail(self, path: Path, sym: str, limit: int = 8) -> tuple[str, ...]:
        hops: list[str] = []
        key: tuple[Path, str] | None = (path, sym)
        seen: set[tuple[Path, str]] = set()
        while key is not None and key not in seen and len(hops) < 64:
            seen.add(key)
            kpath, ksym = key
            try:
                rel = kpath.relative_to(self._display_root).as_posix()
            except ValueError:
                rel = kpath.name
            label = rel if ksym == MODULE_SYMBOL else f"{rel}#{ksym}"
            if not hops or hops[-1] != label:
                hops.append(label)
            key = self._live.get(key)
        hops.reverse()
        if len(hops) > limit:
            hops = [hops[0], "...", *hops[-(limit - 2) :]]
        return tuple(hops)


def build_nextjs_reachability(
    fe_dir: Path,
    src_root: Path,
    display_root: Path,
    clean: Callable[[str], str],
    pre_cleaned: dict[Path, str] | None = None,
) -> tuple[ReachabilityIndex, list[str]]:
    """Return the reachability index plus `route.ts`/`pages/api` path patterns for a Next.js app."""
    from app.adapters.ts_workspace import WorkspaceResolver

    files = collect_graph_files(fe_dir)
    known = set(files)
    ws_res = WorkspaceResolver.build(display_root, extra_roots=(fe_dir, src_root))
    resolve = make_resolver(fe_dir, src_root, known, ws_resolver=ws_res)
    modules: dict[Path, _ModuleInfo] = {}
    for path in files:
        text = (pre_cleaned or {}).get(path)
        if text is None:
            try:
                text = clean(path.read_text(encoding="utf-8"))
            except (OSError, UnicodeError):
                continue
        modules[path] = parse_module(path, text)
    roots = {p for p in files if is_nextjs_entry(p, src_root, fe_dir)}
    index = ReachabilityIndex(modules, roots, resolve, display_root, known - modules.keys())
    return index, nextjs_route_handler_patterns(files, src_root, fe_dir)


def is_react_spa_entry(path: Path, src_root: Path, fe_dir: Path) -> bool:
    """True for Vite/CRA/React Router/TanStack/Remix entry points and file-routed pages."""
    parts = _app_relative(path, src_root, fe_dir)
    if not parts:
        return False
    if len(parts) == 1 and path.stem.lower() in _REACT_SPA_ROOT_STEMS:
        return True
    if parts[0] in ("pages", "routes", "views"):
        return True
    return len(parts) > 1 and parts[0] == "app" and parts[1] in ("routes", "pages", "views")


def build_react_spa_reachability(
    fe_dir: Path,
    src_root: Path,
    display_root: Path,
    clean: Callable[[str], str],
    pre_cleaned: dict[Path, str] | None = None,
) -> ReachabilityIndex:
    """Return the symbol-level reachability index for a React SPA / Vite / Remix frontend."""
    from app.adapters.ts_workspace import WorkspaceResolver

    files = collect_graph_files(fe_dir)
    known = set(files)
    ws_res = WorkspaceResolver.build(display_root, extra_roots=(fe_dir, src_root))
    resolve = make_resolver(fe_dir, src_root, known, ws_resolver=ws_res)
    modules: dict[Path, _ModuleInfo] = {}
    for path in files:
        text = (pre_cleaned or {}).get(path)
        if text is None:
            try:
                text = clean(path.read_text(encoding="utf-8"))
            except (OSError, UnicodeError):
                continue
        modules[path] = parse_module(path, text)
    roots = {p for p in files if is_react_spa_entry(p, src_root, fe_dir)}
    return ReachabilityIndex(modules, roots, resolve, display_root, known - modules.keys())
