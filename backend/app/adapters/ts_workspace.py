"""Shared TypeScript workspace resolution, tsconfig path aliases, and constant/enum lookup."""

from __future__ import annotations

import json
import re
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from app.adapters.treesitter_engine import _get_parser, has_treesitter

TS_SOURCE_EXTS = (".ts", ".tsx", ".mts", ".cts", ".js", ".jsx", ".mjs", ".cjs")
_SUFFIX_SWAPS: dict[str, tuple[str, ...]] = {
    ".js": (".ts", ".tsx", ".js"),
    ".jsx": (".tsx", ".ts", ".jsx"),
    ".mjs": (".mts", ".ts", ".mjs"),
    ".cjs": (".cts", ".ts", ".cjs"),
}
_EXT_RE = re.compile(r"""['"](?P<spec>[^'"]+)['"]""")
_CONST_STR_RE = re.compile(
    r"""(?:^|[;\r\n])[ \t]*(?:export\s+)?const\s+(?P<name>[A-Za-z_$][\w$]*)\s*(?::[^=\n]+)?=\s*(?P<quote>['"`])(?P<val>[^'"`\n]*)(?P=quote)"""
)
_ENUM_BLOCK_RE = re.compile(
    r"""(?:export\s+)?(?:const\s+)?enum\s+(?P<ename>[A-Za-z_$][\w$]*)\s*\{(?P<body>(?:[^}'"`\\]|'[^']*'|"[^"]*"|`[^`]*`|\\.)*?)\}"""
)
_ENUM_MEMBER_RE = re.compile(
    r"""(?:['"](?P<qkey>[A-Za-z0-9_$-]+)['"]|(?P<key>[A-Za-z_$][\w$]*))\s*=\s*(?P<quote>['"`])(?P<val>[^'"`\n]*)(?P=quote)"""
)
_NAMED_IMPORT_RE = re.compile(
    r"""(?:^|[;\r\n])[ \t]*import\s+(?!type\b)(?P<body>[^;\r\n]*?)\s+from\s+['"](?P<spec>[^'"]+)['"]"""
)
_REEXPORT_NAMED_RE = re.compile(
    r"""(?:^|[;\r\n])[ \t]*export\s+(?!type\b)\{(?P<clause>[^}]+)\}\s+from\s+['"](?P<spec>[^'"]+)['"]"""
)
_REEXPORT_STAR_RE = re.compile(
    r"""(?:^|[;\r\n])[ \t]*export\s+\*\s+from\s+['"](?P<spec>[^'"]+)['"]"""
)


def strip_jsonc(raw: str) -> str:
    """Strip // comments, /* */ comments, and trailing commas outside JSON string literals."""
    out: list[str] = []
    n = len(raw)
    i = 0
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
        elif ch == "/" and i + 1 < n and raw[i + 1] == "/":
            i += 2
            while i < n and raw[i] != "\n":
                i += 1
        elif ch == "/" and i + 1 < n and raw[i + 1] == "*":
            i += 2
            while i + 1 < n and not (raw[i] == "*" and raw[i + 1] == "/"):
                if raw[i] == "\n":
                    out.append("\n")
                i += 1
            i += 2
        else:
            out.append(ch)
            i += 1
    cleaned = "".join(out)
    # Remove trailing commas before `}` or `]` outside strings (safe second pass)
    res: list[str] = []
    in_str = False
    j = 0
    m = len(cleaned)
    while j < m:
        ch = cleaned[j]
        if in_str:
            res.append(ch)
            if ch == "\\" and j + 1 < m:
                res.append(cleaned[j + 1])
                j += 2
                continue
            if ch == '"':
                in_str = False
            j += 1
            continue
        if ch == '"':
            in_str = True
            res.append(ch)
            j += 1
        elif ch == ",":
            k = j + 1
            while k < m and cleaned[k] in " \t\r\n":
                k += 1
            if k < m and cleaned[k] in ("}", "]"):
                j += 1
                continue
            res.append(ch)
            j += 1
        else:
            res.append(ch)
            j += 1
    return "".join(res)


@dataclass
class TsConfigPaths:
    config_dir: Path
    base_url: Path
    paths: dict[str, list[tuple[Path, str]]] = field(default_factory=dict)


@dataclass(frozen=True)
class TsImportBinding:
    spec: str
    imported_names: tuple[str, ...]
    local_names: tuple[str, ...]
    namespace_names: tuple[str, ...]
    line: int


@dataclass(frozen=True)
class TsDynamicImportSite:
    spec: str | None
    imported_names: tuple[str, ...]
    local_names: tuple[str, ...]
    line: int
    raw_expr: str
    decl_start: int = -1
    decl_end: int = -1
    is_direct_invoked: bool = False


def _load_jsonc_file(path: Path) -> dict[str, Any]:
    if not path.is_file():
        return {}
    try:
        data = json.loads(strip_jsonc(path.read_text(encoding="utf-8", errors="replace")))
        return data if isinstance(data, dict) else {}
    except (OSError, ValueError):
        return {}


def load_tsconfig_paths(config_path: Path, *, seen: frozenset[Path] = frozenset()) -> TsConfigPaths:
    resolved = config_path.resolve()
    cfg_dir = resolved.parent
    if resolved in seen or not resolved.is_file():
        return TsConfigPaths(config_dir=cfg_dir, base_url=cfg_dir)

    data = _load_jsonc_file(resolved)
    base_cfg: TsConfigPaths | None = None
    ext_val = data.get("extends")
    if isinstance(ext_val, str) and ext_val.startswith("."):
        ext_cand = (cfg_dir / ext_val).resolve()
        if not ext_cand.is_file() and not ext_cand.name.endswith(".json"):
            ext_cand = Path(f"{ext_cand}.json")
        if ext_cand.is_file():
            base_cfg = load_tsconfig_paths(ext_cand, seen=seen | {resolved})

    comp = data.get("compilerOptions")
    if not isinstance(comp, dict):
        comp = {}

    raw_base_url = comp.get("baseUrl")
    if isinstance(raw_base_url, str):
        base_url = (cfg_dir / raw_base_url).resolve()
    elif base_cfg is not None:
        base_url = base_cfg.base_url
    else:
        base_url = cfg_dir

    merged_paths: dict[str, list[tuple[Path, str]]] = dict(base_cfg.paths) if base_cfg is not None else {}
    raw_paths = comp.get("paths")
    if isinstance(raw_paths, dict):
        for pat, targets in raw_paths.items():
            if not isinstance(pat, str) or not isinstance(targets, list):
                continue
            resolved_targets: list[tuple[Path, str]] = []
            for t in targets:
                if not isinstance(t, str):
                    continue
                if "*" in t:
                    pre, suf = t.split("*", 1)
                    resolved_targets.append(((base_url / (pre.removeprefix("./") or ".")).resolve(), suf))
                else:
                    resolved_targets.append(((base_url / t).resolve(), ""))
            if resolved_targets:
                merged_paths[pat] = resolved_targets

    return TsConfigPaths(config_dir=cfg_dir, base_url=base_url, paths=merged_paths)


def _is_within(path: Path, root: Path) -> bool:
    try:
        path.resolve().relative_to(root.resolve())
        return True
    except ValueError:
        return False


def probe_ts_candidate(
    cand: Path,
    repo_root: Path,
    *,
    exts: tuple[str, ...] = TS_SOURCE_EXTS,
) -> Path | None:
    """Resolve a module path candidate to an existing source file inside `repo_root`."""
    try:
        resolved = cand.resolve()
    except OSError:
        return None
    if not _is_within(resolved, repo_root):
        return None
    if resolved.is_file():
        if resolved.suffix in exts:
            return resolved
        return None
    suf = cand.suffix.lower()
    if suf in _SUFFIX_SWAPS:
        stem_path = cand.with_suffix("")
        for swap_ext in _SUFFIX_SWAPS[suf]:
            p = Path(f"{stem_path}{swap_ext}").resolve()
            if _is_within(p, repo_root) and p.is_file():
                return p
    for ext in exts:
        p = Path(f"{cand}{ext}").resolve()
        if _is_within(p, repo_root) and p.is_file():
            return p
    for ext in exts:
        p = (cand / f"index{ext}").resolve()
        if _is_within(p, repo_root) and p.is_file():
            return p
    return None


def _extract_pkg_source_entry(pkg_dir: Path, entry_val: Any) -> Path | None:
    if isinstance(entry_val, str):
        return (pkg_dir / entry_val).resolve()
    if isinstance(entry_val, dict):
        for key in (".", "source", "import", "default", "module", "require", "types"):
            sub = _extract_pkg_source_entry(pkg_dir, entry_val.get(key))
            if sub is not None:
                return sub
    return None


@dataclass
class WorkspaceResolver:
    """Resolves relative, tsconfig path-aliased, and monorepo workspace imports."""

    repo_root: Path
    tsconfigs: dict[Path, TsConfigPaths] = field(default_factory=dict)
    pkg_roots: dict[str, Path] = field(default_factory=dict)
    pkg_entries: dict[str, Path] = field(default_factory=dict)
    _const_cache: dict[Path, tuple[dict[str, str], dict[str, dict[str, str]]]] = field(
        default_factory=dict, repr=False
    )

    @classmethod
    def build(cls, repo_root: Path, extra_roots: tuple[Path, ...] = ()) -> WorkspaceResolver:
        root = repo_root.resolve()
        res = cls(repo_root=root)
        roots_to_scan = [root, *extra_roots]
        for sub_name in ("backend", "server", "frontend", "web", "client"):
            sub_dir = root / sub_name
            if sub_dir.is_dir():
                roots_to_scan.append(sub_dir.resolve())
        for pat in ("packages/*", "apps/*"):
            for d in sorted(root.glob(pat)):
                if d.is_dir() and "node_modules" not in d.parts:
                    roots_to_scan.append(d.resolve())

        seen_dirs: set[Path] = set()
        for d in roots_to_scan:
            rd = d.resolve()
            if rd in seen_dirs:
                continue
            seen_dirs.add(rd)
            for cfg_name in ("tsconfig.json", "tsconfig.server.json", "tsconfig.base.json"):
                cfg_file = rd / cfg_name
                if cfg_file.is_file():
                    res.tsconfigs[rd] = load_tsconfig_paths(cfg_file)
                    break
            pkg_json = rd / "package.json"
            if pkg_json.is_file():
                try:
                    data = json.loads(pkg_json.read_text(encoding="utf-8", errors="replace"))
                except (OSError, ValueError):
                    data = {}
                if isinstance(data, dict) and isinstance(data.get("name"), str):
                    pkg_name = data["name"].strip()
                    if pkg_name:
                        res.pkg_roots[pkg_name] = rd
                        entry = (
                            _extract_pkg_source_entry(rd, data.get("exports"))
                            if isinstance(data.get("exports"), (str, dict))
                            else None
                        )
                        if entry is None:
                            for field_name in ("source", "module", "main"):
                                raw_e = data.get(field_name)
                                if isinstance(raw_e, str):
                                    entry = (rd / raw_e).resolve()
                                    break
                        if entry is not None:
                            res.pkg_entries[pkg_name] = entry
        return res

    def _nearest_tsconfig(self, from_file: Path) -> TsConfigPaths | None:
        cur = from_file.resolve().parent
        while _is_within(cur, self.repo_root):
            if cur in self.tsconfigs:
                return self.tsconfigs[cur]
            if cur == self.repo_root:
                break
            cur = cur.parent
        return self.tsconfigs.get(self.repo_root)

    def resolve_import(
        self,
        spec: str,
        from_file: Path,
        *,
        exts: tuple[str, ...] = TS_SOURCE_EXTS,
    ) -> Path | None:
        spec = spec.strip()
        if not spec:
            return None

        # 1. Relative import
        if spec.startswith("."):
            return probe_ts_candidate((from_file.parent / spec).resolve(), self.repo_root, exts=exts)

        # 2. Nearest tsconfig `paths` and `baseUrl`
        cfg = self._nearest_tsconfig(from_file)
        if cfg is not None:
            # Match longest wildcard prefix first for specificity
            matches: list[tuple[int, str, list[tuple[Path, str]]]] = []
            for pat, targets in cfg.paths.items():
                if "*" in pat:
                    pre, suf = pat.split("*", 1)
                    if spec.startswith(pre) and spec.endswith(suf) and len(spec) >= len(pre) + len(suf):
                        star_val = spec[len(pre) : len(spec) - len(suf) if suf else len(spec)]
                        matches.append((len(pre) + len(suf), star_val, targets))
                elif spec == pat:
                    matches.append((len(pat) + 1000, "", targets))
            matches.sort(key=lambda item: item[0], reverse=True)
            for _score, star_val, targets in matches:
                for tgt_pre, tgt_suf in targets:
                    sub = f"{star_val}{tgt_suf}".lstrip("/") if star_val or tgt_suf else ""
                    cand = (tgt_pre / sub).resolve() if sub else tgt_pre
                    hit = probe_ts_candidate(cand, self.repo_root, exts=exts)
                    if hit is not None:
                        return hit

            # Fallback shortcuts relative to tsconfig baseUrl/src/lib
            if spec.startswith("@/"):
                src_dir = cfg.config_dir / "src" if (cfg.config_dir / "src").is_dir() else cfg.base_url
                hit = probe_ts_candidate((src_dir / spec[2:]).resolve(), self.repo_root, exts=exts)
                if hit is not None:
                    return hit
            elif spec.startswith("$lib/"):
                src_dir = cfg.config_dir / "src" if (cfg.config_dir / "src").is_dir() else cfg.base_url
                lib_dir = src_dir / "lib" if (src_dir / "lib").is_dir() else src_dir
                hit = probe_ts_candidate((lib_dir / spec[5:]).resolve(), self.repo_root, exts=exts)
                if hit is not None:
                    return hit
            elif not spec.startswith("#"):
                hit = probe_ts_candidate((cfg.base_url / spec).resolve(), self.repo_root, exts=exts)
                if hit is not None:
                    return hit

        # 3. Monorepo workspace packages (`@pkg/name` or `@pkg/name/subpath`)
        for pkg_name, pkg_dir in sorted(self.pkg_roots.items(), key=lambda kv: len(kv[0]), reverse=True):
            if spec == pkg_name:
                if pkg_name in self.pkg_entries:
                    hit = probe_ts_candidate(self.pkg_entries[pkg_name], self.repo_root, exts=exts)
                    if hit is not None:
                        return hit
                for sub_cand in (pkg_dir / "src" / "index", pkg_dir / "index"):
                    hit = probe_ts_candidate(sub_cand, self.repo_root, exts=exts)
                    if hit is not None:
                        return hit
            elif spec.startswith(f"{pkg_name}/"):
                rel_sub = spec[len(pkg_name) + 1 :]
                for base_probe in (pkg_dir / rel_sub, pkg_dir / "src" / rel_sub):
                    hit = probe_ts_candidate(base_probe, self.repo_root, exts=exts)
                    if hit is not None:
                        return hit
        return None


def _parse_clause_names(clause: str) -> tuple[list[str], list[str]]:
    """Return `(imported_names, local_names)`, ignoring `type Foo` specifiers."""
    imp_names: list[str] = []
    loc_names: list[str] = []
    for raw_item in clause.split(","):
        item = raw_item.strip()
        if not item or item.startswith("type "):
            continue
        parts = re.split(r"\s+as\s+", item, maxsplit=1)
        src = parts[0].strip()
        dst = parts[1].strip() if len(parts) == 2 else src
        if re.fullmatch(r"[A-Za-z_$][\w$]*", src) and re.fullmatch(r"[A-Za-z_$][\w$]*", dst):
            imp_names.append(src)
            loc_names.append(dst)
    return imp_names, loc_names


def extract_ts_import_bindings(source: str, *, is_tsx: bool = False) -> list[TsImportBinding]:
    """Extract runtime import specifiers + bound symbols (excluding `import type` and type specifiers)."""
    if has_treesitter():
        parser = _get_parser("tsx" if is_tsx else "ts")
        if parser is not None:
            raw = source.encode("utf-8")
            tree = parser.parse(raw)
            out: list[TsImportBinding] = []
            for ch in tree.root_node.children:
                if ch.type != "import_statement":
                    continue
                stmt = raw[ch.start_byte : ch.end_byte].decode("utf-8", errors="replace").strip()
                if re.match(r"^import\s+type\b", stmt):
                    continue
                src_node = ch.child_by_field_name("source")
                if src_node is None:
                    continue
                spec = raw[src_node.start_byte : src_node.end_byte].decode("utf-8", errors="replace").strip().strip("'\"")
                lineno = ch.start_point[0] + 1
                imp_names: list[str] = []
                loc_names: list[str] = []
                ns_names: list[str] = []
                for sub in ch.children:
                    if sub.type == "import_clause":
                        for clause_ch in sub.children:
                            if clause_ch.type == "identifier":
                                nm = raw[clause_ch.start_byte : clause_ch.end_byte].decode("utf-8", errors="replace")
                                imp_names.append("default")
                                loc_names.append(nm)
                            elif clause_ch.type == "namespace_import":
                                id_n = next((c for c in clause_ch.children if c.type == "identifier"), None)
                                if id_n is not None:
                                    ns_names.append(raw[id_n.start_byte : id_n.end_byte].decode("utf-8", errors="replace"))
                            elif clause_ch.type == "named_imports":
                                inner = raw[clause_ch.start_byte : clause_ch.end_byte].decode("utf-8", errors="replace").strip("{}")
                                inames, lnames = _parse_clause_names(inner)
                                imp_names.extend(inames)
                                loc_names.extend(lnames)
                out.append(
                    TsImportBinding(
                        spec=spec,
                        imported_names=tuple(imp_names),
                        local_names=tuple(loc_names),
                        namespace_names=tuple(ns_names),
                        line=lineno,
                    )
                )
            return out

    # Regex fallback when tree-sitter is disabled
    fallback: list[TsImportBinding] = []
    for m in _NAMED_IMPORT_RE.finditer(source):
        spec = m.group("spec")
        body = m.group("body").strip()
        lineno = source.count("\n", 0, m.start()) + 1
        imp_names_f: list[str] = []
        loc_names_f: list[str] = []
        ns_names_f: list[str] = []
        ns_m = re.search(r"\*\s+as\s+([A-Za-z_$][\w$]*)", body)
        if ns_m:
            ns_names_f.append(ns_m.group(1))
        br_m = re.search(r"\{([^}]*)\}", body)
        if br_m:
            inames, lnames = _parse_clause_names(br_m.group(1))
            imp_names_f.extend(inames)
            loc_names_f.extend(lnames)
        head = re.sub(r"\{[^}]*\}|\*\s+as\s+[A-Za-z_$][\w$]*", "", body).replace(",", "").strip()
        if head and re.fullmatch(r"[A-Za-z_$][\w$]*", head):
            imp_names_f.append("default")
            loc_names_f.append(head)
        fallback.append(
            TsImportBinding(
                spec=spec,
                imported_names=tuple(imp_names_f),
                local_names=tuple(loc_names_f),
                namespace_names=tuple(ns_names_f),
                line=lineno,
            )
        )
    return fallback


def _extract_local_string_defs(text: str, is_tsx: bool = False) -> tuple[dict[str, str], dict[str, dict[str, str]]]:
    consts: dict[str, str] = {}
    enums: dict[str, dict[str, str]] = {}
    if has_treesitter():
        parser = _get_parser("tsx" if is_tsx else "ts")
        if parser is not None:
            raw = text.encode("utf-8")
            tree = parser.parse(raw)
            stack = [tree.root_node]
            while stack:
                node = stack.pop()
                if node.type == "enum_declaration":
                    name_n = node.child_by_field_name("name")
                    body_n = node.child_by_field_name("body")
                    if name_n is not None and body_n is not None:
                        ename = raw[name_n.start_byte : name_n.end_byte].decode("utf-8", errors="replace")
                        members: dict[str, str] = {}
                        for ch in body_n.named_children:
                            if ch.type == "enum_assignment":
                                prop_n = ch.child_by_field_name("name") or (ch.named_children[0] if ch.named_children else None)
                                val_n = ch.child_by_field_name("value") or (ch.named_children[-1] if len(ch.named_children) >= 2 else None)
                                if prop_n is not None and val_n is not None and val_n.type in ("string", "template_string"):
                                    k = raw[prop_n.start_byte : prop_n.end_byte].decode("utf-8", errors="replace").strip("'\"")
                                    v_raw = raw[val_n.start_byte : val_n.end_byte].decode("utf-8", errors="replace")
                                    if "${" not in v_raw and len(v_raw) >= 2:
                                        members[k] = v_raw[1:-1]
                        if members:
                            enums[ename] = members
                    continue
                if node.type == "variable_declarator":
                    nm_n = node.child_by_field_name("name")
                    val_n = node.child_by_field_name("value")
                    if nm_n is not None and val_n is not None:
                        while val_n.type in ("as_expression", "type_assertion", "parenthesized_expression") and val_n.named_children:
                            val_n = val_n.named_children[0]
                        if nm_n.type == "identifier" and val_n.type in ("string", "template_string"):
                            cname = raw[nm_n.start_byte : nm_n.end_byte].decode("utf-8", errors="replace")
                            v_raw = raw[val_n.start_byte : val_n.end_byte].decode("utf-8", errors="replace")
                            if "${" not in v_raw and len(v_raw) >= 2:
                                consts.setdefault(cname, v_raw[1:-1])
                    continue
                stack.extend(node.children)
            return consts, enums

    for em in _ENUM_BLOCK_RE.finditer(text):
        members_fb: dict[str, str] = {}
        for mm in _ENUM_MEMBER_RE.finditer(em.group("body")):
            k = mm.group("qkey") or mm.group("key")
            if k:
                members_fb[k] = mm.group("val")
        if members_fb:
            enums[em.group("ename")] = members_fb
    for cm in _CONST_STR_RE.finditer(text):
        consts.setdefault(cm.group("name"), cm.group("val"))
    return consts, enums


def extract_module_string_bindings(
    path: Path,
    resolver: WorkspaceResolver,
    *,
    _visiting: frozenset[Path] = frozenset(),
) -> tuple[dict[str, str], dict[str, dict[str, str]]]:
    """Collect constant strings and enum maps visible in `path` via local defs, imports, and barrels."""
    rp = path.resolve()
    if rp in resolver._const_cache:
        return resolver._const_cache[rp]
    if rp in _visiting or not rp.is_file():
        return {}, {}
    try:
        text = rp.read_text(encoding="utf-8", errors="replace")
    except (OSError, UnicodeError):
        return {}, {}

    visiting = _visiting | {rp}
    is_tsx = rp.suffix in (".tsx", ".jsx")
    consts, enums = _extract_local_string_defs(text, is_tsx=is_tsx)

    for imp in extract_ts_import_bindings(text, is_tsx=is_tsx):
        target = resolver.resolve_import(imp.spec, rp)
        if target is None or target == rp:
            continue
        t_consts, t_enums = extract_module_string_bindings(target, resolver, _visiting=visiting)
        for src_name, dst_name in zip(imp.imported_names, imp.local_names):
            if src_name in t_consts:
                consts.setdefault(dst_name, t_consts[src_name])
            if src_name in t_enums:
                enums.setdefault(dst_name, t_enums[src_name])
        for ns in imp.namespace_names:
            enums.setdefault(ns, dict(t_consts))

    for sm in _REEXPORT_STAR_RE.finditer(text):
        target = resolver.resolve_import(sm.group("spec"), rp)
        if target is not None and target != rp:
            t_consts, t_enums = extract_module_string_bindings(target, resolver, _visiting=visiting)
            for k, v in t_consts.items():
                consts.setdefault(k, v)
            for k, v in t_enums.items():
                enums.setdefault(k, v)

    for nm in _REEXPORT_NAMED_RE.finditer(text):
        target = resolver.resolve_import(nm.group("spec"), rp)
        if target is None or target == rp:
            continue
        t_consts, t_enums = extract_module_string_bindings(target, resolver, _visiting=visiting)
        inames, lnames = _parse_clause_names(nm.group("clause"))
        for src_name, dst_name in zip(inames, lnames):
            if src_name in t_consts:
                consts.setdefault(dst_name, t_consts[src_name])
            if src_name in t_enums:
                enums.setdefault(dst_name, t_enums[src_name])

    resolver._const_cache[rp] = (consts, enums)
    return consts, enums


def resolve_string_expr(expr_text: str, file_path: Path, resolver: WorkspaceResolver) -> str | None:
    """Resolve a static string literal, constant identifier, or `Enum.MEMBER` expression."""
    raw = expr_text.strip()
    if not raw:
        return None
    if len(raw) >= 2 and raw[0] in ("'", '"') and raw[-1] == raw[0] and "\\" not in raw:
        return raw[1:-1]
    if len(raw) >= 2 and raw[0] == "`" and raw[-1] == "`" and "${" not in raw:
        return raw[1:-1]
    if re.fullmatch(r"[A-Za-z_$][\w$]*", raw):
        consts, _enums = extract_module_string_bindings(file_path, resolver)
        return consts.get(raw)
    if re.fullmatch(r"[A-Za-z_$][\w$]*\.[A-Za-z_$][\w$]*", raw):
        owner, member = raw.split(".", 1)
        _consts, enums = extract_module_string_bindings(file_path, resolver)
        return enums.get(owner, {}).get(member)
    return None


def resolve_reexport_targets(
    barrel_path: Path,
    symbol: str | None,
    resolver: WorkspaceResolver,
    *,
    _visiting: frozenset[Path] = frozenset(),
) -> list[Path]:
    """Resolve `export { ... } from '...'` and `export * from '...'` targets inside a barrel file."""
    rp = barrel_path.resolve()
    if rp in _visiting or not rp.is_file():
        return []
    try:
        text = rp.read_text(encoding="utf-8", errors="replace")
    except (OSError, UnicodeError):
        return []

    visiting = _visiting | {rp}
    targets: list[Path] = []
    seen: set[Path] = set()

    def add_target(tgt: Path) -> None:
        if tgt not in seen:
            seen.add(tgt)
            targets.append(tgt)

    for nm in _REEXPORT_NAMED_RE.finditer(text):
        inames, lnames = _parse_clause_names(nm.group("clause"))
        if symbol is not None and symbol not in lnames and symbol not in inames:
            continue
        direct = resolver.resolve_import(nm.group("spec"), rp)
        if direct is not None and direct != rp:
            add_target(direct)
            mapped_sym = None
            if symbol is not None and symbol in lnames:
                mapped_sym = inames[lnames.index(symbol)]
            elif symbol is not None:
                mapped_sym = symbol
            if direct.name.startswith("index."):
                for nested in resolve_reexport_targets(direct, mapped_sym, resolver, _visiting=visiting):
                    add_target(nested)

    for sm in _REEXPORT_STAR_RE.finditer(text):
        direct = resolver.resolve_import(sm.group("spec"), rp)
        if direct is not None and direct != rp:
            add_target(direct)
            if direct.name.startswith("index.") or symbol is not None:
                for nested in resolve_reexport_targets(direct, symbol, resolver, _visiting=visiting):
                    add_target(nested)

    return targets


_DI_CTOR_BLOCK_RE = re.compile(r"\bconstructor\s*\((?P<params>[\s\S]*?)\)\s*\{")
_DI_PARAM_RE = re.compile(
    r"(?:private|protected|public|readonly)\s+(?:readonly\s+)?(?P<prop>[A-Za-z_$][\w$]*)\s*:\s*(?P<type>[A-Za-z_$][\w$]*)"
)
_FIELD_DI_RE = re.compile(
    r"@Inject\([^)]*\)\s*(?:private|protected|public|readonly|\s)*(?P<prop>[A-Za-z_$][\w$]*)\s*:\s*(?P<type>[A-Za-z_$][\w$]*)"
)


def _blank_span(buf: bytearray, start: int, end: int) -> None:
    for i in range(start, end):
        if buf[i] != 10:
            buf[i] = 32


def executable_ts_text(source: str, *, is_tsx: bool = False) -> tuple[str, dict[str, set[str]]]:
    """Return `(executable_code_without_imports_or_type_positions, {ClassName: {di_prop_names}})`."""
    di_map: dict[str, set[str]] = {}
    for cm in _DI_CTOR_BLOCK_RE.finditer(source):
        for pm in _DI_PARAM_RE.finditer(cm.group("params")):
            di_map.setdefault(pm.group("type"), set()).add(pm.group("prop"))
    for fm in _FIELD_DI_RE.finditer(source):
        di_map.setdefault(fm.group("type"), set()).add(fm.group("prop"))

    if has_treesitter():
        parser = _get_parser("tsx" if is_tsx else "ts")
        if parser is not None:
            raw = source.encode("utf-8")
            tree = parser.parse(raw)
            buf = bytearray(raw)
            skip_types = frozenset({
                "import_statement",
                "type_annotation",
                "type_arguments",
                "type_parameters",
                "type_alias_declaration",
                "interface_declaration",
                "implements_clause",
            })

            def mask(node: Any) -> None:
                if node.type in skip_types:
                    _blank_span(buf, node.start_byte, node.end_byte)
                    return
                if node.type == "export_statement" and node.child_by_field_name("source") is not None:
                    _blank_span(buf, node.start_byte, node.end_byte)
                    return
                if node.type in ("as_expression", "satisfies_expression") and len(node.named_children) >= 2:
                    t_node = node.child_by_field_name("type") or node.named_children[-1]
                    _blank_span(buf, node.named_children[0].end_byte, t_node.end_byte)
                for ch in node.children:
                    mask(ch)

            mask(tree.root_node)
            return buf.decode("utf-8", errors="replace"), di_map

    # Regex fallback: strip import/re-export lines, type/interface decls, `typeof import(...)`, and `: Type` annotations.
    cleaned = re.sub(
        r"""(?:^|[;\r\n])[ \t]*(?:import\b[\s\S]*?from\s+['"][^'"]+['"]|import\s+['"][^'"]+['"]|export\s+(?:type\s+)?(?:\*|\{[^}]*\})\s+from\s+['"][^'"]+['"]);?""",
        lambda m: "\n" * m.group(0).count("\n"),
        source,
    )
    cleaned = re.sub(
        r"""(?:^|\n)[ \t]*(?:export\s+)?(?:interface|type)\s+[A-Za-z_$][\w$]*[\s\S]*?(?:\n\};?|\n\}|;)""",
        lambda m: "\n" * m.group(0).count("\n"),
        cleaned,
    )
    cleaned = re.sub(r"\btypeof\s+import\([^)]*\)", " ", cleaned)
    cleaned = re.sub(r":\s*[A-Za-z_$][\w$<>.,\[\]| &]*(?=[,)\n;{=])", "", cleaned)
    cleaned = re.sub(r"\b(?:as|implements)\s+[A-Za-z_$][\w$<>.,\[\] ]*", "", cleaned)
    return cleaned, di_map


def verified_import_bindings(
    exec_text: str,
    di_map: dict[str, set[str]],
    imp: TsImportBinding,
) -> tuple[bool, set[str]]:
    """Return `(is_binding_verified, verified_imported_symbol_names)` for a runtime `TsImportBinding`."""
    if not imp.local_names and not imp.namespace_names:
        return True, set()
    used_imported: set[str] = set()
    for src_name, loc_name in zip(imp.imported_names, imp.local_names):
        if re.search(rf"(?<![.\w$]){re.escape(loc_name)}\b", exec_text):
            used_imported.add(src_name)
            continue
        for prop in di_map.get(loc_name, ()):
            if re.search(rf"\bthis\.{re.escape(prop)}\b", exec_text):
                used_imported.add(src_name)
                break
    for ns in imp.namespace_names:
        if re.search(rf"(?<![.\w$]){re.escape(ns)}\b", exec_text):
            return True, used_imported
    return bool(used_imported), used_imported


_DYN_IMPORT_ASSIGN_RE = re.compile(
    r"""\b(?:const|let|var)\s+(?P<lhs>\{[^}]+\}|[A-Za-z_$][\w$]*)\s*=\s*(?:\(\s*)?(?:await\s+)?import\s*\(\s*(?P<arg>[^)\n]+)\s*\)"""
)
_DYN_IMPORT_ANY_RE = re.compile(
    r"""(?<![.\w$])import\s*\(\s*(?P<arg>[^)\n]+)\s*\)(?:\s*\)?\s*\.\s*(?P<prop>[A-Za-z_$][\w$]*)\s*\()?"""
)
_STATIC_STR_ARG_RE = re.compile(r"""^(?P<q>['"`])(?P<val>[^'"`\\]+)(?P=q)$""")


def _parse_destructure_names(lhs: str) -> tuple[tuple[str, ...], tuple[str, ...]]:
    s = lhs.strip()
    if s.startswith("{") and s.endswith("}"):
        imp_names: list[str] = []
        loc_names: list[str] = []
        for raw_item in s[1:-1].split(","):
            item = raw_item.strip()
            if not item:
                continue
            item = item.split("=", 1)[0].strip()
            if ":" in item:
                src, dst = item.split(":", 1)
                src_s, dst_s = src.strip(), dst.strip()
            else:
                src_s = dst_s = item
            if re.fullmatch(r"[A-Za-z_$][\w$]*", src_s) and re.fullmatch(r"[A-Za-z_$][\w$]*", dst_s):
                imp_names.append(src_s)
                loc_names.append(dst_s)
        return tuple(imp_names), tuple(loc_names)
    if re.fullmatch(r"[A-Za-z_$][\w$]*", s):
        return ("*",), (s,)
    return (), ()


def _static_import_arg(raw_arg: str) -> str | None:
    stripped = raw_arg.strip().split(",", 1)[0].strip()
    m = _STATIC_STR_ARG_RE.match(stripped)
    if not m:
        return None
    val = m.group("val")
    if "${" in val:
        return None
    return val


def extract_ts_dynamic_imports(exec_text: str, *, is_tsx: bool = False) -> list[TsDynamicImportSite]:
    """Extract runtime dynamic `import(...)` call sites from type-masked `exec_text`."""
    if has_treesitter():
        parser = _get_parser("tsx" if is_tsx else "ts")
        if parser is not None:
            raw = exec_text.encode("utf-8")
            tree = parser.parse(raw)
            sites: list[TsDynamicImportSite] = []

            def _char_idx(byte_pos: int) -> int:
                return len(raw[:byte_pos].decode("utf-8", errors="replace"))

            def walk(node: Any) -> None:
                if node.type == "call_expression":
                    fn = node.child_by_field_name("function")
                    if fn is not None and fn.type == "import":
                        args = node.child_by_field_name("arguments")
                        arg_nodes = [n for n in args.named_children if n.type != "comment"] if args else []
                        raw_arg = (
                            raw[arg_nodes[0].start_byte : arg_nodes[0].end_byte].decode("utf-8", errors="replace")
                            if arg_nodes
                            else ""
                        )
                        spec = _static_import_arg(raw_arg)
                        lineno = node.start_point[0] + 1
                        imp_names: tuple[str, ...] = ()
                        loc_names: tuple[str, ...] = ()
                        d_start, d_end = -1, -1
                        direct = False
                        cur = node.parent
                        while cur is not None and cur.type in (
                            "await_expression",
                            "parenthesized_expression",
                            "as_expression",
                            "satisfies_expression",
                            "non_null_expression",
                        ):
                            cur = cur.parent
                        if cur is not None and cur.type == "member_expression":
                            prop_n = cur.child_by_field_name("property")
                            prop = (
                                raw[prop_n.start_byte : prop_n.end_byte].decode("utf-8", errors="replace")
                                if prop_n is not None
                                else ""
                            )
                            p2 = cur.parent
                            if p2 is not None and p2.type == "call_expression":
                                direct = True
                                if prop and prop != "then":
                                    imp_names = (prop,)
                        elif cur is not None and cur.type == "variable_declarator":
                            name_n = cur.child_by_field_name("name")
                            if name_n is not None:
                                d_start = _char_idx(name_n.start_byte)
                                d_end = _char_idx(name_n.end_byte)
                                lhs_txt = raw[name_n.start_byte : name_n.end_byte].decode("utf-8", errors="replace")
                                imp_names, loc_names = _parse_destructure_names(lhs_txt)
                        sites.append(
                            TsDynamicImportSite(
                                spec=spec,
                                imported_names=imp_names,
                                local_names=loc_names,
                                line=lineno,
                                raw_expr=raw_arg.strip() or "<dynamic>",
                                decl_start=d_start,
                                decl_end=d_end,
                                is_direct_invoked=direct,
                            )
                        )
                for ch in node.children:
                    walk(ch)

            walk(tree.root_node)
            return sites

    sites_fb: list[TsDynamicImportSite] = []
    covered_arg_spans: list[tuple[int, int]] = []
    for m in _DYN_IMPORT_ASSIGN_RE.finditer(exec_text):
        covered_arg_spans.append(m.span("arg"))
        imp_names, loc_names = _parse_destructure_names(m.group("lhs"))
        raw_arg = m.group("arg").strip()
        sites_fb.append(
            TsDynamicImportSite(
                spec=_static_import_arg(raw_arg),
                imported_names=imp_names,
                local_names=loc_names,
                line=exec_text.count("\n", 0, m.start()) + 1,
                raw_expr=raw_arg or "<dynamic>",
                decl_start=m.start("lhs"),
                decl_end=m.end("lhs"),
                is_direct_invoked=False,
            )
        )
    for m in _DYN_IMPORT_ANY_RE.finditer(exec_text):
        aspan = m.span("arg")
        if any(cs <= aspan[0] and aspan[1] <= ce for cs, ce in covered_arg_spans):
            continue
        raw_arg = m.group("arg").strip()
        prop = m.group("prop")
        sites_fb.append(
            TsDynamicImportSite(
                spec=_static_import_arg(raw_arg),
                imported_names=(prop,) if prop and prop != "then" else (),
                local_names=(),
                line=exec_text.count("\n", 0, m.start()) + 1,
                raw_expr=raw_arg or "<dynamic>",
                decl_start=-1,
                decl_end=-1,
                is_direct_invoked=bool(prop),
            )
        )
    return sites_fb


def verified_dynamic_import(exec_text: str, site: TsDynamicImportSite) -> tuple[bool, set[str]]:
    """Return `(is_invoked, used_imported_symbols)` for a dynamic `import(...)` site."""
    if site.is_direct_invoked:
        used = {s for s in site.imported_names if s and s != "*"}
        return True, used
    if not site.local_names:
        return True, set()
    if site.decl_start >= 0 and site.decl_end > site.decl_start:
        masked = f"{exec_text[:site.decl_start]}{' ' * (site.decl_end - site.decl_start)}{exec_text[site.decl_end:]}"
    else:
        masked = exec_text
    matched = False
    used_syms: set[str] = set()
    pairs = (
        zip(site.imported_names, site.local_names)
        if len(site.imported_names) == len(site.local_names)
        else [("*", ln) for ln in site.local_names]
    )
    for imp_s, loc_s in pairs:
        if re.search(rf"(?<![.\w$]){re.escape(loc_s)}\b", masked):
            matched = True
            if imp_s and imp_s != "*":
                used_syms.add(imp_s)
    return matched, used_syms
