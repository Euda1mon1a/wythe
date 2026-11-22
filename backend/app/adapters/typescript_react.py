"""Tier 3 Adapter: React SPA / Vite / React Router / TanStack Router / Remix (`typescript-react`)."""

from __future__ import annotations

import json
import os
import re
import stat
from dataclasses import replace
from pathlib import Path

from app.adapters.base import (
    DisplayExtractionResult,
    FrontendHttpCall,
    RawCandidateFinding,
)
from app.adapters.frontend_common import (
    build_a11y_component_resolver,
    build_frontend_url_const_resolver,
    collect_safe_graph_files,
    extract_html_mount_info,
    extract_html_script_specs,
    extract_script_preserving_lines,
    format_unobserved_a11y_note,
    make_safe_graph_resolver,
    resolve_frontend_import,
    scan_display_module_semantics,
)
from app.adapters.ts_reachability import (
    _SKIP_DIRS as _REACH_SKIP_DIRS,
)
from app.adapters.ts_reachability import (
    MODULE_SYMBOL,
    ReachabilityIndex,
    _ModuleInfo,
    is_react_spa_entry,
    parse_module,
)
from app.adapters.ts_sdk import WorkspaceSdkIndex
from app.adapters.ts_workspace import (
    WorkspaceResolver,
    safe_read_repo_text,
    safe_resolve_contained_path,
)
from app.adapters.typescript_nextjs import (
    _REEXPORT_NAMED_RE,
    _REEXPORT_STAR_RE,
    _check_ts_syntax_complete,
    _is_pure_barrel_ts,
    has_frontend_generator_config,
)
from app.schemas.atlas import AtlasEdge, AtlasNode

_EXTS = (".ts", ".tsx", ".js", ".jsx", ".mjs", ".html", ".htm")
_API_CLIENT_SUFFIXES = (
    "-client",
    "_client",
    "-api",
    "_api",
    "-service",
    "_service",
    "-transport",
    "_transport",
    "-stream",
    "_stream",
)
_API_CLIENT_PASCAL_SUFFIXES = ("Client", "Api", "Service", "Transport", "Stream")
_API_CLIENT_STEMS = frozenset(
    {"api", "client", "http", "queries", "request", "fetcher", "transport", "sse", "stream"}
)
_VANILLA_ENTRY_STEMS = frozenset({"app", "main", "router", "index"})
_HOOK_STEM_RE = re.compile(r"^use(?:[A-Z0-9]|[-_])")
_SKIP_DIR_PARTS = frozenset(
    {
        "node_modules",
        ".git",
        ".venv",
        "venv",
        "dist",
        "build",
        "out",
        "ui_dist",
        "__tests__",
        "__mocks__",
        "mocks",
        "__fixtures__",
        "fixtures",
        "test-utils",
        "src-tauri",
        "coverage",
        ".next",
    }
)
_HTTP_OR_A11Y_HINT_RE = re.compile(
    r"(?:\bfetch\s*\(|\bEventSource\s*\(|\baxios\b|\.(?:get|post|put|patch|delete|del)\s*(?:<[^>]*>)?\s*\(|<(?:img|button|input|select|textarea)\b|\bonclick\s*=)",
    re.IGNORECASE,
)


def _safe_is_file(path: Path | None) -> bool:
    if path is None:
        return False
    try:
        st = path.lstat()
        return not stat.S_ISLNK(st.st_mode) and stat.S_ISREG(st.st_mode)
    except OSError:
        return False


def _rel_parts_within_repo(path: Path, fe_dir: Path, repo_res: Path) -> tuple[str, ...]:
    if path.is_relative_to(fe_dir):
        return path.relative_to(fe_dir).parts
    if path.is_relative_to(repo_res):
        return path.relative_to(repo_res).parts
    return path.parts


def _dir_has_frontend_sources(root: Path) -> bool:
    try:
        st = root.lstat()
        if stat.S_ISLNK(st.st_mode) or not stat.S_ISDIR(st.st_mode) or not os.access(root, os.R_OK | os.X_OK):
            return False
    except OSError:
        return False
    for parent, dirs, files in os.walk(root, followlinks=False, onerror=lambda _exc: None):
        parent_p = Path(parent)
        kept_dirs: list[str] = []
        for d in dirs:
            if d in _SKIP_DIR_PARTS:
                continue
            dp = parent_p / d
            try:
                dst = dp.lstat()
            except OSError:
                continue
            if stat.S_ISLNK(dst.st_mode) or not stat.S_ISDIR(dst.st_mode):
                continue
            if os.access(dp, os.R_OK | os.X_OK):
                kept_dirs.append(d)
        dirs[:] = kept_dirs
        for fname in files:
            p = parent_p / fname
            if p.suffix.lower() not in _EXTS:
                continue
            try:
                fst = p.lstat()
            except OSError:
                continue
            if not stat.S_ISLNK(fst.st_mode) and stat.S_ISREG(fst.st_mode):
                return True
    return False


def _resolve_spa_script_path(
    spec: str,
    current_file: Path,
    fe_dir: Path,
    src_root: Path,
    mount_prefixes: tuple[str, ...] = (),
    *,
    repo_root: Path | None = None,
) -> Path | None:
    clean_spec = spec.split("?", 1)[0].split("#", 1)[0].strip()
    if not clean_spec or "\x00" in clean_spec:
        return None
    bound_root = repo_root if repo_root is not None else fe_dir
    hit = resolve_frontend_import(clean_spec, current_file, src_root, _EXTS, repo_root=bound_root)
    if hit is not None:
        return hit
    if clean_spec.startswith("/") and not clean_spec.startswith("//"):
        rel = clean_spec.lstrip("/")
        for base_dir in (fe_dir, src_root):
            cand = safe_resolve_contained_path(base_dir / rel, bound_root)
            if _safe_is_file(cand) and cand is not None and cand.is_relative_to(bound_root):
                return cand
        if rel.startswith(f"{fe_dir.name}/"):
            cand = safe_resolve_contained_path(fe_dir / rel[len(fe_dir.name) + 1 :], bound_root)
            if _safe_is_file(cand) and cand is not None and cand.is_relative_to(bound_root):
                return cand
        for pref in mount_prefixes:
            if pref and clean_spec.startswith(f"{pref}/"):
                sub = clean_spec[len(pref) :].lstrip("/")
                cand = safe_resolve_contained_path(fe_dir / sub, bound_root)
                if _safe_is_file(cand) and cand is not None and cand.is_relative_to(bound_root):
                    return cand
    return None


class TypeScriptReactSpaAdapter:
    """Extracts React SPA routes/pages, hooks, API clients, components, and DISP rules."""

    name = "typescript-react"

    def extract(self, repo_root: Path, frontend_subdir: str) -> DisplayExtractionResult:
        try:
            if repo_root.is_symlink():
                return DisplayExtractionResult(
                    nodes=[],
                    edges=[],
                    http_calls=[],
                    findings=[],
                    coverage_complete=False,
                    notes=[f"Repository root `{repo_root}` is a symlink; display coverage is incomplete."],
                )
            repo_res = repo_root.resolve(strict=True)
            if not repo_res.is_dir():
                return DisplayExtractionResult(
                    nodes=[],
                    edges=[],
                    http_calls=[],
                    findings=[],
                    coverage_complete=False,
                    notes=[f"Repository root `{repo_root}` is not a directory; display coverage is incomplete."],
                )
            if not os.access(repo_res, os.R_OK | os.X_OK):
                raise PermissionError(f"Repository root is not readable/traversable: {repo_res}")
            with os.scandir(repo_res):
                pass
        except OSError as exc:
            return DisplayExtractionResult(
                nodes=[],
                edges=[],
                http_calls=[],
                findings=[],
                coverage_complete=False,
                notes=[f"Repository root `{repo_root}` is unreadable ({exc}); display coverage is incomplete."],
            )
        fe_dir = (
            repo_res
            if frontend_subdir in ("", ".")
            else safe_resolve_contained_path(Path(frontend_subdir), repo_root)
        )
        try:
            fe_ok = (
                fe_dir is not None
                and fe_dir.is_dir()
                and fe_dir.is_relative_to(repo_res)
                and os.access(fe_dir, os.R_OK | os.X_OK)
            )
            if fe_ok and fe_dir is not None:
                with os.scandir(fe_dir):
                    pass
        except OSError:
            fe_ok = False
        if not fe_ok or fe_dir is None:
            return DisplayExtractionResult(
                nodes=[],
                edges=[],
                http_calls=[],
                findings=[],
                coverage_complete=False,
                notes=[
                    f"Frontend directory `{frontend_subdir}` is missing, unreadable, or outside repository root; display coverage is incomplete."
                ],
            )
        coverage_complete = True
        extra_notes: list[str] = []
        raw_src = fe_dir / "src"
        src_root = fe_dir
        try:
            src_st = raw_src.lstat()
        except FileNotFoundError:
            src_st = None
        except OSError as exc:
            src_st = None
            coverage_complete = False
            extra_notes.append(f"Unreadable source root `{raw_src}` ({exc}); display coverage is incomplete.")
        if src_st is not None:
            if stat.S_ISLNK(src_st.st_mode):
                coverage_complete = False
                extra_notes.append(f"Skipped symlink source root `{raw_src}`; display coverage is incomplete.")
            elif stat.S_ISDIR(src_st.st_mode):
                if not os.access(raw_src, os.R_OK | os.X_OK):
                    coverage_complete = False
                    extra_notes.append(f"Unreadable source root `{raw_src}`; display coverage is incomplete.")
                else:
                    safe_src = safe_resolve_contained_path(raw_src, repo_res)
                    if safe_src is not None and _dir_has_frontend_sources(safe_src):
                        src_root = safe_src
        try:
            src_ok = src_root.is_dir() and os.access(src_root, os.R_OK | os.X_OK)
        except OSError:
            src_ok = False
        if not src_ok:
            return DisplayExtractionResult(
                nodes=[],
                edges=[],
                http_calls=[],
                findings=[],
                coverage_complete=False,
                notes=[f"Frontend source root `{src_root}` is missing or unreadable; display coverage is incomplete."],
            )

        cleaned: dict[Path, str] = {}
        raw_sources: dict[Path, str] = {}
        barrel_targets: dict[Path, list[Path]] = {}
        nodes_by_path: dict[Path, AtlasNode] = {}
        used_node_ids: set[str] = set()
        mount_errors: list[str] = []
        html_mount_prefixes, html_api_base = extract_html_mount_info(
            fe_dir, src_root, repo_root=repo_res, errors_out=mount_errors
        )
        if mount_errors:
            coverage_complete = False
            extra_notes.extend(mount_errors)

        def _on_react_walk_err(exc: OSError) -> None:
            nonlocal coverage_complete
            coverage_complete = False
            extra_notes.append(
                f"Unreadable frontend directory `{exc.filename or fe_dir}` ({exc}); display coverage is incomplete."
            )

        def _walk_react_tree(walk_root: Path) -> list[Path]:
            nonlocal coverage_complete
            collected: list[Path] = []
            for parent, dirs, files in os.walk(walk_root, followlinks=False, onerror=_on_react_walk_err):
                parent_p = Path(parent)
                kept_dirs: list[str] = []
                for d in sorted(dirs):
                    dp = parent_p / d
                    rel_d_parts = _rel_parts_within_repo(dp, fe_dir, repo_res)
                    if any(part in _SKIP_DIR_PARTS for part in rel_d_parts):
                        continue
                    try:
                        dst = dp.lstat()
                    except OSError as exc:
                        coverage_complete = False
                        extra_notes.append(
                            f"Unreadable frontend directory `{dp}` ({exc}); display coverage is incomplete."
                        )
                        continue
                    if stat.S_ISLNK(dst.st_mode):
                        coverage_complete = False
                        extra_notes.append(
                            f"Skipped symlink frontend path `{dp}`; display coverage is incomplete."
                        )
                        continue
                    if stat.S_ISDIR(dst.st_mode):
                        if not os.access(dp, os.R_OK | os.X_OK):
                            coverage_complete = False
                            extra_notes.append(
                                f"Unreadable frontend directory `{dp}`; display coverage is incomplete."
                            )
                            continue
                        kept_dirs.append(d)
                dirs[:] = kept_dirs
                for fname in sorted(files):
                    collected.append(parent_p / fname)
            return sorted(collected)

        candidate_files: list[Path] = []
        seen_cands: set[Path] = set()
        for p in _walk_react_tree(src_root):
            rel_parts = _rel_parts_within_repo(p, fe_dir, repo_res)
            if any(part in _SKIP_DIR_PARTS for part in rel_parts[:-1]):
                continue
            try:
                st = p.lstat()
            except OSError as exc:
                if p.suffix.lower() in _EXTS:
                    coverage_complete = False
                    extra_notes.append(
                        f"Unreadable frontend path `{p}` ({exc}); display coverage is incomplete."
                    )
                continue
            if stat.S_ISLNK(st.st_mode):
                if p.suffix.lower() in _EXTS or not p.suffix:
                    coverage_complete = False
                    extra_notes.append(f"Skipped symlink frontend path `{p}`; display coverage is incomplete.")
                continue
            if stat.S_ISDIR(st.st_mode):
                continue
            if not stat.S_ISREG(st.st_mode):
                if p.suffix.lower() in _EXTS:
                    coverage_complete = False
                    extra_notes.append(
                        f"Skipped non-regular frontend path `{p}`; display coverage is incomplete."
                    )
                continue
            safe_p = safe_resolve_contained_path(p, repo_res)
            if safe_p is None:
                coverage_complete = False
                extra_notes.append(f"Rejected out-of-repo frontend path `{p}`; display coverage is incomplete.")
                continue
            if safe_p not in seen_cands:
                seen_cands.add(safe_p)
                candidate_files.append(safe_p)

        if src_root != fe_dir:
            try:
                top_entries = sorted(fe_dir.iterdir())
            except OSError as exc:
                top_entries = []
                coverage_complete = False
                extra_notes.append(
                    f"Unreadable frontend directory `{fe_dir}` ({exc}); display coverage is incomplete."
                )
            for top_f in top_entries:
                try:
                    st = top_f.lstat()
                except OSError as exc:
                    if top_f.suffix.lower() in (".html", ".htm", ".mjs"):
                        coverage_complete = False
                        extra_notes.append(
                            f"Unreadable frontend file `{top_f}` ({exc}); display coverage is incomplete."
                        )
                    continue
                if stat.S_ISLNK(st.st_mode):
                    if top_f.suffix.lower() in (".html", ".htm", ".mjs"):
                        coverage_complete = False
                        extra_notes.append(f"Skipped symlink frontend file `{top_f}`; display coverage is incomplete.")
                    continue
                if stat.S_ISDIR(st.st_mode):
                    continue
                if not stat.S_ISREG(st.st_mode):
                    if top_f.suffix.lower() in (".html", ".htm", ".mjs"):
                        coverage_complete = False
                        extra_notes.append(
                            f"Skipped non-regular frontend path `{top_f}`; display coverage is incomplete."
                        )
                    continue
                if top_f.suffix.lower() in (".html", ".htm", ".mjs"):
                    rp = safe_resolve_contained_path(top_f, repo_res)
                    if rp is not None and rp not in seen_cands:
                        seen_cands.add(rp)
                        candidate_files.append(rp)

        html_module_targets: dict[Path, list[Path]] = {}
        html_module_entries: set[Path] = set()
        has_html_module_tag = False
        for hf in list(candidate_files):
            if not _safe_is_file(hf) or hf.suffix.lower() not in (".html", ".htm"):
                continue
            rel_fe_parts = _rel_parts_within_repo(hf, fe_dir, repo_res)
            if any(p in _SKIP_DIR_PARTS for p in rel_fe_parts[:-1]):
                continue
            try:
                h_raw = safe_read_repo_text(hf, repo_res, encoding="utf-8")
            except (OSError, UnicodeError) as exc:
                coverage_complete = False
                extra_notes.append(f"Unreadable HTML file `{hf}` ({exc}); display coverage is incomplete.")
                continue
            if re.search(r"<script\b[^>]*\btype\s*=\s*['\"]module['\"]", h_raw, re.IGNORECASE):
                has_html_module_tag = True
            h_res = hf
            targets_for_html: list[Path] = []
            for spec in extract_html_script_specs(h_raw, base_prefixes=html_mount_prefixes):
                tgt = _resolve_spa_script_path(
                    spec, h_res, fe_dir, src_root, html_mount_prefixes, repo_root=repo_res
                )
                if tgt is not None:
                    tgt_parts = _rel_parts_within_repo(tgt, fe_dir, repo_res)
                    if not any(p in _SKIP_DIR_PARTS for p in tgt_parts[:-1]):
                        targets_for_html.append(tgt)
                        html_module_entries.add(tgt)
                        if tgt not in seen_cands:
                            seen_cands.add(tgt)
                            candidate_files.append(tgt)
            if targets_for_html:
                html_module_targets[h_res] = targets_for_html

        if src_root != fe_dir and html_module_entries:
            for vanilla_dir_name in ("views", "core", "utils", "shared"):
                raw_vdir = fe_dir / vanilla_dir_name
                try:
                    vst_dir = raw_vdir.lstat()
                except FileNotFoundError:
                    continue
                except OSError as exc:
                    coverage_complete = False
                    extra_notes.append(f"Unreadable directory `{raw_vdir}` ({exc}); display coverage is incomplete.")
                    continue
                if stat.S_ISLNK(vst_dir.st_mode):
                    coverage_complete = False
                    extra_notes.append(f"Skipped symlink directory `{raw_vdir}`; display coverage is incomplete.")
                    continue
                if not stat.S_ISDIR(vst_dir.st_mode):
                    continue
                if not os.access(raw_vdir, os.R_OK | os.X_OK):
                    coverage_complete = False
                    extra_notes.append(f"Unreadable directory `{raw_vdir}`; display coverage is incomplete.")
                    continue
                vdir = safe_resolve_contained_path(raw_vdir, repo_res)
                if vdir is not None:
                    for vf in _walk_react_tree(vdir):
                        try:
                            vst = vf.lstat()
                        except OSError as exc:
                            if vf.suffix.lower() in _EXTS:
                                coverage_complete = False
                                extra_notes.append(
                                    f"Unreadable frontend path `{vf}` ({exc}); display coverage is incomplete."
                                )
                            continue
                        if stat.S_ISLNK(vst.st_mode):
                            if vf.suffix.lower() in _EXTS or not vf.suffix:
                                coverage_complete = False
                                extra_notes.append(f"Skipped symlink frontend file `{vf}`; display coverage is incomplete.")
                            continue
                        if stat.S_ISDIR(vst.st_mode):
                            continue
                        if not stat.S_ISREG(vst.st_mode):
                            if vf.suffix.lower() in _EXTS:
                                coverage_complete = False
                                extra_notes.append(
                                    f"Skipped non-regular frontend path `{vf}`; display coverage is incomplete."
                                )
                            continue
                        if vf.suffix.lower() in _EXTS:
                            safe_vf = safe_resolve_contained_path(vf, repo_res)
                            if safe_vf is not None and safe_vf not in seen_cands:
                                seen_cands.add(safe_vf)
                                candidate_files.append(safe_vf)

        has_src_tsx_pages = any(
            _safe_is_file(f)
            and f.is_relative_to(src_root)
            and f.suffix in (".tsx", ".jsx")
            and (f.stem == "App" or any(p in f.relative_to(src_root).parts[:2] for p in ("pages", "routes", "views")))
            for f in candidate_files
        )
        has_vanilla_dirs = False
        for root in dict.fromkeys((src_root, fe_dir)):
            for d in ("views", "core", "utils", "shared"):
                cand_vd = root / d
                try:
                    vd_st = cand_vd.lstat()
                    if stat.S_ISLNK(vd_st.st_mode) or not stat.S_ISDIR(vd_st.st_mode):
                        continue
                    if not os.access(cand_vd, os.R_OK | os.X_OK):
                        coverage_complete = False
                        extra_notes.append(f"Unreadable frontend directory `{cand_vd}`; display coverage is incomplete.")
                        continue
                except FileNotFoundError:
                    continue
                except OSError as exc:
                    coverage_complete = False
                    extra_notes.append(f"Unreadable frontend directory `{cand_vd}` ({exc}); display coverage is incomplete.")
                    continue
                if any(_safe_is_file(p) and p.suffix.lower() in (".js", ".mjs") for p in _walk_react_tree(cand_vd)):
                    has_vanilla_dirs = True
                    break
            if has_vanilla_dirs:
                break
        is_vanilla_ui = (
            bool(html_module_entries)
            or has_html_module_tag
            or (not has_src_tsx_pages and has_vanilla_dirs)
        )

        for fpath in candidate_files:
            if not _safe_is_file(fpath) or fpath.suffix.lower() not in _EXTS:
                continue
            resolved = safe_resolve_contained_path(fpath, repo_res)
            if resolved is None:
                coverage_complete = False
                extra_notes.append(f"Rejected out-of-repo frontend path `{fpath}`; display coverage is incomplete.")
                continue
            fe_parts = _rel_parts_within_repo(resolved, fe_dir, repo_res)
            if any(p in _SKIP_DIR_PARTS for p in fe_parts[:-1]):
                continue
            is_in_src = resolved.is_relative_to(src_root)
            if is_in_src:
                rel_src = resolved.relative_to(src_root).as_posix()
            elif resolved.is_relative_to(fe_dir):
                rel_src = resolved.relative_to(fe_dir).as_posix()
            else:
                rel_src = resolved.relative_to(repo_res).as_posix()
            if (
                fpath.name.endswith(
                    (
                        ".d.ts",
                        ".test.ts",
                        ".test.tsx",
                        ".test.js",
                        ".test.jsx",
                        ".test.mjs",
                        ".spec.ts",
                        ".spec.tsx",
                        ".spec.js",
                        ".spec.jsx",
                        ".spec.mjs",
                        ".config.ts",
                        ".config.js",
                        ".config.mjs",
                        ".config.cjs",
                    )
                )
                or rel_src.endswith("api-generated.ts")
                or fpath.name == "types.gen.ts"
                or ("/core/" in f"/{rel_src}" and fpath.name.endswith(".gen.ts"))
                or rel_src.startswith("client/client/")
                or rel_src == "vite-env.d.ts"
            ):
                continue
            try:
                raw = safe_read_repo_text(resolved, repo_res, encoding="utf-8")
            except (OSError, UnicodeError) as exc:
                coverage_complete = False
                extra_notes.append(f"Unreadable frontend file `{rel_src}` ({exc}); display coverage is incomplete.")
                continue
            if fpath.suffix.lower() not in (".html", ".htm") and not _check_ts_syntax_complete(
                raw, fpath.suffix.lower()
            ):
                coverage_complete = False
                extra_notes.append(
                    f"TypeScript/JavaScript parse error in `{rel_src}`; display coverage is incomplete."
                )

            clean_txt = extract_script_preserving_lines(raw, fpath.suffix)
            parts = Path(rel_src).parts
            eff_parts = parts[1:] if len(parts) > 1 and parts[0] in ("lib", "app") else parts
            top_part = eff_parts[0] if eff_parts else ""
            is_vanilla_index_entry = (
                resolved in html_module_entries
                or (
                    len(parts) == 1
                    and is_vanilla_ui
                    and fpath.suffix.lower() in (".js", ".mjs")
                    and not _REEXPORT_STAR_RE.search(clean_txt)
                    and not _REEXPORT_NAMED_RE.search(clean_txt)
                )
            )
            if (
                fpath.name in ("index.ts", "index.tsx", "index.js", "index.jsx", "index.mjs")
                and top_part not in ("pages", "routes", "views")
                and not is_vanilla_index_entry
            ):
                targets: list[Path] = []
                for rex in (_REEXPORT_STAR_RE, _REEXPORT_NAMED_RE):
                    for m in rex.finditer(clean_txt):
                        t = resolve_frontend_import(
                            m.group("spec"), resolved, src_root, _EXTS, repo_root=repo_res
                        )
                        if t is not None:
                            targets.append(t)
                barrel_targets[resolved] = targets
                if _is_pure_barrel_ts(clean_txt, is_tsx=fpath.suffix.lower() in (".tsx", ".jsx", ".js")):
                    continue

            stem_low = fpath.stem.lower()
            is_html = fpath.suffix.lower() in (".html", ".htm")
            html_targets = html_module_targets.get(resolved, [])
            only_react_bootstrap = bool(html_targets) and all(
                t.name in ("main.tsx", "index.tsx") for t in html_targets
            )
            if (
                is_html
                and not is_in_src
                and has_src_tsx_pages
                and not _HTTP_OR_A11Y_HINT_RE.search(raw)
                and (not html_targets or only_react_bootstrap)
            ):
                continue

            is_kebab_snake_client = stem_low.endswith(_API_CLIENT_SUFFIXES)
            is_client_name = (
                stem_low in _API_CLIENT_STEMS
                or fpath.stem.endswith(_API_CLIENT_PASCAL_SUFFIXES)
                or is_kebab_snake_client
                or fpath.name.endswith(".gen.ts")
            )
            is_vanilla_entry = (
                resolved in html_module_entries
                or (
                    len(parts) == 1
                    and is_vanilla_ui
                    and fpath.suffix.lower() in (".js", ".mjs")
                    and stem_low in _VANILLA_ENTRY_STEMS
                )
            )
            in_client_dir = top_part in ("api", "client", "services", "clients", "queries") or (
                len(parts) > 1 and parts[0] in ("api", "client", "services", "clients", "queries")
            )
            in_named_js_dir = (
                top_part in ("views", "core", "utils", "shared", "services", "api")
                or (len(parts) > 1 and parts[0] in ("views", "core", "utils", "shared", "services", "api", "lib"))
            )
            if is_kebab_snake_client or (in_named_js_dir and stem_low in _API_CLIENT_STEMS):
                lbl, subkind, cluster = fpath.stem, "api_client", "api_clients"
            elif top_part in ("pages", "routes", "views") or fpath.stem == "App" or is_html or is_vanilla_entry:
                lbl = "/" if stem_low in ("app", "home", "index") else f"/{stem_low}"
                subkind, cluster = "page", "pages"
            elif top_part in ("hooks", "stores", "store") or _HOOK_STEM_RE.match(fpath.stem) or stem_low in ("store", "state"):
                lbl, subkind, cluster = fpath.stem, "hook", "hooks"
            elif in_client_dir or is_client_name:
                lbl, subkind, cluster = fpath.stem, "api_client", "api_clients"
            elif top_part in ("core", "utils", "shared"):
                lbl = fpath.stem
                if bool(_HTTP_OR_A11Y_HINT_RE.search(clean_txt)):
                    subkind, cluster = "api_client", "api_clients"
                else:
                    subkind, cluster = "component", top_part
            elif top_part in ("components", "features") or fpath.suffix in (".tsx", ".jsx"):
                lbl, subkind, cluster = fpath.stem, "component", top_part or "components"
            elif fpath.suffix.lower() in (".mjs", ".js", ".ts") and _HTTP_OR_A11Y_HINT_RE.search(clean_txt):
                lbl, subkind, cluster = fpath.stem, "api_client", "api_clients"
            else:
                continue

            cleaned[resolved] = clean_txt
            raw_sources[resolved] = raw
            rel_repo = resolved.relative_to(repo_res).as_posix()
            slug = Path(rel_src).with_suffix("").as_posix().replace("/", ".")
            node_id = f"d:{subkind}:{slug}"
            if node_id in used_node_ids:
                node_id = f"{node_id}.{fpath.suffix.lstrip('.').lower()}"
            used_node_ids.add(node_id)
            nodes_by_path[resolved] = AtlasNode(
                id=node_id,
                tier="display",
                subkind=subkind,  # type: ignore[arg-type]
                label=lbl,
                source_file=rel_repo,
                line=1,
                status="clean",
                role="surface",
                cluster=cluster,
                summary=f"React {subkind.replace('_', ' ')} `{lbl}` ({rel_repo}).",
            )

        ws_resolver = WorkspaceResolver.build(repo_res, (fe_dir,))
        reach: ReachabilityIndex | None = None
        try:
            graph_errors: list[str] = []
            graph_files = collect_safe_graph_files(
                fe_dir,
                repo_res,
                skip_dirs=_REACH_SKIP_DIRS | _SKIP_DIR_PARTS,
                errors_out=graph_errors,
            )
            known_graph = graph_files | set(nodes_by_path.keys())
            base_resolve = make_safe_graph_resolver(
                fe_dir,
                src_root,
                repo_res,
                known_graph,
                ws_resolver=ws_resolver,
                errors_out=graph_errors,
            )
            if graph_errors:
                coverage_complete = False
                extra_notes.extend(graph_errors)

            def _resolve_graph_import(spec: str, current_file: Path) -> Path | None:
                clean_spec = spec.split("?", 1)[0].split("#", 1)[0].strip()
                if not clean_spec:
                    return None
                hit = base_resolve(clean_spec, current_file)
                if hit is not None:
                    return hit
                hit = _resolve_spa_script_path(
                    clean_spec,
                    current_file,
                    fe_dir,
                    src_root,
                    html_mount_prefixes,
                    repo_root=repo_res,
                )
                return hit if hit is not None and hit in known_graph else None

            modules: dict[Path, _ModuleInfo] = {}
            for gf in sorted(known_graph):
                if gf.suffix.lower() in (".html", ".htm"):
                    synth = [cleaned.get(gf, "")]
                    for tgt in html_module_targets.get(gf, []):
                        rel_spec = os.path.relpath(tgt, gf.parent).replace("\\", "/")
                        if not rel_spec.startswith("."):
                            rel_spec = f"./{rel_spec}"
                        synth.append(f"import {json.dumps(rel_spec)};")
                    modules[gf] = parse_module(gf, "\n".join(synth))
                else:
                    text = cleaned.get(gf)
                    if text is None:
                        try:
                            raw_gf = safe_read_repo_text(gf, repo_res, encoding="utf-8")
                            text = extract_script_preserving_lines(raw_gf, gf.suffix)
                        except (OSError, UnicodeError) as exc:
                            coverage_complete = False
                            extra_notes.append(f"Unreadable frontend file `{gf}` ({exc}); display coverage is incomplete.")
                            continue
                    modules[gf] = parse_module(gf, text)

            html_roots = {
                p for p in known_graph if p.suffix.lower() in (".html", ".htm") and p in nodes_by_path
            }
            html_linked_entries = {
                tgt
                for hp in html_roots
                for tgt in html_module_targets.get(hp, [])
                if tgt in known_graph
            }
            js_roots = {
                p
                for p in graph_files
                if (is_react_spa_entry(p, src_root, fe_dir) or p in html_module_entries)
                and (p not in html_linked_entries or p.parent.name in ("pages", "routes", "views"))
            }
            reach_roots = html_roots | js_roots
            unreadable_graph = known_graph - modules.keys()
            if unreadable_graph:
                coverage_complete = False
            reach = ReachabilityIndex(
                modules,
                reach_roots,
                _resolve_graph_import,
                repo_res,
                unreadable_graph,
            )
        except (OSError, ValueError, RecursionError) as exc:
            reach = None
            coverage_complete = False
            extra_notes.append(f"Display reachability analysis failed ({exc}); display coverage is incomplete.")

        edges: list[AtlasEdge] = []
        seen_edges: set[tuple[str, str, str]] = set()
        http_calls: list[FrontendHttpCall] = []
        findings: list[RawCandidateFinding] = []

        const_read_errors: list[str] = []
        url_const_resolver = build_frontend_url_const_resolver(
            src_root,
            _EXTS,
            cleaned_cache=cleaned,
            html_api_base=html_api_base,
            repo_root=repo_res,
            read_errors_out=const_read_errors,
        )
        comp_resolver_for = build_a11y_component_resolver(src_root, _EXTS, repo_root=repo_res)
        has_gen_cfg = has_frontend_generator_config(fe_dir, repo_root=repo_res)
        sdk_index = WorkspaceSdkIndex.build(repo_res, ws_resolver)
        page_paths = {p for p, n in nodes_by_path.items() if n.subkind == "page"}
        unobserved_a11y: list[str] = []

        for fpath, node in nodes_by_path.items():
            try:
                sdk_calls, uses_typed_sdk = sdk_index.extract_caller_sdk_calls(
                    fpath,
                    cleaned[fpath],
                    is_tsx=fpath.suffix in (".tsx", ".jsx"),
                )
                specs, calls, mod_findings = scan_display_module_semantics(
                    node,
                    cleaned[fpath],
                    node.source_file,
                    raw_source=raw_sources[fpath],
                    imported_url_consts=url_const_resolver(fpath, cleaned[fpath]),
                    component_resolver=comp_resolver_for(fpath, raw_sources[fpath]),
                    unobserved_a11y_out=unobserved_a11y,
                    has_generator_config=has_gen_cfg,
                    sdk_calls=sdk_calls,
                    uses_typed_sdk=uses_typed_sdk,
                    mount_prefixes=html_mount_prefixes,
                    html_api_base=html_api_base,
                )
                if reach is not None:
                    annotated_calls: list[FrontendHttpCall] = []
                    for c in calls:
                        sym = reach.enclosing_symbol(fpath, c.line)
                        caller_sym = None if sym == MODULE_SYMBOL else sym
                        live: bool | None = None
                        trail: tuple[str, ...] = ()
                        entry_ids: tuple[str, ...] = ()
                        if reach.has_roots:
                            live = reach.is_live(fpath, sym)
                            trail = reach.trail(fpath, sym) if live else ()
                            if live:
                                entry_ids = tuple(
                                    nodes_by_path[rp].id
                                    for rp in reach.reaching_roots(fpath, sym, stop_paths=page_paths)
                                    if rp in nodes_by_path
                                )
                        annotated_calls.append(
                            replace(
                                c,
                                caller_symbol=caller_sym,
                                reachable=live,
                                reach_trail=trail,
                                entry_node_ids=entry_ids,
                            )
                        )
                    http_calls.extend(annotated_calls)
                else:
                    http_calls.extend(calls)
                findings.extend(mod_findings)
                for spec in specs:
                    dst_path = _resolve_spa_script_path(
                        spec,
                        fpath,
                        fe_dir,
                        src_root,
                        html_mount_prefixes,
                        repo_root=repo_res,
                    )
                    if dst_path is None:
                        dst_path = ws_resolver.resolve_import(spec, fpath, exts=_EXTS)
                    if dst_path is None:
                        continue
                    expanded = list(barrel_targets.get(dst_path, []))
                    if (dst_path in nodes_by_path or not expanded) and dst_path not in expanded:
                        expanded.insert(0, dst_path)
                    for exp in expanded:
                        if exp in nodes_by_path and exp != fpath:
                            dst = nodes_by_path[exp]
                            kind = "uses_hook" if dst.subkind == "hook" else "uses_client"
                            if (node.id, dst.id, kind) not in seen_edges:
                                seen_edges.add((node.id, dst.id, kind))
                                edges.append(
                                    AtlasEdge(
                                        id=f"e:{node.id}->{dst.id}:{kind}",
                                        source_id=node.id,
                                        target_id=dst.id,
                                        kind=kind,  # type: ignore[arg-type]
                                        verification="verified",
                                        evidence_path=node.source_file,
                                        evidence_note=f"Imports `{dst.label}`.",
                                    )
                                )
            except RecursionError as exc:
                coverage_complete = False
                extra_notes.append(
                    f"Display extraction exceeded recursion limit in `{node.source_file}` ({exc}); display coverage is incomplete."
                )

        if const_read_errors:
            coverage_complete = False
            extra_notes.extend(dict.fromkeys(const_read_errors))

        if reach is not None:
            for source, target in reach.import_edges():
                src_node, dst_node = nodes_by_path.get(source), nodes_by_path.get(target)
                if src_node is not None and dst_node is not None and src_node.id != dst_node.id:
                    kind = "uses_hook" if dst_node.subkind == "hook" else "uses_client"
                    if (src_node.id, dst_node.id, kind) not in seen_edges:
                        seen_edges.add((src_node.id, dst_node.id, kind))
                        edges.append(
                            AtlasEdge(
                                id=f"e:{src_node.id}->{dst_node.id}:{kind}",
                                source_id=src_node.id,
                                target_id=dst_node.id,
                                kind=kind,  # type: ignore[arg-type]
                                verification="declared",
                                evidence_path=src_node.source_file,
                                evidence_note=f"Dynamic or module-evaluation import of `{dst_node.label}`.",
                            )
                        )

        notes = reach.analysis_notes() if reach is not None else [
            "Display reachability could not be analyzed; unbacked calls remain blocking."
        ]
        if any(note.startswith("Unreadable source ") for note in notes):
            coverage_complete = False
        if extra_notes:
            notes = [*notes, *extra_notes]
        unobs_note = format_unobserved_a11y_note(unobserved_a11y)
        if unobs_note:
            notes.append(unobs_note)

        return DisplayExtractionResult(
            nodes=list(nodes_by_path.values()),
            edges=edges,
            http_calls=http_calls,
            findings=findings,
            coverage_complete=coverage_complete,
            notes=notes,
        )
