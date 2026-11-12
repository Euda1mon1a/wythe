"""Tier 2 Adapter: Rust Manipulation (`axum`, `actix-web`, `rocket`, `Tauri` + `sqlx`/`Diesel`/`SeaORM`)."""

from __future__ import annotations

import re
from pathlib import Path

from app.adapters.base import (
    ManipulatorExtractionResult,
    RawCandidateFinding,
    RouteDescriptor,
    TruthExtractionResult,
)
from app.adapters.rust_inspect import (
    _DIESEL_READ_RE,
    _DIESEL_WRITE_RE,
    _PLAIN_FN_DEF_RE,
    _QUALIFIED_CALL_RE,
    _QUERY_FILE_RE,
    _RUST_CLOCK_RE,
    _RUST_POLICY_RE,
    _SEAORM_READ_RE,
    _SEAORM_WRITE_RE,
    _SQL_READ_RE,
    _SQL_WRITE_RE,
    _USE_CRATE_RE,
    compile_rust_route_regex,
    extract_rust_routes,
    strip_rust_comments,
)
from app.core.policy_context import get_active_policy_tokens, name_has_policy_token
from app.schemas.atlas import AtlasEdge, AtlasNode

_SKIP_DIRS = ("target", "node_modules", ".git", "tests", "benches", "examples", "entity", "entities")
_INFRA_RS = ("main.rs", "lib.rs", "mod.rs", "schema.rs", "config.rs", "error.rs", "errors.rs", "db.rs", "state.rs")
_CARGO_NAME_RE = re.compile(r'^\s*name\s*=\s*"(?P<name>[^"]+)"', re.MULTILINE)
_USE_ANY_RE = re.compile(r"""\buse\s+(?P<crate>[a-z_][a-z0-9_]*)::(?P<path>[A-Za-z0-9_:{},\s*]+);""")


def _is_wasm_ui_crate(crate_dir: Path) -> bool:
    if (crate_dir / "Trunk.toml").is_file() or (crate_dir / "index.html").is_file():
        return True
    ctoml = crate_dir / "Cargo.toml"
    if ctoml.is_file():
        txt = ctoml.read_text(encoding="utf-8", errors="replace").lower()
        if any(fw in txt for fw in ("yew", "leptos", "dioxus", "wasm-bindgen")):
            return True
    return False


class RustHttpAdapter:
    """Extracts Rust HTTP/Tauri routes, module call graphs, SQL/ORM read-write links, and MANIP rules."""

    name = "rust-http"

    def extract(
        self,
        repo_root: Path,
        backend_subdir: str,
        truth: TruthExtractionResult,
    ) -> ManipulatorExtractionResult:
        base_dir = repo_root if backend_subdir in ("", ".") else repo_root / backend_subdir
        if backend_subdir in ("", ".") and (repo_root / "src-tauri" / "Cargo.toml").is_file():
            base_dir = repo_root / "src-tauri"

        scan_roots: list[Path] = []
        crate_ident_to_files: dict[str, list[Path]] = {}
        primary_src = base_dir / "src" if (base_dir / "src").is_dir() else base_dir
        if primary_src.is_dir():
            scan_roots.append(primary_src)
        if (repo_root / "crates").is_dir():
            for cdir in sorted((repo_root / "crates").iterdir()):
                if not cdir.is_dir() or _is_wasm_ui_crate(cdir):
                    continue
                csrc = cdir / "src"
                if csrc.is_dir() and csrc not in scan_roots:
                    scan_roots.append(csrc)
                ctoml = cdir / "Cargo.toml"
                if ctoml.is_file():
                    nm = _CARGO_NAME_RE.search(ctoml.read_text(encoding="utf-8", errors="replace"))
                    if nm:
                        crate_ident_to_files[nm.group("name").replace("-", "_")] = []

        if not scan_roots:
            return ManipulatorExtractionResult(nodes=[], edges=[], routes=[], findings=[])

        cleaned_by_file: dict[Path, str] = {}
        routes_by_file: dict[Path, list[tuple[str, str, int, set[str]]]] = {}
        pub_fns_by_file: dict[Path, set[str]] = {}
        wasted_ui_dirs = {
            cdir.resolve()
            for cdir in ((repo_root / "crates").iterdir() if (repo_root / "crates").is_dir() else ())
            if cdir.is_dir() and _is_wasm_ui_crate(cdir)
        }

        seen_rs: set[Path] = set()
        for sroot in scan_roots:
            for rs_file in sorted(sroot.rglob("*.rs")):
                resolved_rs = rs_file.resolve()
                if resolved_rs in seen_rs or any(resolved_rs.is_relative_to(wd) for wd in wasted_ui_dirs):
                    continue
                if any(p in _SKIP_DIRS for p in rs_file.parts) or rs_file.name in ("build.rs", "schema.rs", "mod.rs"):
                    continue
                seen_rs.add(resolved_rs)
                try:
                    raw = rs_file.read_text(encoding="utf-8")
                except (OSError, UnicodeError):
                    continue
                if "#[sea_orm(" in raw or "diesel::table!" in raw:
                    continue
                cleaned = strip_rust_comments(raw)
                cleaned_by_file[rs_file] = cleaned
                routes_by_file[rs_file] = extract_rust_routes(cleaned)
                pub_fns_by_file[rs_file] = {m.group("fn") for m in _PLAIN_FN_DEF_RE.finditer(cleaned)}

        nodes_by_file: dict[Path, AtlasNode] = {}
        stem_to_files: dict[str, list[Path]] = {}
        fn_to_files: dict[str, list[Path]] = {}

        for rs_file, file_routes in routes_by_file.items():
            rel_repo = rs_file.relative_to(repo_root).as_posix()
            rel_src = rs_file.relative_to(primary_src).as_posix() if rs_file.is_relative_to(primary_src) else rel_repo
            parts = Path(rel_src).parts
            if file_routes or any(p in ("routes", "handlers", "controllers", "endpoints", "commands") for p in parts):
                subkind, cluster = "route", "api"
            elif any(p in ("solver", "solvers", "scheduling", "engine") for p in parts):
                subkind, cluster = "solver", parts[0]
            elif "bin" in parts or rs_file.name == "cli.rs":
                subkind, cluster = "cli", "cli"
            else:
                subkind, cluster = "service", parts[0] if len(parts) > 1 else "services"

            slug = Path(rel_src).with_suffix("").as_posix().replace("/", ".")
            nid = f"m:{subkind}:{slug}"
            nodes_by_file[rs_file] = AtlasNode(
                id=nid,
                tier="manipulate",
                subkind=subkind,  # type: ignore[arg-type]
                label=slug,
                source_file=rel_repo,
                line=1,
                status="clean",
                role="mechanism",
                cluster=cluster,
                summary=f"Rust {subkind} `{slug}` ({rel_repo}).",
            )
            stem_to_files.setdefault(rs_file.stem, []).append(rs_file)
            for cident, cfiles in crate_ident_to_files.items():
                if f"/{cident.replace('_', '-')}/" in f"/{rel_repo}":
                    if rs_file.name == "lib.rs":
                        cfiles.insert(0, rs_file)
                    else:
                        cfiles.append(rs_file)
            for fn_name in pub_fns_by_file[rs_file]:
                fn_to_files.setdefault(fn_name, []).append(rs_file)

        has_service_layer = any(n.subkind in ("service", "solver") for n in nodes_by_file.values())
        edges: list[AtlasEdge] = []
        seen_edges: set[tuple[str, str, str]] = set()
        routes: list[RouteDescriptor] = []
        findings: list[RawCandidateFinding] = []
        table_readers: dict[str, set[str]] = {}
        table_writers: dict[str, set[str]] = {}

        def add_edge(src: str, dst: str, kind: str, path: str, note: str) -> None:
            key = (src, dst, kind)
            if src == dst or key in seen_edges:
                return
            seen_edges.add(key)
            edges.append(
                AtlasEdge(
                    id=f"e:{src}->{dst}:{kind}",
                    source_id=src,
                    target_id=dst,
                    kind=kind,  # type: ignore[arg-type]
                    verification="verified",
                    evidence_path=path,
                    evidence_note=note,
                )
            )

        for rs_file, node in nodes_by_file.items():
            txt = cleaned_by_file[rs_file]
            rel_repo = node.source_file

            # 1. Intra-crate `use crate::...`, `mod::fn(...)`, and direct handler/helper calls
            for um in _USE_CRATE_RE.finditer(txt):
                tokens = [t for t in re.split(r"[:{},\s*]+", um.group("path")) if t]
                for tok in tokens:
                    for dst_f in stem_to_files.get(tok, []):
                        if dst_f != rs_file:
                            add_edge(node.id, nodes_by_file[dst_f].id, "calls_helper", rel_repo, f"Imports `crate::...::{tok}`.")
                    for dst_f in fn_to_files.get(tok, []):
                        if dst_f != rs_file:
                            add_edge(node.id, nodes_by_file[dst_f].id, "calls_helper", rel_repo, f"Invokes `{tok}()`.")

            for qm in _QUALIFIED_CALL_RE.finditer(txt):
                for dst_f in stem_to_files.get(qm.group("mod"), []):
                    if dst_f != rs_file:
                        add_edge(node.id, nodes_by_file[dst_f].id, "calls_helper", rel_repo, f"Calls `{qm.group('mod')}::{qm.group('fn')}()`.")

            for wum in _USE_ANY_RE.finditer(txt):
                c_ident = wum.group("crate")
                if c_ident not in crate_ident_to_files:
                    continue
                tokens = [t for t in re.split(r"[:{},\s*]+", wum.group("path")) if t]
                matched_specific = False
                for tok in tokens:
                    for dst_f in stem_to_files.get(tok, []) + fn_to_files.get(tok, []):
                        if dst_f != rs_file:
                            matched_specific = True
                            add_edge(node.id, nodes_by_file[dst_f].id, "calls_helper", rel_repo, f"Imports `{c_ident}::...::{tok}`.")
                if not matched_specific and crate_ident_to_files[c_ident]:
                    dst_f = crate_ident_to_files[c_ident][0]
                    if dst_f != rs_file:
                        add_edge(node.id, nodes_by_file[dst_f].id, "calls_helper", rel_repo, f"Imports workspace crate `{c_ident}`.")

            # Link injected trait/struct fields like `articles_service.get_articles(...)` or `articles_repository.get_articles(...)`
            for stem_key, dst_files in stem_to_files.items():
                if len(stem_key) > 6 and stem_key.endswith(("_service", "_repository")) and stem_key in txt:
                    for dst_f in dst_files:
                        if dst_f != rs_file:
                            add_edge(node.id, nodes_by_file[dst_f].id, "calls_helper", rel_repo, f"Delegates to `{stem_key}`.")

            # 2. Route descriptors
            methods_seen: list[str] = []
            paths_seen: list[str] = []
            for verb, full_p, lineno, h_syms in routes_by_file[rs_file]:
                if verb not in methods_seen:
                    methods_seen.append(verb)
                if full_p not in paths_seen:
                    paths_seen.append(full_p)
                for h_sym in h_syms:
                    for dst_f in fn_to_files.get(h_sym, []):
                        if dst_f != rs_file:
                            add_edge(node.id, nodes_by_file[dst_f].id, "calls_helper", rel_repo, f"Mounts handler `{h_sym}`.")
                routes.append(
                    RouteDescriptor(
                        node_id=node.id,
                        http_method=verb,
                        full_path=full_p,
                        path_regex=compile_rust_route_regex(full_p),
                        source_file=rel_repo,
                        line=lineno,
                        called_symbols=h_syms,
                        imported_modules=set(),
                    )
                )
            node.http_methods = methods_seen
            node.http_paths = paths_seen[:25]

            # 3. SQL / sqlx / Diesel / SeaORM read & write extraction
            write_tids: list[tuple[str, int]] = []
            read_tids: set[str] = set()

            for wm in _SQL_WRITE_RE.finditer(txt):
                tid = truth.table_symbol_map.get(wm.group(1).lower())
                if tid:
                    write_tids.append((tid, txt.count("\n", 0, wm.start()) + 1))
            for rm in _SQL_READ_RE.finditer(txt):
                tid = truth.table_symbol_map.get(rm.group(1).lower())
                if tid:
                    read_tids.add(tid)
            for qfm in _QUERY_FILE_RE.finditer(txt):
                qf_arg = qfm.group("qfile")
                lineno = txt.count("\n", 0, qfm.start()) + 1
                wtid = truth.table_symbol_map.get(f"sqlx_file:write:{qf_arg}") or truth.table_symbol_map.get(f"sqlx_file:write:{Path(qf_arg).name}")
                rtid = truth.table_symbol_map.get(f"sqlx_file:read:{qf_arg}") or truth.table_symbol_map.get(f"sqlx_file:read:{Path(qf_arg).name}")
                if wtid:
                    write_tids.append((wtid, lineno))
                if rtid:
                    read_tids.add(rtid)
            for dwm in _DIESEL_WRITE_RE.finditer(txt):
                tid = truth.table_symbol_map.get(dwm.group("tbl").lower())
                if tid:
                    write_tids.append((tid, txt.count("\n", 0, dwm.start()) + 1))
            for drm in _DIESEL_READ_RE.finditer(txt):
                tid = truth.table_symbol_map.get(drm.group("tbl").lower())
                if tid:
                    read_tids.add(tid)
            for swm in _SEAORM_WRITE_RE.finditer(txt):
                tid = truth.table_symbol_map.get(swm.group("ent").lower())
                if tid:
                    write_tids.append((tid, txt.count("\n", 0, swm.start()) + 1))
            for srm in _SEAORM_READ_RE.finditer(txt):
                tid = truth.table_symbol_map.get(srm.group("ent").lower())
                if tid:
                    read_tids.add(tid)

            for tid in sorted(read_tids):
                table_readers.setdefault(tid, set()).add(node.id)
                add_edge(node.id, tid, "reads_truth", rel_repo, f"Rust query reads `{tid}`.")
            seen_direct_write: set[str] = set()
            for tid, wline in write_tids:
                table_writers.setdefault(tid, set()).add(node.id)
                add_edge(node.id, tid, "writes_truth", rel_repo, f"Rust mutation writes `{tid}`.")
                if node.subkind == "route" and has_service_layer and tid not in seen_direct_write:
                    seen_direct_write.add(tid)
                    findings.append(
                        RawCandidateFinding(
                            rule_code="TRUTH-003",
                            node_id=node.id,
                            source_file=rel_repo,
                            line=wline,
                            title=f"Rust route handler `{node.label}` mutates `{tid}` directly",
                            detail=f"{rel_repo}:{wline} writes `{tid}` inside HTTP/Tauri handler instead of a transactional service door.",
                            remediation="Delegate mutations to a Rust domain/repository service or DB write-lane function.",
                        )
                    )

            # 4. MANIP-001 & MANIP-002
            active_tokens = get_active_policy_tokens()
            for pm in _RUST_POLICY_RE.finditer(txt):
                cname = pm.group("name")
                if name_has_policy_token(cname, active_tokens):
                    lineno = txt.count("\n", 0, pm.start()) + 1
                    node.status = "policy_in_code"
                    findings.append(
                        RawCandidateFinding(
                            rule_code="MANIP-001",
                            node_id=node.id,
                            source_file=rel_repo,
                            line=lineno,
                            title=f"Hardcoded Rust policy constant `{cname}` ({pm.group('val')})",
                            detail=f"{rel_repo}:{lineno} hardcodes mutable domain policy `{cname}` in Rust.",
                            remediation="Persist policy thresholds in database truth and load via typed query.",
                        )
                    )

            if rs_file.name not in ("clock.rs", "time.rs"):
                for cm in _RUST_CLOCK_RE.finditer(txt):
                    lineno = txt.count("\n", 0, cm.start()) + 1
                    if node.status == "clean":
                        node.status = "gray_zone"
                    findings.append(
                        RawCandidateFinding(
                            rule_code="MANIP-002",
                            node_id=node.id,
                            source_file=rel_repo,
                            line=lineno,
                            title=f"Direct Rust host clock call `{cm.group(0).strip()}`",
                            detail=f"{rel_repo}:{lineno} calls `{cm.group(0).strip()}` directly instead of a clock authority.",
                            remediation="Inject a shared Clock trait / database time authority.",
                        )
                    )

        # 5. Update truth read/write counts & TRUTH-001
        for tnode in truth.nodes:
            if tnode.subkind != "table":
                continue
            tnode.read_by_count = len(table_readers.get(tnode.id, set()))
            tnode.written_by_count = len(table_writers.get(tnode.id, set()))
            if tnode.read_by_count == 0 and tnode.role == "input":
                tnode.status = "orphaned"
                findings.append(
                    RawCandidateFinding(
                        rule_code="TRUTH-001",
                        node_id=tnode.id,
                        source_file=tnode.source_file,
                        line=tnode.line,
                        title=f"Persisted input table `{tnode.label}` has 0 verified Rust readers",
                        detail=f"`{tnode.label}` is defined as input truth, but no Rust module reads it.",
                        remediation="Wire active Rust consumers or retire unused schema.",
                    )
                )

        # 6. MANIP-003 (inert service/solver modules)
        inbound: dict[str, int] = {}
        for e in edges:
            if e.kind == "calls_helper":
                inbound[e.target_id] = inbound.get(e.target_id, 0) + 1
        for rs_file, node in nodes_by_file.items():
            if node.subkind in ("service", "solver") and rs_file.name not in _INFRA_RS and inbound.get(node.id, 0) == 0:
                if node.status == "clean":
                    node.status = "unwired"
                findings.append(
                    RawCandidateFinding(
                        rule_code="MANIP-003",
                        node_id=node.id,
                        source_file=node.source_file,
                        line=1,
                        title=f"Rust manipulator `{node.label}` has no inbound callers",
                        detail=f"`{node.source_file}` is not invoked by any route, command, CLI, or peer service.",
                        remediation="Wire the Rust module into an active route/command door or remove dead code.",
                    )
                )

        return ManipulatorExtractionResult(
            nodes=list(nodes_by_file.values()),
            edges=edges,
            routes=routes,
            findings=findings,
        )
