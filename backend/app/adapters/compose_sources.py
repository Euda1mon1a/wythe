"""Static Docker Compose / Compose Specification lineage adapter.

Parses `compose*.yaml`/`compose*.yml` and `docker-compose*.yaml`/`docker-compose*.yml`
at the repository root and 1-level subdirectories (including `.docker/`) via
`yaml.safe_load` without invoking `docker` or inspecting running containers.
"""

from __future__ import annotations

import copy
import re
from dataclasses import dataclass, field
from pathlib import Path, PurePosixPath

import yaml

from app.adapters.base import ManipulatorExtractionResult, RawCandidateFinding
from app.adapters.dockerfile_sources import (
    ALLOWED_CONTAINER_DOT_DIRS,
    CommandTarget,
    DockerIgnoreSpec,
    DockerStage,
    ParsedDockerfile,
    StageCopyMapping,
    _is_within_root,
    _norm_container_path,
    augment_dockerfile_sources,
    effective_node_symbol_links,
    ensure_repo_target_nodes,
    extract_command_targets_from_argv,
    extract_command_targets_from_shell,
    index_nodes_by_source,
    is_compose_filename,
    parse_dockerfile,
    resolve_command_targets_with_symbols,
)
from app.adapters.service_sources import EXCLUDED_PARTS
from app.core.policy_context import get_active_policy_tokens, name_has_policy_token
from app.schemas.atlas import AtlasEdge, AtlasNode

_COMPOSE_NAMES = ("compose.yaml", "compose.yml", "docker-compose.yaml", "docker-compose.yml")
_DB_BACKING_IMAGES = frozenset(
    {"postgres", "postgresql", "postgis", "pgvector", "timescaledb", "mysql", "mariadb"}
)
_CACHE_BACKING_IMAGES = frozenset(
    {"redis", "redis-stack", "redis-stack-server", "valkey", "dragonfly"}
)
_NUMERIC_LITERAL_RE = re.compile(r"^[+-]?(?:\d+(?:\.\d+)?|\.\d+)$")
_PURE_ENV_INTERP_RE = re.compile(
    r"^\$(?:[A-Za-z_][A-Za-z0-9_]*|\{[A-Za-z_][A-Za-z0-9_]*(?::\?[^}]*)?\}|\([A-Za-z_][A-Za-z0-9_]*\))$"
)
_DEFAULT_ENV_INTERP_RE = re.compile(
    r"^\$\{[A-Za-z_][A-Za-z0-9_]*(?::-|-|:=|=)(?P<default>[^}]*)\}$"
)
_SVC_HEADER_RE = re.compile(r"^(?P<indent>\s+)(?P<name>[A-Za-z0-9_.-]+)\s*:\s*(?:#.*)?$")


@dataclass(frozen=True)
class ComposeServiceSpec:
    name: str
    line: int
    build_context: str | None = None
    build_dockerfile: str | None = None
    build_target: str | None = None
    image: str | None = None
    command: str | list[str] | None = None
    entrypoint: str | list[str] | None = None
    working_dir: str | None = None
    depends_on: tuple[str, ...] = ()
    environment: tuple[tuple[str, object, int], ...] = ()
    bind_mounts: tuple[tuple[str, str], ...] = ()  # (host_rel_to_compose_dir, container_path)


@dataclass(frozen=True)
class ParsedComposeFile:
    rel_path: str
    abs_path: Path
    services: list[ComposeServiceSpec] = field(default_factory=list)


def discover_compose_files(repo_root: Path) -> list[Path]:
    """Discover compose files at `repo_root` and immediate 1-level subdirectories (incl. `.docker`)."""
    if repo_root.is_symlink():
        return []
    real_root = repo_root.resolve()
    dirs_to_check = [repo_root]
    try:
        for child in sorted(repo_root.iterdir()):
            if (
                not child.is_symlink()
                and child.is_dir()
                and (not child.name.startswith(".") or child.name in ALLOWED_CONTAINER_DOT_DIRS)
                and child.name not in EXCLUDED_PARTS
                and _is_within_root(child, real_root)
            ):
                dirs_to_check.append(child)
    except OSError:
        return []

    found: list[Path] = []
    for sdir in dirs_to_check:
        try:
            entries = sorted(sdir.iterdir())
        except OSError:
            continue
        for cand in entries:
            if (
                is_compose_filename(cand.name)
                and not cand.is_symlink()
                and cand.is_file()
                and _is_within_root(cand, real_root)
            ):
                found.append(cand)
    return sorted(found, key=lambda p: p.resolve().relative_to(real_root).as_posix())


def _locate_compose_lines(text: str, service_names: set[str]) -> tuple[dict[str, int], dict[tuple[str, str], int]]:
    """Best-effort 1-based line numbers for `services.<svc>` and `environment` keys."""
    svc_lines: dict[str, int] = {}
    env_lines: dict[tuple[str, str], int] = {}
    in_services = False
    services_indent = -1
    svc_indent: int | None = None
    current_svc: str | None = None

    for lineno, raw in enumerate(text.splitlines(), start=1):
        stripped = raw.strip()
        if not stripped or stripped.startswith("#"):
            continue
        indent = len(raw) - len(raw.lstrip(" "))
        if re.match(r"^services\s*:\s*(?:#.*)?$", stripped) and (not in_services or indent <= services_indent):
            in_services = True
            services_indent = indent
            svc_indent = None
            current_svc = None
            continue
        if not in_services:
            continue
        if indent <= services_indent:
            in_services = False
            current_svc = None
            continue

        m = _SVC_HEADER_RE.match(raw)
        if m and m.group("name") in service_names and (svc_indent is None or indent == svc_indent):
            svc_indent = indent
            current_svc = m.group("name")
            svc_lines.setdefault(current_svc, lineno)
            continue

        if current_svc is not None and svc_indent is not None and indent > svc_indent:
            kv_dict = re.match(r"^(?:-\s*)?(?P<key>[A-Za-z_][A-Za-z0-9_]*)\s*[:=]", stripped)
            if kv_dict:
                env_lines.setdefault((current_svc, kv_dict.group("key")), lineno)
    return svc_lines, env_lines


def classify_backing_image(image: str | None) -> str | None:
    """Return canonical backing technology (`postgres`, `mysql`, `mariadb`, `redis`, `valkey`) or None."""
    if not image or not isinstance(image, str):
        return None
    ref = image.strip().split("@", 1)[0].split(":", 1)[0].lower()
    leaf = ref.rsplit("/", 1)[-1]
    if leaf in _DB_BACKING_IMAGES:
        if leaf in {"postgresql", "postgis", "pgvector", "timescaledb"}:
            return "postgres"
        return leaf
    if leaf in _CACHE_BACKING_IMAGES:
        if leaf in {"redis-stack", "redis-stack-server", "dragonfly"}:
            return "redis"
        return leaf
    for candidate in ("postgres", "mariadb", "mysql", "valkey", "redis"):
        if leaf.startswith(candidate + "-") or leaf.endswith("-" + candidate):
            return candidate
    return None


_classify_backing_image = classify_backing_image


def _normalize_command_field(raw: object) -> str | list[str] | None:
    if isinstance(raw, str):
        return raw.strip() or None
    if isinstance(raw, list):
        items = [str(x) for x in raw if isinstance(x, (str, int, float)) and not isinstance(x, bool)]
        return items or None
    return None


def _extract_depends_on(raw: object) -> tuple[str, ...]:
    if isinstance(raw, list):
        return tuple(str(x).strip() for x in raw if isinstance(x, str) and x.strip())
    if isinstance(raw, dict):
        return tuple(str(k).strip() for k in raw if isinstance(k, str) and k.strip())
    return ()


def _extract_environment(
    raw: object,
    svc_name: str,
    svc_line: int,
    env_lines: dict[tuple[str, str], int],
) -> tuple[tuple[str, object, int], ...]:
    items: list[tuple[str, object, int]] = []
    if isinstance(raw, dict):
        for k, v in raw.items():
            if not isinstance(k, str) or not k.strip():
                continue
            key = k.strip()
            line = env_lines.get((svc_name, key), svc_line)
            items.append((key, v, line))
    elif isinstance(raw, list):
        for entry in raw:
            if not isinstance(entry, str):
                continue
            s = entry.strip()
            if not s:
                continue
            if "=" in s:
                key, val = s.split("=", 1)
                key = key.strip()
                if key:
                    line = env_lines.get((svc_name, key), svc_line)
                    items.append((key, val, line))
            else:
                line = env_lines.get((svc_name, s), svc_line)
                items.append((s, None, line))
    return tuple(items)


def _extract_bind_mounts(raw: object) -> tuple[tuple[str, str], ...]:
    mounts: list[tuple[str, str]] = []
    if not isinstance(raw, list):
        return ()
    for item in raw:
        if isinstance(item, str):
            parts = item.split(":")
            if len(parts) >= 2 and (
                parts[0].startswith((".", "/")) or "/" in parts[0]
            ):
                mounts.append((parts[0].strip(), parts[1].strip()))
        elif isinstance(item, dict):
            vtype = str(item.get("type") or "bind").lower()
            src = item.get("source")
            tgt = item.get("target")
            if vtype == "bind" and isinstance(src, str) and isinstance(tgt, str) and src and tgt:
                mounts.append((src.strip(), tgt.strip()))
    return tuple(mounts)


def parse_compose_file(
    compose_path: Path,
    repo_root: Path,
) -> tuple[ParsedComposeFile | None, str | None]:
    real_root = repo_root.resolve()
    if compose_path.is_symlink() or not compose_path.is_file() or not _is_within_root(compose_path, real_root):
        return None, None
    rel_path = compose_path.resolve().relative_to(real_root).as_posix()
    try:
        text = compose_path.read_text(encoding="utf-8")
        data = yaml.safe_load(text)
    except (OSError, UnicodeError, yaml.YAMLError):
        return None, f"Could not parse compose file {rel_path}; service declarations absent."

    if data is None:
        return ParsedComposeFile(rel_path=rel_path, abs_path=compose_path, services=[]), None
    if not isinstance(data, dict) or not isinstance(data.get("services"), dict):
        return ParsedComposeFile(rel_path=rel_path, abs_path=compose_path, services=[]), None

    raw_services: dict[str, object] = data["services"]
    svc_names = {str(k) for k in raw_services if isinstance(k, str)}
    svc_lines, env_lines = _locate_compose_lines(text, svc_names)

    specs: list[ComposeServiceSpec] = []
    for svc_name, cfg in raw_services.items():
        if not isinstance(svc_name, str) or not isinstance(cfg, dict):
            continue
        line = svc_lines.get(svc_name, 1)
        b_ctx: str | None = None
        b_df: str | None = None
        b_target: str | None = None
        build = cfg.get("build")
        if isinstance(build, str) and build.strip():
            b_ctx = build.strip()
            b_df = "Dockerfile"
        elif isinstance(build, dict):
            b_ctx = str(build.get("context") or ".").strip()
            b_df = str(build.get("dockerfile") or "Dockerfile").strip()
            if isinstance(build.get("target"), str) and build["target"].strip():
                b_target = build["target"].strip()

        image_val = cfg.get("image")
        image_str = image_val.strip() if isinstance(image_val, str) and image_val.strip() else None
        wd_val = cfg.get("working_dir")
        wd_str = wd_val.strip() if isinstance(wd_val, str) and wd_val.strip() else None

        specs.append(
            ComposeServiceSpec(
                name=svc_name,
                line=line,
                build_context=b_ctx,
                build_dockerfile=b_df,
                build_target=b_target,
                image=image_str,
                command=_normalize_command_field(cfg.get("command")),
                entrypoint=_normalize_command_field(cfg.get("entrypoint")),
                working_dir=wd_str,
                depends_on=_extract_depends_on(cfg.get("depends_on")),
                environment=_extract_environment(cfg.get("environment"), svc_name, line, env_lines),
                bind_mounts=_extract_bind_mounts(cfg.get("volumes")),
            )
        )
    return ParsedComposeFile(rel_path=rel_path, abs_path=compose_path, services=specs), None


def policy_literal_sample(
    env_key: str,
    raw_val: object,
    active_tokens: tuple[str, ...],
) -> str | None:
    key_up = env_key.strip().upper()
    if not key_up or not name_has_policy_tokens_match(key_up, active_tokens):
        return None
    if raw_val is None or isinstance(raw_val, bool):
        return None
    if isinstance(raw_val, (int, float)):
        return repr(raw_val)
    if isinstance(raw_val, (list, dict)):
        return f"collection[{len(raw_val)}]" if len(raw_val) >= 2 else None
    if isinstance(raw_val, str):
        s = raw_val.strip()
        if not s or s.lower() in {"true", "false", "null", "none", "yes", "no", "on", "off"}:
            return None
        if _PURE_ENV_INTERP_RE.match(s):
            return None
        dm = _DEFAULT_ENV_INTERP_RE.match(s)
        if dm is not None:
            s = dm.group("default").strip()
            if not s or _PURE_ENV_INTERP_RE.match(s):
                return None
        if _NUMERIC_LITERAL_RE.match(s):
            return s
        if "," in s and "://" not in s and len([p for p in s.split(",") if p.strip()]) >= 3:
            return repr(s[:32])
    return None


_policy_literal_sample = policy_literal_sample


def name_has_policy_tokens_match(key_up: str, active_tokens: tuple[str, ...]) -> bool:
    return name_has_policy_token(key_up, active_tokens)


def _effective_compose_stage(
    svc: ComposeServiceSpec,
    compose_dir: Path,
    parsed_df: ParsedDockerfile | None,
    real_root: Path,
) -> DockerStage | None:
    base_stage = parsed_df.select_stage(svc.build_target) if parsed_df is not None else None
    if base_stage is None and not svc.bind_mounts and not svc.working_dir:
        return None
    if base_stage is not None:
        eff = copy.deepcopy(base_stage)
    else:
        eff = DockerStage(index=0, name=None, base_image=svc.image or "scratch", line=svc.line)
    if svc.working_dir:
        eff.workdir = _norm_container_path(svc.working_dir, eff.workdir)
    for k, v, _ in svc.environment:
        if isinstance(v, (str, int, float)) and not isinstance(v, bool):
            eff.env[k] = str(v)
    for host_src, cont_tgt in svc.bind_mounts:
        hpath = (compose_dir / host_src).resolve()
        if hpath.is_symlink() or not _is_within_root(hpath, real_root) or not hpath.exists():
            continue
        repo_rel = "." if hpath == real_root else hpath.relative_to(real_root).as_posix()
        c_dest = _norm_container_path(cont_tgt, eff.workdir)
        eff.mappings.append(
            StageCopyMapping(
                container_path=c_dest,
                repo_rel=repo_rel,
                is_dir=hpath.is_dir(),
                context_rel_root=".",
                ignore_spec=DockerIgnoreSpec(),
            )
        )
    return eff


def _extract_compose_command_targets(
    svc: ComposeServiceSpec,
    stage: DockerStage | None,
) -> list[CommandTarget]:
    env = stage.env if stage is not None else {}
    wdir = stage.workdir if stage is not None else (svc.working_dir or "/")
    targets: list[CommandTarget] = []
    for field_val in (svc.entrypoint, svc.command):
        if isinstance(field_val, list) and field_val:
            targets.extend(extract_command_targets_from_argv(field_val, env, wdir))
        elif isinstance(field_val, str) and field_val:
            targets.extend(extract_command_targets_from_shell(field_val, env, wdir))
    if isinstance(svc.entrypoint, list) and isinstance(svc.command, list) and svc.entrypoint and svc.command:
        targets.extend(extract_command_targets_from_argv([*svc.entrypoint, *svc.command], env, wdir))
    return list(dict.fromkeys(targets))


def augment_compose_sources(
    repo_root: Path,
    backend_subdir: str,
    result: ManipulatorExtractionResult,
    dockerfiles: dict[str, object] | None = None,
) -> None:
    """Discover compose files, add `m:compose:*` nodes/edges, and flag hardcoded policy env vars."""
    cpaths = discover_compose_files(repo_root)
    if not cpaths:
        return

    real_root = repo_root.resolve()
    df_cache: dict[str, ParsedDockerfile] = {
        k: v for k, v in (dockerfiles or {}).items() if isinstance(v, ParsedDockerfile)
    }
    by_src = index_nodes_by_source(result)
    seen_node_ids = {n.id for n in result.nodes}
    seen_edge_ids = {e.id for e in result.edges}
    active_tokens = get_active_policy_tokens()

    file_count = 0
    all_svc_labels: list[str] = []
    build_linked = 0
    backing_stores: list[str] = []
    unresolved_external: list[str] = []

    for cpath in cpaths:
        parsed_cf, err_note = parse_compose_file(cpath, repo_root)
        if err_note:
            result.notes.append(err_note)
        if parsed_cf is None or not parsed_cf.services:
            continue
        file_count += 1
        rel = parsed_cf.rel_path
        compose_dir = cpath.parent.resolve()

        svc_node_map: dict[str, AtlasNode] = {}
        svc_resolved_df: dict[str, tuple[str | None, ParsedDockerfile | None, Path | None]] = {}

        for svc in parsed_cf.services:
            nid = f"m:compose:{rel}:{svc.name}"
            all_svc_labels.append(svc.name)
            backing_kind = _classify_backing_image(svc.image)

            df_rel: str | None = None
            parsed_df: ParsedDockerfile | None = None
            ctx_dir: Path | None = None
            if svc.build_context is not None:
                cand_ctx = (compose_dir / svc.build_context).resolve()
                if _is_within_root(cand_ctx, real_root) and cand_ctx.is_dir():
                    ctx_dir = cand_ctx
                    df_name = svc.build_dockerfile or "Dockerfile"
                    df_cand = ctx_dir / df_name
                    if not df_cand.is_file():
                        df_cand = compose_dir / df_name
                    if not df_cand.is_symlink() and df_cand.is_file() and _is_within_root(df_cand, real_root):
                        df_rel = df_cand.resolve().relative_to(real_root).as_posix()
                        parsed_df = df_cache.get(df_rel)
                        if parsed_df is None:
                            parsed_df = parse_dockerfile(df_cand, repo_root, context_override=ctx_dir)
                            if parsed_df is not None:
                                df_cache[df_rel] = parsed_df
                    else:
                        result.findings.append(
                            RawCandidateFinding(
                                rule_code="MANIP-005",
                                node_id=nid,
                                source_file=rel,
                                line=svc.line,
                                title=f"Compose service `{svc.name}` names absent Dockerfile `{df_name}`",
                                detail=(
                                    f"Service `{svc.name}` at `{rel}:{svc.line}` declares `build.dockerfile` "
                                    f"`{df_name}`, which does not exist in `{svc.build_context}`."
                                ),
                                remediation="Fix `build.context`/`build.dockerfile` or restore the missing Dockerfile.",
                            )
                        )
            svc_resolved_df[svc.name] = (df_rel, parsed_df, ctx_dir)

            if df_rel is not None:
                build_linked += 1
                origin_txt = f"Builds `{df_rel}`" + (f" (target `{svc.build_target}`)" if svc.build_target else "")
            elif backing_kind is not None:
                backing_stores.append(f"{svc.name} [{backing_kind}]")
                origin_txt = f"Backing `{backing_kind}` store image `{svc.image}`"
            elif svc.image:
                unresolved_external.append(f"{svc.name} [{svc.image}]")
                origin_txt = f"External image `{svc.image}`"
            else:
                origin_txt = "Unresolved service origin"

            parent_rel = PurePosixPath(rel).parent
            svc_label = (
                svc.name
                if parent_rel == PurePosixPath(".")
                else f"{parent_rel.name}/{svc.name}"
            )
            node = AtlasNode(
                id=nid,
                tier="manipulate",
                subkind="cli",
                label=svc_label,
                source_file=rel,
                line=svc.line,
                cluster="containers",
                summary=f"{origin_txt}. Compose service declaration; container liveness and runtime wiring are not observed.",
            )
            for env_key, env_val, env_line in svc.environment:
                sample = _policy_literal_sample(env_key, env_val, active_tokens)
                if sample is not None:
                    node.status = "policy_in_code"
                    result.findings.append(
                        RawCandidateFinding(
                            rule_code="MANIP-001",
                            node_id=nid,
                            source_file=rel,
                            line=env_line,
                            title=f"Hardcoded policy threshold `{env_key}` ({sample}) in `{rel}`",
                            detail=(
                                f"Compose service `{svc.name}` at `{rel}:{env_line}` hardcodes mutable domain "
                                f"policy threshold `{env_key}={sample}` in container environment config."
                            ),
                            remediation=(
                                "Store mutable domain policy thresholds in PostgreSQL truth (or pass runtime "
                                "secrets/config via `${VAR}` without hardcoded policy literals)."
                            ),
                        )
                    )
            if nid not in seen_node_ids:
                seen_node_ids.add(nid)
                result.nodes.append(node)
            svc_node_map[svc.name] = node

        for svc in parsed_cf.services:
            nid = svc_node_map[svc.name].id
            df_rel, parsed_df, ctx_dir = svc_resolved_df[svc.name]
            if df_rel is not None:
                df_nid = f"m:dockerfile:{df_rel}"
                if df_nid not in seen_node_ids:
                    seen_node_ids.add(df_nid)
                    result.nodes.append(
                        AtlasNode(
                            id=df_nid,
                            tier="manipulate",
                            subkind="cli",
                            label=df_rel,
                            source_file=df_rel,
                            cluster="containers",
                            summary="Container build declaration; image build and runtime execution are not observed.",
                        )
                    )
                eid = f"e:compose:{rel}:{svc.name}->dockerfile:{df_rel}"
                if eid not in seen_edge_ids:
                    seen_edge_ids.add(eid)
                    result.edges.append(
                        AtlasEdge(
                            id=eid,
                            source_id=nid,
                            target_id=df_nid,
                            kind="calls_helper",
                            verification="declared",
                            evidence_path=f"{rel}:{svc.line}",
                            evidence_note=f"Compose service `{svc.name}` builds from `{df_rel}`.",
                        )
                    )

            for dep in svc.depends_on:
                dep_node = svc_node_map.get(dep)
                if dep_node is not None and dep_node.id != nid:
                    eid = f"e:compose:{rel}:{svc.name}->svc:{dep}"
                    if eid not in seen_edge_ids:
                        seen_edge_ids.add(eid)
                        result.edges.append(
                            AtlasEdge(
                                id=eid,
                                source_id=nid,
                                target_id=dep_node.id,
                                kind="calls_helper",
                                verification="declared",
                                evidence_path=f"{rel}:{svc.line}",
                                evidence_note=f"Compose service `{svc.name}` declares `depends_on` `{dep}`.",
                            )
                        )

            eff_stage = _effective_compose_stage(svc, compose_dir, parsed_df, real_root)
            cmd_targets = _extract_compose_command_targets(svc, eff_stage)
            if not cmd_targets:
                continue
            fallback_roots: list[Path] = []
            if ctx_dir is not None:
                fallback_roots.append(ctx_dir)
            if compose_dir not in fallback_roots:
                fallback_roots.append(compose_dir)
            bdir = (repo_root / backend_subdir).resolve() if backend_subdir else real_root
            if _is_within_root(bdir, real_root) and bdir.is_dir() and bdir not in fallback_roots:
                fallback_roots.append(bdir)

            resolved_triples = resolve_command_targets_with_symbols(
                cmd_targets, real_root, eff_stage, fallback_roots, set(by_src)
            )
            for repo_rel, _, syms in resolved_triples:
                tnodes = ensure_repo_target_nodes(
                    repo_rel, real_root, result, by_src, eff_stage, fallback_roots, seen_edge_ids
                )
                for tnode in tnodes:
                    eid = f"e:compose:{rel}:{svc.name}->{tnode.id}"
                    if eid not in seen_edge_ids:
                        seen_edge_ids.add(eid)
                        result.edges.append(
                            AtlasEdge(
                                id=eid,
                                source_id=nid,
                                target_id=tnode.id,
                                kind="calls_helper",
                                verification="declared",
                                evidence_path=f"{rel}:{svc.line}",
                                evidence_note=(
                                    f"Compose service `{svc.name}` command/entrypoint resolves to `{repo_rel}`; "
                                    "container runtime execution is not observed."
                                ),
                                symbol_links=effective_node_symbol_links(tnode.id, syms, result),
                            )
                        )

    if file_count:
        backing_txt = ", ".join(backing_stores) if backing_stores else "none"
        ext_txt = ", ".join(unresolved_external) if unresolved_external else "none"
        result.notes.append(
            f"Compose source coverage: {file_count} file(s), {len(all_svc_labels)} service(s) "
            f"({', '.join(sorted(set(all_svc_labels)))}), {build_linked} build-linked, "
            f"backing DB/Redis container(s): {backing_txt}, "
            f"unresolved external image(s): {ext_txt}. "
            "Runtime container liveness, env_file contents, and external registries are not observed."
        )


def augment_container_sources(
    repo_root: Path,
    backend_subdir: str,
    result: ManipulatorExtractionResult,
) -> None:
    """Run static Dockerfile + Compose + Kubernetes source lineage augmentation in order."""
    from app.adapters.k8s_sources import augment_k8s_sources

    dockerfiles = augment_dockerfile_sources(repo_root, backend_subdir, result)
    augment_compose_sources(repo_root, backend_subdir, result, dockerfiles=dockerfiles)
    augment_k8s_sources(repo_root, backend_subdir, result, dockerfiles=dockerfiles)
