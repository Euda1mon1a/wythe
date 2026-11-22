"""Static Kubernetes workload and ConfigMap lineage adapter.

Parses Kubernetes YAML manifests (`Deployment`, `StatefulSet`, `DaemonSet`, `Job`,
`CronJob`, `Pod`, `ConfigMap`, plus `kind: List` wrappers) at the repository root and
Kubernetes directories (`k8s/`, `kubernetes/`, `manifests/`, `deploy/`, `deployments/`,
`.k8s/`, `charts/`, `helm/`) via `yaml.safe_load_all` without invoking `kubectl`,
`helm`, or cluster APIs. Unrendered Helm/Mustache `{{` templates are safely skipped
before YAML parsing and recorded in scan coverage notes.
"""

from __future__ import annotations

import copy
import os
import re
from dataclasses import dataclass
from pathlib import Path, PurePosixPath

import yaml

from app.adapters.base import ManipulatorExtractionResult, RawCandidateFinding
from app.adapters.compose_sources import (
    classify_backing_image,
    discover_compose_files,
    parse_compose_file,
    policy_literal_sample,
)
from app.adapters.dockerfile_sources import (
    CommandTarget,
    DockerStage,
    ParsedDockerfile,
    _exec_invokes_shell,
    _has_safe_path_segments,
    _is_within_root,
    _load_bounded_yaml_all,
    _norm_container_path,
    _read_bounded_regular_text,
    _safe_contained_dir,
    _safe_contained_file,
    _safe_is_dir,
    _safe_is_file,
    _safe_is_symlink,
    _safe_resolve,
    effective_node_symbol_links,
    ensure_repo_target_nodes,
    extract_command_targets_from_argv,
    extract_command_targets_from_shell,
    index_nodes_by_source,
    is_compose_filename,
    resolve_command_targets_with_symbols,
)
from app.adapters.service_sources import EXCLUDED_PARTS
from app.core.policy_context import get_active_policy_tokens
from app.schemas.atlas import AtlasEdge, AtlasNode

K8S_DIR_NAMES = frozenset(
    {"k8s", "kubernetes", "manifests", "deploy", "deployments", ".k8s", "helm", "charts"}
)
WORKLOAD_KINDS = frozenset({"Deployment", "StatefulSet", "DaemonSet", "Job", "CronJob", "Pod"})
CONFIG_KINDS = frozenset({"ConfigMap"})
SUPPORTED_K8S_KINDS = WORKLOAD_KINDS | CONFIG_KINDS
MAX_TOTAL_K8S_ENV_ENTRIES = 4096
MAX_TOTAL_K8S_CONTAINERS = 1024
MAX_TOTAL_K8S_RESOURCES = 1024

_YAML_SUFFIXES = (".yaml", ".yml")
_API_VERSION_RE = re.compile(r"(?m)^\s*apiVersion\s*:")
_KIND_RE = re.compile(r"(?m)^\s*kind\s*:")
_DOC_SEP_RE = re.compile(r"^---(?:\s+#.*|\s*)$")
_KIND_LINE_RE = re.compile(r"^\s*kind\s*:\s*['\"]?(?P<kind>[A-Za-z0-9_.-]+)['\"]?\s*(?:#.*)?$")
_NAME_LINE_RE = re.compile(r"^\s*name\s*:\s*['\"]?(?P<name>[A-Za-z0-9_.-]+)['\"]?\s*(?:#.*)?$")
_ENV_NAME_LINE_RE = re.compile(
    r"^\s*-\s*name\s*:\s*['\"]?(?P<key>[A-Za-z_][A-Za-z0-9_.-]*)['\"]?\s*(?:#.*)?$"
)
_KV_KEY_LINE_RE = re.compile(r"^\s*(?P<key>[A-Za-z_][A-Za-z0-9_.-]*)\s*:")
_K8S_VALID_INTERP_RE = re.compile(r"\$\$|\$\([A-Za-z_][A-Za-z0-9_.]*\)")
_K8S_PAREN_REF_RE = re.compile(r"\$\(([A-Za-z_][A-Za-z0-9_]*)\)")
_BARE_SHELL_VAR_RE = re.compile(r"\$(?:[A-Za-z_][A-Za-z0-9_]*|\{[^}]*\})")
_EXTERNAL_INFRA_LEAVES = frozenset(
    {
        "alpine",
        "busybox",
        "caddy",
        "consul",
        "coredns",
        "curl",
        "envoy",
        "etcd",
        "fluent-bit",
        "fluentd",
        "grafana",
        "haproxy",
        "istio-proxy",
        "jaeger",
        "kafka",
        "keycloak",
        "memcached",
        "minio",
        "nats",
        "nginx",
        "opensearch",
        "otel-collector",
        "pause",
        "prometheus",
        "promtail",
        "rabbitmq",
        "traefik",
        "vault",
        "vector",
        "zookeeper",
    }
)


@dataclass(frozen=True)
class K8sEnvEntry:
    name: str
    value: object = None
    has_value_from: bool = False
    configmap_ref: str | None = None
    line: int = 1


@dataclass(frozen=True)
class K8sContainerSpec:
    name: str
    is_init: bool = False
    image: str | None = None
    command: tuple[str, ...] | None = None
    args: tuple[str, ...] | None = None
    working_dir: str | None = None
    env: tuple[K8sEnvEntry, ...] = ()
    env_from_configmaps: tuple[str, ...] = ()


@dataclass(frozen=True)
class K8sResourceSpec:
    kind: str
    name: str
    namespace: str | None
    rel_path: str
    line: int
    containers: tuple[K8sContainerSpec, ...] = ()
    volume_configmaps: tuple[str, ...] = ()
    config_data: tuple[tuple[str, object, int], ...] = ()


@dataclass(frozen=True)
class ParsedK8sFile:
    rel_path: str
    resources: tuple[K8sResourceSpec, ...] = ()
    skipped_template: bool = False
    parse_error: str | None = None


def discover_k8s_files(
    repo_root: Path,
    *,
    skipped_notes: list[str] | None = None,
) -> list[tuple[Path, bool]]:
    """Discover candidate YAML files at `repo_root` and inside K8s manifest directories.

    Returns `(path, in_k8s_dir)` pairs sorted by repo-relative POSIX path.
    """
    if not _has_safe_path_segments(repo_root) or _safe_is_symlink(repo_root):
        if skipped_notes is not None:
            skipped_notes.append(
                "Skipped symlink or unsafe repository root; Kubernetes manifest declarations absent."
            )
        return []
    real_root = _safe_resolve(repo_root)
    if real_root is None:
        if skipped_notes is not None:
            skipped_notes.append(
                "Skipped unreadable repository root; Kubernetes manifest declarations absent."
            )
        return []
    found: dict[str, tuple[Path, bool]] = {}

    try:
        root_entries = sorted(repo_root.iterdir())
    except OSError:
        return []

    search_roots: list[Path] = []
    for entry in root_entries:
        if _safe_is_symlink(entry) or not _is_within_root(entry, real_root):
            if skipped_notes is not None and (
                entry.name in K8S_DIR_NAMES
                or (entry.name.lower().endswith(_YAML_SUFFIXES) and not is_compose_filename(entry.name))
            ):
                skipped_notes.append(
                    f"Skipped symlink or out-of-root Kubernetes source {entry.name}; manifest declarations absent."
                )
            continue
        if _safe_is_file(entry):
            if entry.name.lower().endswith(_YAML_SUFFIXES) and not is_compose_filename(entry.name):
                rel = _safe_contained_file(entry, real_root)
                if rel is not None:
                    found[rel] = (entry, False)
        elif entry.name.lower().endswith(_YAML_SUFFIXES) and not is_compose_filename(entry.name):
            if skipped_notes is not None:
                skipped_notes.append(
                    f"Skipped non-regular Kubernetes YAML {entry.name}; manifest declarations absent."
                )
        elif _safe_is_dir(entry) and entry.name not in EXCLUDED_PARTS:
            if entry.name in K8S_DIR_NAMES:
                search_roots.append(entry)
            elif not entry.name.startswith("."):
                try:
                    sub_entries = sorted(entry.iterdir())
                except OSError:
                    continue
                for sub in sub_entries:
                    if sub.name in K8S_DIR_NAMES and (
                        _safe_is_symlink(sub) or not _is_within_root(sub, real_root)
                    ):
                        if skipped_notes is not None:
                            skipped_notes.append(
                                f"Skipped symlink or out-of-root Kubernetes directory {entry.name}/{sub.name}; manifest declarations absent."
                            )
                        continue
                    if sub.name in K8S_DIR_NAMES and _safe_contained_dir(sub, real_root) is not None:
                        search_roots.append(sub)

    walk_errors: list[OSError] = []
    for kroot in search_roots:
        for cur_dir, dirnames, filenames in os.walk(
            kroot, followlinks=False, onerror=walk_errors.append
        ):
            cur_path = Path(cur_dir)
            if _safe_contained_dir(cur_path, real_root) is None:
                dirnames[:] = []
                continue
            keep_dirs: list[str] = []
            for d in sorted(dirnames):
                if (d.startswith(".") and d != ".k8s") or d in EXCLUDED_PARTS:
                    continue
                dpath = cur_path / d
                if _safe_contained_dir(dpath, real_root) is None:
                    if skipped_notes is not None:
                        try:
                            rel_d = dpath.relative_to(repo_root).as_posix()
                        except ValueError:
                            rel_d = d
                        skipped_notes.append(
                            f"Skipped symlink or out-of-root Kubernetes directory {rel_d}; manifest declarations absent."
                        )
                    continue
                keep_dirs.append(d)
            dirnames[:] = keep_dirs
            for fname in sorted(filenames):
                if not fname.lower().endswith(_YAML_SUFFIXES) or is_compose_filename(fname):
                    continue
                cand = cur_path / fname
                rel = _safe_contained_file(cand, real_root)
                if rel is None:
                    if skipped_notes is not None:
                        try:
                            rel_c = cand.relative_to(repo_root).as_posix()
                        except ValueError:
                            rel_c = fname
                        skipped_notes.append(
                            f"Skipped symlink or non-regular Kubernetes YAML {rel_c}; manifest declarations absent."
                        )
                    continue
                found[rel] = (cand, True)

    if walk_errors and skipped_notes is not None:
        skipped_notes.append(
            "Skipped unreadable Kubernetes directory during manifest discovery; manifest declarations absent."
        )

    return [found[k] for k in sorted(found)]


def _locate_k8s_lines(
    text: str,
) -> tuple[dict[tuple[str, str], int], list[tuple[int, dict[str, int]]]]:
    """Best-effort 1-based line lookup for `(kind, metadata.name)` and key lines per YAML doc."""
    res_lines: dict[tuple[str, str], int] = {}
    doc_key_maps: list[tuple[int, dict[str, int]]] = []

    doc_start = 1
    cur_kind: str | None = None
    cur_kind_line = 1
    in_metadata = False
    meta_indent = -1
    cur_keys: dict[str, int] = {}

    for lineno, raw in enumerate(text.splitlines(), start=1):
        if _DOC_SEP_RE.match(raw):
            if cur_keys or lineno > doc_start:
                doc_key_maps.append((doc_start, cur_keys))
            doc_start = lineno + 1
            cur_kind = None
            cur_kind_line = doc_start
            in_metadata = False
            meta_indent = -1
            cur_keys = {}
            continue

        stripped = raw.strip()
        if not stripped or stripped.startswith("#"):
            continue
        indent = len(raw) - len(raw.lstrip(" "))

        km = _KIND_LINE_RE.match(raw)
        if km and indent <= 4:
            cur_kind = km.group("kind")
            cur_kind_line = lineno
            continue

        if re.match(r"^\s*metadata\s*:\s*(?:#.*)?$", raw) and indent <= 4:
            in_metadata = True
            meta_indent = indent
            continue

        if in_metadata:
            if indent <= meta_indent:
                in_metadata = False
            else:
                nm = _NAME_LINE_RE.match(raw)
                if nm and indent == meta_indent + 2 and cur_kind:
                    res_lines.setdefault((cur_kind, nm.group("name")), cur_kind_line)
                continue

        em = _ENV_NAME_LINE_RE.match(raw)
        if em:
            cur_keys.setdefault(em.group("key"), lineno)
            continue
        kvm = _KV_KEY_LINE_RE.match(raw)
        if kvm:
            cur_keys.setdefault(kvm.group("key"), lineno)

    doc_key_maps.append((doc_start, cur_keys))
    return res_lines, doc_key_maps


def _normalize_argv_list(
    raw: object,
    budget: list[int] | None = None,
) -> tuple[str, ...] | None:
    if raw is None:
        return None
    if isinstance(raw, str):
        return (raw,)
    if isinstance(raw, list):
        out: list[str] = []
        for x in raw:
            if budget is not None:
                if budget[0] <= 0:
                    budget[3] = 1
                    break
                budget[0] -= 1
            elif len(out) >= MAX_TOTAL_K8S_ENV_ENTRIES:
                break
            if isinstance(x, (str, int, float)) and not isinstance(x, bool):
                out.append(str(x))
        return tuple(out)
    return None


def _extract_pod_spec(kind: str, doc: dict[str, object]) -> dict[str, object] | None:
    spec = doc.get("spec")
    if not isinstance(spec, dict):
        return None
    if kind == "Pod":
        return spec
    if kind == "CronJob":
        jt = spec.get("jobTemplate")
        if isinstance(jt, dict):
            j_spec = jt.get("spec")
            if isinstance(j_spec, dict):
                tmpl = j_spec.get("template")
                if isinstance(tmpl, dict) and isinstance(tmpl.get("spec"), dict):
                    return tmpl["spec"]
    tmpl = spec.get("template")
    if isinstance(tmpl, dict) and isinstance(tmpl.get("spec"), dict):
        return tmpl["spec"]
    return None


def _parse_containers(
    raw_list: object,
    is_init: bool,
    key_lines: dict[str, int],
    fallback_line: int,
    budget: list[int] | None = None,
) -> list[K8sContainerSpec]:
    if not isinstance(raw_list, list):
        return []
    b = budget if budget is not None else [MAX_TOTAL_K8S_ENV_ENTRIES, MAX_TOTAL_K8S_CONTAINERS, MAX_TOTAL_K8S_RESOURCES, 0]
    specs: list[K8sContainerSpec] = []
    for idx, item in enumerate(raw_list):
        if b[1] <= 0 or b[0] <= 0:
            b[3] = 1
            break
        b[1] -= 1
        b[0] -= 1
        if not isinstance(item, dict):
            continue
        cname_raw = item.get("name")
        cname = cname_raw.strip() if isinstance(cname_raw, str) and cname_raw.strip() else f"container-{idx}"
        img_raw = item.get("image")
        image = img_raw.strip() if isinstance(img_raw, str) and img_raw.strip() else None
        wd_raw = item.get("workingDir")
        wdir = wd_raw.strip() if isinstance(wd_raw, str) and wd_raw.strip() else None

        env_entries: list[K8sEnvEntry] = []
        raw_env = item.get("env")
        if isinstance(raw_env, list):
            for eitem in raw_env:
                if b[0] <= 0:
                    b[3] = 1
                    break
                b[0] -= 1
                if not isinstance(eitem, dict):
                    continue
                ename = eitem.get("name")
                if not isinstance(ename, str) or not ename.strip():
                    continue
                ename_clean = ename.strip()
                vf = eitem.get("valueFrom")
                has_vf = isinstance(vf, dict) and bool(vf)
                cm_ref: str | None = None
                if isinstance(vf, dict):
                    cmk = vf.get("configMapKeyRef")
                    if isinstance(cmk, dict) and isinstance(cmk.get("name"), str) and cmk["name"].strip():
                        cm_ref = cmk["name"].strip()
                env_entries.append(
                    K8sEnvEntry(
                        name=ename_clean,
                        value=eitem.get("value"),
                        has_value_from=has_vf and "value" not in eitem,
                        configmap_ref=cm_ref,
                        line=key_lines.get(ename_clean, fallback_line),
                    )
                )

        env_from_cms: list[str] = []
        raw_ef = item.get("envFrom")
        if isinstance(raw_ef, list):
            for ef in raw_ef:
                if b[0] <= 0:
                    b[3] = 1
                    break
                b[0] -= 1
                if isinstance(ef, dict):
                    cmr = ef.get("configMapRef")
                    if isinstance(cmr, dict) and isinstance(cmr.get("name"), str) and cmr["name"].strip():
                        env_from_cms.append(cmr["name"].strip())

        specs.append(
            K8sContainerSpec(
                name=cname,
                is_init=is_init,
                image=image,
                command=_normalize_argv_list(item.get("command"), b),
                args=_normalize_argv_list(item.get("args"), b),
                working_dir=wdir,
                env=tuple(env_entries),
                env_from_configmaps=tuple(env_from_cms),
            )
        )
    return specs


def _extract_resource_spec(
    doc: dict[str, object],
    rel_path: str,
    res_lines: dict[tuple[str, str], int],
    key_lines: dict[str, int],
    default_line: int,
    budget: list[int] | None = None,
) -> K8sResourceSpec | None:
    b = budget if budget is not None else [MAX_TOTAL_K8S_ENV_ENTRIES, MAX_TOTAL_K8S_CONTAINERS, MAX_TOTAL_K8S_RESOURCES, 0]
    if b[2] <= 0 or b[0] <= 0:
        b[3] = 1
        return None
    kind = doc.get("kind")
    if not isinstance(kind, str) or kind not in SUPPORTED_K8S_KINDS:
        return None
    if not isinstance(doc.get("apiVersion"), str):
        return None
    meta = doc.get("metadata")
    if not isinstance(meta, dict):
        return None
    mname = meta.get("name")
    if not isinstance(mname, str) or not mname.strip():
        return None
    b[2] -= 1
    b[0] -= 1
    name_clean = mname.strip()
    ns_raw = meta.get("namespace")
    ns_clean = ns_raw.strip() if isinstance(ns_raw, str) and ns_raw.strip() else None
    rline = res_lines.get((kind, name_clean), default_line)

    if kind == "ConfigMap":
        cdata: list[tuple[str, object, int]] = []
        raw_data = doc.get("data")
        if isinstance(raw_data, dict):
            for k, v in raw_data.items():
                if b[0] <= 0:
                    b[3] = 1
                    break
                b[0] -= 1
                if isinstance(k, str) and k.strip():
                    k_clean = k.strip()
                    cdata.append((k_clean, v, key_lines.get(k_clean, rline)))
        return K8sResourceSpec(
            kind=kind,
            name=name_clean,
            namespace=ns_clean,
            rel_path=rel_path,
            line=rline,
            config_data=tuple(cdata),
        )

    pod_spec = _extract_pod_spec(kind, doc)
    if pod_spec is None:
        return K8sResourceSpec(
            kind=kind, name=name_clean, namespace=ns_clean, rel_path=rel_path, line=rline
        )

    containers = [
        *_parse_containers(pod_spec.get("initContainers"), True, key_lines, rline, b),
        *_parse_containers(pod_spec.get("containers"), False, key_lines, rline, b),
    ]
    vol_cms: list[str] = []
    raw_vols = pod_spec.get("volumes")
    if isinstance(raw_vols, list):
        for vol in raw_vols:
            if b[0] <= 0:
                b[3] = 1
                break
            b[0] -= 1
            if isinstance(vol, dict):
                cmv = vol.get("configMap")
                if isinstance(cmv, dict) and isinstance(cmv.get("name"), str) and cmv["name"].strip():
                    vol_cms.append(cmv["name"].strip())

    return K8sResourceSpec(
        kind=kind,
        name=name_clean,
        namespace=ns_clean,
        rel_path=rel_path,
        line=rline,
        containers=tuple(containers),
        volume_configmaps=tuple(vol_cms),
    )


def parse_k8s_manifests(
    manifest_path: Path,
    repo_root: Path,
    *,
    in_k8s_dir: bool = True,
) -> ParsedK8sFile:
    """Statically parse a candidate YAML file for supported Kubernetes resources."""
    real_root = _safe_resolve(repo_root)
    rel_path = _safe_contained_file(manifest_path, real_root) if real_root is not None else None
    if rel_path is None:
        try:
            safe_rel = manifest_path.relative_to(repo_root).as_posix()
        except ValueError:
            safe_rel = manifest_path.name
        return ParsedK8sFile(
            rel_path=safe_rel,
            parse_error=f"Skipped symlink or non-regular Kubernetes YAML {safe_rel}; manifest declarations absent.",
        )
    try:
        text = _read_bounded_regular_text(
            manifest_path, max_bytes=1_048_576, real_root=real_root
        )
    except (OSError, UnicodeError, ValueError):
        if in_k8s_dir:
            return ParsedK8sFile(
                rel_path=rel_path,
                parse_error=f"Could not read Kubernetes YAML {rel_path}; manifest declarations absent.",
            )
        return ParsedK8sFile(rel_path=rel_path)

    looks_like_k8s = bool(_API_VERSION_RE.search(text) and _KIND_RE.search(text))
    if "{{" in text:
        if in_k8s_dir or looks_like_k8s:
            return ParsedK8sFile(rel_path=rel_path, skipped_template=True)
        return ParsedK8sFile(rel_path=rel_path)

    if not looks_like_k8s:
        return ParsedK8sFile(rel_path=rel_path)

    try:
        raw_docs = _load_bounded_yaml_all(text, max_nodes=4096, max_depth=64)
    except (yaml.YAMLError, RecursionError, ValueError):
        return ParsedK8sFile(
            rel_path=rel_path,
            parse_error=f"Could not parse Kubernetes YAML {rel_path}; manifest declarations absent.",
        )

    res_lines, doc_key_maps = _locate_k8s_lines(text)
    resources: list[K8sResourceSpec] = []
    budget = [MAX_TOTAL_K8S_ENV_ENTRIES, MAX_TOTAL_K8S_CONTAINERS, MAX_TOTAL_K8S_RESOURCES, 0]
    for doc_idx, raw_doc in enumerate(raw_docs):
        if budget[3]:
            break
        if not isinstance(raw_doc, dict):
            continue
        default_line, key_lines = (
            doc_key_maps[doc_idx]
            if doc_idx < len(doc_key_maps)
            else (doc_key_maps[-1] if doc_key_maps else (1, {}))
        )
        if raw_doc.get("kind") == "List" and isinstance(raw_doc.get("items"), list):
            for item in raw_doc["items"]:
                if budget[2] <= 0 or budget[0] <= 0:
                    budget[3] = 1
                    break
                if isinstance(item, dict):
                    rspec = _extract_resource_spec(
                        item, rel_path, res_lines, key_lines, default_line, budget
                    )
                    if rspec is not None:
                        resources.append(rspec)
                if budget[3]:
                    break
        else:
            rspec = _extract_resource_spec(
                raw_doc, rel_path, res_lines, key_lines, default_line, budget
            )
            if rspec is not None:
                resources.append(rspec)

    trunc_err = (
        f"Truncated Kubernetes YAML {rel_path} after exceeding entry budget ({MAX_TOTAL_K8S_ENV_ENTRIES}); manifest declarations partial."
        if budget[3]
        else None
    )
    return ParsedK8sFile(rel_path=rel_path, resources=tuple(resources), parse_error=trunc_err)


def _normalize_image_repo(image: str | None) -> tuple[str | None, str | None]:
    """Return `(repo_without_tag_or_digest, leaf_name)` in lowercase, or `(None, None)`."""
    if not image or not isinstance(image, str):
        return None, None
    ref = image.strip().split("@", 1)[0]
    last_slash = ref.rfind("/")
    colon_idx = ref.rfind(":")
    if colon_idx > last_slash:
        ref = ref[:colon_idx]
    norm = ref.strip().lower()
    if not norm:
        return None, None
    leaf = norm.rsplit("/", 1)[-1]
    return norm, leaf


def _build_compose_dockerfile_bridge(
    repo_root: Path,
    real_root: Path,
) -> tuple[dict[str, str], dict[str, str]]:
    """Map compose build `image_repo -> df_rel` and `service_name -> df_rel`."""
    image_to_df: dict[str, str] = {}
    svc_to_df: dict[str, str] = {}
    for cpath in discover_compose_files(repo_root):
        parsed_cf, _ = parse_compose_file(cpath, repo_root)
        if parsed_cf is None:
            continue
        cdir = _safe_resolve(cpath.parent) or real_root
        for svc in parsed_cf.services:
            if svc.build_context is None:
                continue
            ctx_dir = (
                _safe_contained_dir(cdir / svc.build_context, real_root)
                if _has_safe_path_segments(svc.build_context)
                else None
            )
            if ctx_dir is None:
                continue
            df_name = svc.build_dockerfile or "Dockerfile"
            if not _has_safe_path_segments(df_name):
                continue
            df_cand = ctx_dir / df_name
            df_rel = _safe_contained_file(df_cand, real_root)
            if df_rel is None:
                df_cand = cdir / df_name
                df_rel = _safe_contained_file(df_cand, real_root)
            if df_rel is None:
                continue
            svc_to_df.setdefault(svc.name.lower(), df_rel)
            img_repo, _ = _normalize_image_repo(svc.image)
            if img_repo:
                image_to_df.setdefault(img_repo, df_rel)
    return image_to_df, svc_to_df


def _dockerfile_stem_tokens(df_rel: str) -> set[str]:
    p = PurePosixPath(df_rel)
    name = p.name
    lower_name = name.lower()
    tokens: set[str] = set()
    for pfx in ("dockerfile.", "containerfile."):
        if lower_name.startswith(pfx):
            tokens.update(t for t in re.split(r"[^a-z0-9]+", lower_name[len(pfx) :]) if len(t) >= 2)
    for sfx in (".dockerfile", ".containerfile"):
        if lower_name.endswith(sfx):
            tokens.update(t for t in re.split(r"[^a-z0-9]+", lower_name[: -len(sfx)]) if len(t) >= 2)
    for part in p.parts[:-1]:
        if part not in (".", ".docker"):
            tokens.update(t for t in re.split(r"[^a-z0-9]+", part.lower()) if len(t) >= 2)
    return tokens


def _match_dockerfile_for_container(
    cont: K8sContainerSpec,
    workload_name: str,
    df_cache: dict[str, ParsedDockerfile],
    compose_img_to_df: dict[str, str],
    compose_svc_to_df: dict[str, str],
) -> tuple[str | None, ParsedDockerfile | None]:
    if not df_cache:
        return None, None
    img_repo, img_leaf = _normalize_image_repo(cont.image)
    if img_repo and img_repo in compose_img_to_df:
        df_rel = compose_img_to_df[img_repo]
        return df_rel, df_cache.get(df_rel)

    if classify_backing_image(cont.image) is not None or (
        img_leaf is not None and img_leaf in _EXTERNAL_INFRA_LEAVES
    ):
        return None, None

    for key_cand in (img_leaf, cont.name.lower(), workload_name.lower()):
        if key_cand and key_cand in compose_svc_to_df:
            df_rel = compose_svc_to_df[key_cand]
            return df_rel, df_cache.get(df_rel)

    probe_tokens: set[str] = set()
    for raw_hint in (img_leaf or "", cont.name, workload_name):
        probe_tokens.update(t for t in re.split(r"[^a-z0-9]+", raw_hint.lower()) if len(t) >= 2)

    scored: list[tuple[int, str]] = []
    for df_rel in sorted(df_cache):
        stems = _dockerfile_stem_tokens(df_rel)
        overlap = len(stems & probe_tokens)
        if overlap > 0:
            scored.append((overlap, df_rel))
    if scored:
        scored.sort(key=lambda pair: (-pair[0], pair[1]))
        best_rel = scored[0][1]
        return best_rel, df_cache.get(best_rel)

    if len(df_cache) == 1 and not cont.is_init and cont.image:
        sole_rel = next(iter(df_cache))
        return sole_rel, df_cache[sole_rel]

    return None, None


def _has_unexpanded_k8s_token(tok: str) -> bool:
    cleaned = _K8S_VALID_INTERP_RE.sub("", tok)
    return bool(_BARE_SHELL_VAR_RE.search(cleaned) or tok == "~" or tok.startswith("~/"))


def _check_k8s_container_command(
    cont: K8sContainerSpec,
    stage: DockerStage | None,
    nid: str,
    res: K8sResourceSpec,
    findings: list[RawCandidateFinding],
) -> None:
    if cont.command is not None:
        if len(cont.command) == 0 or not cont.command[0].strip():
            findings.append(
                RawCandidateFinding(
                    rule_code="MANIP-004",
                    node_id=nid,
                    source_file=res.rel_path,
                    line=res.line,
                    title=f"Empty executable in Kubernetes `{res.kind}` `{res.name}` (`{cont.name}`)",
                    detail=(
                        f"Container `{cont.name}` in `{res.rel_path}:{res.line}` declares an empty "
                        "`command` array or blank executable."
                    ),
                    remediation="Specify a non-empty executable in `command` or omit `command` to use image `ENTRYPOINT`.",
                )
            )
            return

        bad_tokens: list[str] = []
        first = cont.command[0]
        if _has_unexpanded_k8s_token(first):
            bad_tokens.append(first)
        elif not _exec_invokes_shell(list(cont.command)):
            for tok in (*cont.command[1:], *(cont.args or ())):
                if _has_unexpanded_k8s_token(tok):
                    bad_tokens.append(tok)
        if bad_tokens:
            sample = ", ".join(f"`{t}`" for t in bad_tokens[:3])
            findings.append(
                RawCandidateFinding(
                    rule_code="MANIP-004",
                    node_id=nid,
                    source_file=res.rel_path,
                    line=res.line,
                    title=f"Kubernetes exec `command`/`args` uses shell syntax ({sample}) without a shell",
                    detail=(
                        f"Container `{cont.name}` in `{res.kind}` `{res.name}` (`{res.rel_path}:{res.line}`) "
                        f"passes {sample} in exec-array `command`/`args`; Kubernetes expands `$(VAR_NAME)`, "
                        "not bare `$VAR`, `${VAR}`, or `~`, unless a shell (`sh -c`) is invoked."
                    ),
                    remediation=(
                        "Use Kubernetes `$(VAR_NAME)` parenthesized env references, or invoke "
                        '`["sh", "-c", "..."]` when shell expansion is intended.'
                    ),
                )
            )
        return

    if cont.args:
        df_ep_shell = (
            stage is not None
            and stage.entrypoint is not None
            and (not stage.entrypoint.is_exec or _exec_invokes_shell(list(stage.entrypoint.argv)))
        )
        if not df_ep_shell:
            bad_args = [tok for tok in cont.args if _has_unexpanded_k8s_token(tok)]
            if bad_args:
                sample = ", ".join(f"`{t}`" for t in bad_args[:3])
                findings.append(
                    RawCandidateFinding(
                        rule_code="MANIP-004",
                        node_id=nid,
                        source_file=res.rel_path,
                        line=res.line,
                        title=f"Kubernetes `args` uses unexpanded shell token ({sample}) without a shell",
                        detail=(
                            f"Container `{cont.name}` in `{res.kind}` `{res.name}` (`{res.rel_path}:{res.line}`) "
                            f"passes {sample} in `args` without a shell entrypoint; Kubernetes only expands `$(VAR_NAME)`."
                        ),
                        remediation="Replace `$VAR`/`${VAR}` with `$(VAR_NAME)` or invoke `sh -c` explicitly.",
                    )
                )


def _check_configmap_policy(
    res: K8sResourceSpec,
    node: AtlasNode,
    active_tokens: tuple[str, ...],
    findings: list[RawCandidateFinding],
) -> None:
    for dkey, dval, dline in res.config_data:
        sample = policy_literal_sample(dkey, dval, active_tokens)
        if sample is not None:
            node.status = "policy_in_code"
            findings.append(
                RawCandidateFinding(
                    rule_code="MANIP-001",
                    node_id=node.id,
                    source_file=res.rel_path,
                    line=dline,
                    title=f"Hardcoded policy threshold `{dkey}` ({sample}) in ConfigMap `{res.name}`",
                    detail=(
                        f"Kubernetes ConfigMap `{res.name}` at `{res.rel_path}:{dline}` hardcodes mutable "
                        f"domain policy threshold `{dkey}={sample}` in `data`."
                    ),
                    remediation="Move mutable domain policy thresholds into PostgreSQL truth instead of static ConfigMaps.",
                )
            )
            continue
        if isinstance(dval, str) and "\n" in dval:
            for raw_ln in dval.splitlines():
                s = raw_ln.strip()
                if not s or s.startswith("#") or "=" not in s:
                    continue
                sub_k, sub_v = s.split("=", 1)
                sub_sample = policy_literal_sample(sub_k.strip(), sub_v.strip(), active_tokens)
                if sub_sample is not None:
                    node.status = "policy_in_code"
                    findings.append(
                        RawCandidateFinding(
                            rule_code="MANIP-001",
                            node_id=node.id,
                            source_file=res.rel_path,
                            line=dline,
                            title=f"Hardcoded policy threshold `{sub_k.strip()}` ({sub_sample}) in ConfigMap `{res.name}`",
                            detail=(
                                f"Kubernetes ConfigMap `{res.name}` key `{dkey}` (`{res.rel_path}:{dline}`) "
                                f"embeds mutable policy threshold `{sub_k.strip()}={sub_sample}`."
                            ),
                            remediation="Move mutable domain policy thresholds into PostgreSQL truth.",
                        )
                    )


def _effective_k8s_stage(
    cont: K8sContainerSpec,
    parsed_df: ParsedDockerfile | None,
    fallback_line: int,
) -> DockerStage | None:
    base_stage = parsed_df.select_stage() if parsed_df is not None else None
    if base_stage is None and not cont.working_dir and not cont.env:
        return None
    eff = (
        copy.deepcopy(base_stage)
        if base_stage is not None
        else DockerStage(index=0, name=None, base_image=cont.image or "scratch", line=fallback_line)
    )
    if cont.working_dir:
        eff.workdir = _norm_container_path(cont.working_dir, eff.workdir)
    for eentry in cont.env:
        if not eentry.has_value_from and isinstance(eentry.value, (str, int, float)) and not isinstance(eentry.value, bool):
            eff.env[eentry.name] = _K8S_PAREN_REF_RE.sub(r"${\1}", str(eentry.value))
    return eff


def _extract_k8s_command_targets(
    cont: K8sContainerSpec,
    stage: DockerStage | None,
) -> list[CommandTarget]:
    env = stage.env if stage is not None else {}
    wdir = stage.workdir if stage is not None else (cont.working_dir or "/")
    cmd_norm = [_K8S_PAREN_REF_RE.sub(r"${\1}", t) for t in cont.command] if cont.command else []
    args_norm = [_K8S_PAREN_REF_RE.sub(r"${\1}", t) for t in cont.args] if cont.args else []

    targets: list[CommandTarget] = []
    if cmd_norm and args_norm:
        targets.extend(extract_command_targets_from_argv([*cmd_norm, *args_norm], env, wdir))
    if cmd_norm:
        targets.extend(extract_command_targets_from_argv(cmd_norm, env, wdir))
        if len(cmd_norm) == 1 and " " in cmd_norm[0]:
            targets.extend(extract_command_targets_from_shell(cmd_norm[0], env, wdir))
    if args_norm:
        if not cmd_norm and stage is not None and stage.entrypoint is not None and stage.entrypoint.is_exec:
            targets.extend(
                extract_command_targets_from_argv([*stage.entrypoint.argv, *args_norm], env, wdir)
            )
        targets.extend(extract_command_targets_from_argv(args_norm, env, wdir))
    return list(dict.fromkeys(targets))


def augment_k8s_sources(
    repo_root: Path,
    backend_subdir: str,
    result: ManipulatorExtractionResult,
    dockerfiles: dict[str, object] | None = None,
) -> None:
    """Discover Kubernetes manifests, emit `m:k8s:*` nodes/edges, and flag K8s drift/policy findings."""
    skipped_notes: list[str] = []
    candidates = discover_k8s_files(repo_root, skipped_notes=skipped_notes)
    if skipped_notes:
        object.__setattr__(result, "coverage_complete", False)
        for sn in skipped_notes:
            if sn not in result.notes:
                result.notes.append(sn)
    if not candidates:
        return

    parsed_files: list[ParsedK8sFile] = []
    skipped_templates: list[str] = []
    for mpath, in_k8s_dir in candidates:
        pf = parse_k8s_manifests(mpath, repo_root, in_k8s_dir=in_k8s_dir)
        if pf.parse_error:
            result.notes.append(pf.parse_error)
            object.__setattr__(result, "coverage_complete", False)
        if pf.skipped_template:
            skipped_templates.append(pf.rel_path)
            continue
        if pf.resources:
            parsed_files.append(pf)

    if not parsed_files and not skipped_templates:
        return

    real_root = _safe_resolve(repo_root)
    if real_root is None:
        object.__setattr__(result, "coverage_complete", False)
        return
    df_cache: dict[str, ParsedDockerfile] = {
        k: v for k, v in (dockerfiles or {}).items() if isinstance(v, ParsedDockerfile)
    }
    compose_img_to_df, compose_svc_to_df = (
        _build_compose_dockerfile_bridge(repo_root, real_root) if df_cache else ({}, {})
    )
    by_src = index_nodes_by_source(result)
    seen_node_ids = {n.id for n in result.nodes}
    seen_edge_ids = {e.id for e in result.edges}
    active_tokens = get_active_policy_tokens()

    cm_by_ns: dict[tuple[str | None, str], AtlasNode] = {}
    cm_by_name: dict[str, AtlasNode] = {}
    workload_records: list[
        tuple[K8sResourceSpec, AtlasNode, list[tuple[K8sContainerSpec, str | None, ParsedDockerfile | None]]]
    ] = []

    workload_count = 0
    configmap_count = 0
    df_linked_count = 0
    entrypoint_linked_count = 0
    backing_stores: list[str] = []

    for pf in parsed_files:
        for res in pf.resources:
            kind_l = res.kind.lower()
            nid = f"m:k8s:{res.rel_path}:{kind_l}:{res.name}"
            if res.kind == "ConfigMap":
                configmap_count += 1
                node = AtlasNode(
                    id=nid,
                    tier="manipulate",
                    subkind="cli",
                    label=f"configmap/{res.name}",
                    source_file=res.rel_path,
                    line=res.line,
                    cluster="containers",
                    summary=(
                        f"Kubernetes ConfigMap `{res.name}` ({len(res.config_data)} key(s)). "
                        "Static manifest declaration; cluster state and live pod mounts are not observed."
                    ),
                )
                _check_configmap_policy(res, node, active_tokens, result.findings)
                if nid not in seen_node_ids:
                    seen_node_ids.add(nid)
                    result.nodes.append(node)
                cm_by_ns[(res.namespace, res.name)] = node
                cm_by_name.setdefault(res.name, node)
                continue

            workload_count += 1
            cont_matches: list[tuple[K8sContainerSpec, str | None, ParsedDockerfile | None]] = []
            summary_parts: list[str] = []
            for cont in res.containers:
                df_rel, parsed_df = _match_dockerfile_for_container(
                    cont, res.name, df_cache, compose_img_to_df, compose_svc_to_df
                )
                cont_matches.append((cont, df_rel, parsed_df))
                bkind = classify_backing_image(cont.image)
                if df_rel is not None:
                    summary_parts.append(f"`{cont.name}` -> `{df_rel}`")
                elif bkind is not None:
                    backing_stores.append(f"{res.name}/{cont.name} [{bkind}]")
                    summary_parts.append(f"backing `{bkind}` (`{cont.image}`)")
                elif cont.image:
                    summary_parts.append(f"image `{cont.image}`")

            origin_desc = ", ".join(dict.fromkeys(summary_parts)) if summary_parts else "pod template"
            node = AtlasNode(
                id=nid,
                tier="manipulate",
                subkind="cli",
                label=f"{kind_l}/{res.name}",
                source_file=res.rel_path,
                line=res.line,
                cluster="containers",
                summary=(
                    f"Kubernetes {res.kind} ({origin_desc}). "
                    "Static workload declaration; cluster admission, secret values, and pod liveness are not observed."
                ),
            )

            for cont, _, parsed_df in cont_matches:
                eff_stage = _effective_k8s_stage(cont, parsed_df, res.line)
                _check_k8s_container_command(cont, eff_stage, nid, res, result.findings)
                for eentry in cont.env:
                    if eentry.has_value_from:
                        continue
                    sample = policy_literal_sample(eentry.name, eentry.value, active_tokens)
                    if sample is not None:
                        node.status = "policy_in_code"
                        result.findings.append(
                            RawCandidateFinding(
                                rule_code="MANIP-001",
                                node_id=nid,
                                source_file=res.rel_path,
                                line=eentry.line,
                                title=(
                                    f"Hardcoded policy threshold `{eentry.name}` ({sample}) "
                                    f"in Kubernetes {res.kind} `{res.name}`"
                                ),
                                detail=(
                                    f"Container `{cont.name}` in `{res.kind}` `{res.name}` "
                                    f"(`{res.rel_path}:{eentry.line}`) hardcodes mutable domain policy "
                                    f"threshold `{eentry.name}={sample}` in `env`."
                                ),
                                remediation=(
                                    "Store mutable domain policy thresholds in PostgreSQL truth (or inject "
                                    "non-policy runtime secrets via `valueFrom`)."
                                ),
                            )
                        )

            if nid not in seen_node_ids:
                seen_node_ids.add(nid)
                result.nodes.append(node)
            workload_records.append((res, node, cont_matches))

    bdir = (
        _safe_contained_dir(repo_root / backend_subdir, real_root)
        if backend_subdir
        else real_root
    )
    has_bdir = bdir is not None

    for res, wnode, cont_matches in workload_records:
        kind_l = res.kind.lower()
        nid = wnode.id
        referenced_cms: set[str] = set(res.volume_configmaps)
        linked_this_workload_df = False
        linked_this_workload_ep = False

        for cont, df_rel, parsed_df in cont_matches:
            referenced_cms.update(cont.env_from_configmaps)
            for eentry in cont.env:
                if eentry.configmap_ref:
                    referenced_cms.add(eentry.configmap_ref)

            if df_rel is not None:
                linked_this_workload_df = True
                df_nid = f"m:dockerfile:{df_rel}"
                eid = f"e:k8s:{res.rel_path}:{kind_l}:{res.name}->dockerfile:{df_rel}"
                if df_nid in seen_node_ids and eid not in seen_edge_ids:
                    seen_edge_ids.add(eid)
                    result.edges.append(
                        AtlasEdge(
                            id=eid,
                            source_id=nid,
                            target_id=df_nid,
                            kind="calls_helper",
                            verification="declared",
                            evidence_path=f"{res.rel_path}:{res.line}",
                            evidence_note=(
                                f"Kubernetes {res.kind} `{res.name}` container `{cont.name}` maps to `{df_rel}`."
                            ),
                        )
                    )

            eff_stage = _effective_k8s_stage(cont, parsed_df, res.line)
            cmd_targets = _extract_k8s_command_targets(cont, eff_stage)
            if not cmd_targets:
                continue
            fallback_roots: list[Path] = []
            if parsed_df is not None and parsed_df.context_root not in fallback_roots:
                fallback_roots.append(parsed_df.context_root)
            if real_root not in fallback_roots:
                fallback_roots.append(real_root)
            if has_bdir and bdir is not None and bdir not in fallback_roots:
                fallback_roots.append(bdir)

            resolved_triples = resolve_command_targets_with_symbols(
                cmd_targets, real_root, eff_stage, fallback_roots, set(by_src)
            )
            for repo_rel, _, syms in resolved_triples:
                tnodes = ensure_repo_target_nodes(
                    repo_rel, real_root, result, by_src, eff_stage, fallback_roots, seen_edge_ids
                )
                for tnode in tnodes:
                    linked_this_workload_ep = True
                    eid = f"e:k8s:{res.rel_path}:{kind_l}:{res.name}->{tnode.id}"
                    if eid not in seen_edge_ids:
                        seen_edge_ids.add(eid)
                        result.edges.append(
                            AtlasEdge(
                                id=eid,
                                source_id=nid,
                                target_id=tnode.id,
                                kind="calls_helper",
                                verification="declared",
                                evidence_path=f"{res.rel_path}:{res.line}",
                                evidence_note=(
                                    f"Kubernetes {res.kind} `{res.name}` (`{cont.name}`) command/args resolves "
                                    f"to `{repo_rel}`; cluster execution is not observed."
                                ),
                                symbol_links=effective_node_symbol_links(tnode.id, syms, result),
                            )
                        )

        if linked_this_workload_df:
            df_linked_count += 1
        if linked_this_workload_ep:
            entrypoint_linked_count += 1

        for cm_name in sorted(referenced_cms):
            cm_node = cm_by_ns.get((res.namespace, cm_name)) or cm_by_name.get(cm_name)
            if cm_node is not None:
                eid = f"e:k8s:{res.rel_path}:{kind_l}:{res.name}->cm:{cm_name}"
                if eid not in seen_edge_ids:
                    seen_edge_ids.add(eid)
                    result.edges.append(
                        AtlasEdge(
                            id=eid,
                            source_id=nid,
                            target_id=cm_node.id,
                            kind="calls_helper",
                            verification="declared",
                            evidence_path=f"{res.rel_path}:{res.line}",
                            evidence_note=(
                                f"Kubernetes {res.kind} `{res.name}` references ConfigMap `{cm_name}`."
                            ),
                        )
                    )

    backing_txt = ", ".join(backing_stores) if backing_stores else "none"
    skip_txt = (
        f", skipped {len(skipped_templates)} unrendered Helm/Mustache `{{{{` template file(s) "
        f"({', '.join(skipped_templates[:5])})"
        if skipped_templates
        else ""
    )
    result.notes.append(
        f"Kubernetes source coverage: {len(parsed_files)} manifest file(s), "
        f"{workload_count} workload(s), {configmap_count} ConfigMap(s), "
        f"{df_linked_count} Dockerfile-linked, {entrypoint_linked_count} entrypoint-linked, "
        f"backing DB/Redis image(s): {backing_txt}{skip_txt}. "
        "Cluster state, Helm/Kustomize rendering, and live Secret values are not observed."
    )
