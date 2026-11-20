"""Static container CLI launcher and host service unit lineage adapter.

Statically inspects `launchd` `.plist` declarations, `systemd` `.service` units,
and POSIX `.sh` scripts for `container run` (`apple/container`), `docker run`,
and `podman run` invocations—as well as direct `systemd`/`launchd` script targets—
without invoking `container`, `docker`, `podman`, `launchctl`, `systemctl`, or shells,
and without following symlinks outside the repository root.
"""

from __future__ import annotations

import copy
import os
import plistlib
import re
import shlex
from dataclasses import dataclass, field
from pathlib import Path, PurePosixPath
from xml.parsers.expat import ExpatError

from app.adapters.base import ManipulatorExtractionResult, RawCandidateFinding
from app.adapters.dockerfile_sources import (
    ALLOWED_CONTAINER_DOT_DIRS,
    CommandTarget,
    DockerIgnoreSpec,
    DockerStage,
    ParsedDockerfile,
    StageCopyMapping,
    _exec_invokes_shell,
    _is_within_root,
    _norm_container_path,
    discover_dockerfiles,
    effective_node_symbol_links,
    ensure_repo_target_nodes,
    extract_command_targets_from_argv,
    extract_command_targets_from_shell,
    extract_stage_command_targets,
    index_nodes_by_source,
    parse_dockerfile,
    resolve_command_targets_with_symbols,
)
from app.adapters.plist_locations import command_locations, env_locations
from app.adapters.service_sources import EXCLUDED_PARTS, source_reference
from app.core.policy_context import get_active_policy_tokens
from app.schemas.atlas import AtlasEdge, AtlasNode

MAX_UNIT_FILE_BYTES = 262_144
MAX_ENV_FILE_BYTES = 131_072

CONTAINER_CLI_BINARIES = frozenset({"container", "docker", "podman"})
_VAR_TOKEN_RE = re.compile(r"\$(?:[A-Za-z_][A-Za-z0-9_]*|\{[^}]*\})")
_TILDE_ARG_RE = re.compile(r"(?:^|[=:])~(?:/|$)")
_SH_ASSIGN_RE = re.compile(r"^(?P<key>[A-Za-z_][A-Za-z0-9_]*)=(?P<val>.*)$")
_CMD_SUB_TOKEN_PREFIX = "__WYTHE_DYN_SUB_"
_CMD_SUB_PLACEHOLDER_RE = re.compile(rf"\$\{{{re.escape(_CMD_SUB_TOKEN_PREFIX)}\d+__\}}")
_SYSTEMD_SIMPLE_BRACE_RE = re.compile(r"\$\{[A-Za-z_][A-Za-z0-9_]*\}")
_SYSTEMD_WHOLE_VAR_RE = re.compile(r"^\$[A-Za-z_][A-Za-z0-9_]*$")
_SHELL_CONTROL_PREFIXES = frozenset({"if", "then", "elif", "else", "while", "until", "do", "!", "time", "{"})

_GLOBAL_BOOL_FLAGS = frozenset(
    {"-D", "--debug", "--tls", "--tlsverify", "-r", "--remote", "--no-out", "--syslog", "--transient-store"}
)
_GLOBAL_VALUE_FLAGS = frozenset(
    {
        "-H",
        "--host",
        "-c",
        "--context",
        "--config",
        "-l",
        "--log-level",
        "--tlscacert",
        "--tlscert",
        "--tlskey",
        "--root",
        "--runroot",
        "--storage-driver",
        "--storage-opt",
        "--cgroup-manager",
        "--conmon",
        "--namespace",
        "--runtime",
        "--runtime-flag",
        "--tmpdir",
        "--events-backend",
        "--hooks-dir",
        "--cdi-spec-dir",
        "--module",
        "--url",
        "--connection",
        "--authfile",
        "--cert-dir",
        "--creds",
        "--decryption-key",
        "--encryption-key",
        "--identity",
        "--imagestore",
        "--network-cmd-path",
        "--network-config-dir",
        "--out",
        "--remote-host",
        "--syslog-facility",
        "--volumepath",
    }
)
_RUN_BOOL_FLAGS = frozenset(
    {
        "-d",
        "--detach",
        "-i",
        "--interactive",
        "-t",
        "--tty",
        "--rm",
        "--remove",
        "--read-only",
        "--init",
        "--privileged",
        "-P",
        "--publish-all",
        "--no-healthcheck",
        "--oom-kill-disable",
        "--sig-proxy",
        "-q",
        "--quiet",
        "--replace",
        "--rmi",
        "--passwd",
        "--http-proxy",
        "--tls-verify",
        "--no-hosts",
        "--no-dns",
        "--virtualization",
        "--rosetta",
        "--ssh",
        "--env-host",
    }
)
_RUN_SHORT_BOOL_CHARS = frozenset({"d", "i", "t", "P", "q"})
_RUN_SHORT_VALUE_CHARS = frozenset({"e", "v", "w", "p", "u", "m", "c", "a", "h", "l", "k"})
_RUN_VALUE_FLAGS = frozenset(
    {
        "-e",
        "--env",
        "--env-file",
        "--mount",
        "-v",
        "--volume",
        "-w",
        "--workdir",
        "--entrypoint",
        "-p",
        "--publish",
        "--publish-socket",
        "--expose",
        "--name",
        "-h",
        "--hostname",
        "--domainname",
        "-u",
        "--user",
        "--uid",
        "--gid",
        "--group-add",
        "--network",
        "--net",
        "--network-alias",
        "--net-alias",
        "--ip",
        "--ip6",
        "--mac-address",
        "--dns",
        "--dns-domain",
        "--dns-search",
        "--dns-option",
        "--dns-opt",
        "--add-host",
        "--link",
        "-c",
        "--cpus",
        "--cpu-shares",
        "--cpu-period",
        "--cpu-quota",
        "--cpu-rt-period",
        "--cpu-rt-runtime",
        "--cpuset-cpus",
        "--cpuset-mems",
        "-m",
        "--memory",
        "--memory-swap",
        "--memory-swappiness",
        "--memory-reservation",
        "--kernel-memory",
        "--pids-limit",
        "--shm-size",
        "--ulimit",
        "--blkio-weight",
        "--device",
        "--device-cgroup-rule",
        "--gpus",
        "--platform",
        "-a",
        "--arch",
        "--attach",
        "--os",
        "-k",
        "--kernel",
        "--scheme",
        "--progress",
        "--cidfile",
        "--pidfile",
        "--conmon-pidfile",
        "-l",
        "--label",
        "--label-file",
        "--annotation",
        "--restart",
        "--pull",
        "--stop-signal",
        "--stop-timeout",
        "--runtime",
        "--security-opt",
        "--cap-add",
        "--cap-drop",
        "--userns",
        "--uidmap",
        "--gidmap",
        "--subuidname",
        "--subgidname",
        "--cgroupns",
        "--cgroup-parent",
        "--ipc",
        "--pid",
        "--uts",
        "--seccomp-policy",
        "--log-driver",
        "--log-opt",
        "--health-cmd",
        "--health-interval",
        "--health-retries",
        "--health-timeout",
        "--health-start-period",
        "--health-start-interval",
        "--health-on-failure",
        "--volumes-from",
        "--tmpfs",
        "--rootfs",
        "--pod",
        "--pod-id-file",
        "--tz",
        "--umask",
        "--sdnotify",
        "--systemd",
        "--secret",
        "--sysctl",
        "--oom-score-adj",
        "--detach-keys",
        "--authfile",
        "--cgroups",
        "--cgroup-conf",
        "--blkio-weight-device",
        "--device-read-bps",
        "--device-write-bps",
        "--device-read-iops",
        "--device-write-iops",
        "--storage-opt",
        "--isolation",
        "--io-maxbandwidth",
        "--io-maxiops",
        "--cpu-count",
        "--cpu-percent",
        "--link-local-ip",
        "--volume-driver",
        "--chrootdirs",
        "--decryption-key",
        "--encryption-key",
        "--exit-policy",
        "--hooks-dir",
        "--hostuser",
        "--image-volume",
        "--infra-conmon-pidfile",
        "--os-version",
        "--os-feature",
        "--variant",
        "--preserve-fds",
        "--preserve-fd",
        "--rdt-class",
        "--requires",
        "--retry",
        "--retry-delay",
        "--shm-size-systemd",
        "--signature-policy",
        "--timeout",
        "--unsetenv",
        "--cert-dir",
        "--creds",
        "--log-level",
        "--runtime-flag",
        "--template",
        "--boot-kernel",
        "--passwd-entry",
        "--personality",
        "--procfs-opts",
        "--rdma-resource",
        "--seccomp-profile",
        "--selinux-opts",
        "--userns-uid-map",
        "--userns-gid-map",
        "--userns-uid-map-user",
        "--userns-gid-map-group",
    }
)
_EXTERNAL_BASE_LEAVES = frozenset(
    {
        "alpine",
        "almalinux",
        "amazonlinux",
        "bun",
        "busybox",
        "caddy",
        "centos",
        "consul",
        "coredns",
        "curl",
        "debian",
        "deno",
        "distroless",
        "eclipse-temurin",
        "envoy",
        "etcd",
        "fedora",
        "fluent-bit",
        "fluentd",
        "golang",
        "grafana",
        "hadolint",
        "haproxy",
        "httpd",
        "istio-proxy",
        "jaeger",
        "kafka",
        "keycloak",
        "memcached",
        "minio",
        "nats",
        "nginx",
        "node",
        "nodejs",
        "ollama",
        "openjdk",
        "opensearch",
        "otel-collector",
        "pause",
        "php",
        "prometheus",
        "promtail",
        "pypy",
        "python",
        "rabbitmq",
        "rockylinux",
        "ruby",
        "rust",
        "syft",
        "traefik",
        "trivy",
        "ubuntu",
        "vault",
        "vector",
        "wolfi-base",
        "zookeeper",
    }
)
_EXTERNAL_REGISTRY_PREFIXES = (
    "docker.io/library/",
    "gcr.io/distroless/",
    "cgr.dev/chainguard/",
    "mcr.microsoft.com/",
    "public.ecr.aws/",
)
_TEMPLATE_ENV_MARKERS = (".example", ".sample", ".template", ".tmpl", ".dist", ".defaults")


@dataclass(frozen=True)
class EnvAssignment:
    key: str
    value: str | None
    line: int


@dataclass(frozen=True)
class MountSpec:
    kind: str  # "bind" | "volume" | "tmpfs"
    source: str | None
    target: str
    readonly: bool
    raw: str


@dataclass(frozen=True)
class ContainerRunInvocation:
    cli: str  # "container" | "docker" | "podman"
    line: int
    image: str | None
    command_argv: tuple[str, ...] = ()
    entrypoint: str | None = None
    workdir: str | None = None
    rm: bool = False
    read_only_rootfs: bool = False
    network: str | None = None
    env: tuple[EnvAssignment, ...] = ()
    env_files: tuple[tuple[str, int], ...] = ()
    mounts: tuple[MountSpec, ...] = ()
    raw_argv: tuple[str, ...] = ()
    unresolved_flag: str | None = None


@dataclass(frozen=True)
class SystemdExecSpec:
    directive: str  # "ExecStart" | "ExecStartPre"
    argv: tuple[str, ...]
    line: int
    raw: str


@dataclass(frozen=True)
class ParsedSystemdUnit:
    rel_path: str
    description: str | None
    line: int
    working_dir: str | None = None
    working_dir_line: int = 1
    environment: tuple[EnvAssignment, ...] = ()
    env_files: tuple[tuple[str, bool, int], ...] = ()
    exec_commands: tuple[SystemdExecSpec, ...] = ()
    empty_exec_lines: tuple[int, ...] = ()


@dataclass(frozen=True)
class ParsedLaunchdUnit:
    rel_path: str
    disabled: bool
    program: str | None
    program_line: int
    program_args: tuple[str, ...]
    arg_lines: tuple[int, ...]
    environment: tuple[EnvAssignment, ...] = ()
    structural_problem: tuple[str, int] | None = field(default=None)


def _parse_mount_flag(spec: str) -> MountSpec | None:
    parts = [p.strip() for p in spec.split(",") if p.strip()]
    if not parts:
        return None
    mtype = "bind"
    source: str | None = None
    target: str | None = None
    readonly = False
    for part in parts:
        if "=" not in part:
            if part.lower() in {"readonly", "ro"}:
                readonly = True
            elif part.lower() == "rw":
                readonly = False
            continue
        k_raw, v_raw = part.split("=", 1)
        k = k_raw.strip().lower()
        v = v_raw.strip()
        if k == "type" and v:
            mtype = v.lower()
        elif k in {"source", "src"}:
            source = v
        elif k in {"target", "dst", "destination"}:
            target = v
        elif k in {"readonly", "ro"}:
            readonly = v.lower() not in {"0", "false", "no"}
    if not target:
        return None
    return MountSpec(kind=mtype, source=source, target=target, readonly=readonly, raw=spec)


def _parse_volume_flag(spec: str) -> MountSpec | None:
    stripped = spec.strip()
    if not stripped:
        return None
    if ":" not in stripped:
        return MountSpec(kind="volume", source=None, target=stripped, readonly=False, raw=spec)
    segs = stripped.split(":")
    src = segs[0].strip()
    tgt = segs[1].strip()
    opts_raw = ":".join(segs[2:]).strip() if len(segs) >= 3 else ""
    if not tgt:
        return None
    opts = {o.strip().lower() for o in opts_raw.split(",") if o.strip()}
    readonly = bool(opts & {"ro", "readonly"})
    is_host_path = bool(
        src.startswith((".", "/", "~", "$")) or "/" in src or "\\" in src
    )
    kind = "bind" if is_host_path else "volume"
    return MountSpec(kind=kind, source=src or None, target=tgt, readonly=readonly, raw=spec)


def _unwrap_host_prefix(tokens: list[str]) -> list[str]:
    cur = list(tokens)
    for _ in range(10):
        while cur and (cur[0] in _SHELL_CONTROL_PREFIXES or _SH_ASSIGN_RE.match(cur[0])):
            cur.pop(0)
        if not cur or cur[0] in {"fi", "done", "}"}:
            return []
        exe = PurePosixPath(cur[0]).name
        if exe in {"exec", "nohup", "command"}:
            cur.pop(0)
            if exe == "command":
                while cur and cur[0] in {"-p", "--"}:
                    if cur.pop(0) == "--":
                        break
            continue
        if exe == "env":
            idx = 1
            while idx < len(cur):
                tok = cur[idx]
                if tok == "--":
                    idx += 1
                    break
                if tok in {"-u", "--unset", "-C", "--chdir"} and idx + 1 < len(cur):
                    idx += 2
                elif tok.startswith("-") or _SH_ASSIGN_RE.match(tok):
                    idx += 1
                else:
                    break
            cur = cur[idx:]
            continue
        if exe == "sudo":
            idx = 1
            while idx < len(cur):
                tok = cur[idx]
                if tok == "--":
                    idx += 1
                    break
                if tok in {"-u", "--user", "-g", "--group", "-C", "-D", "--chdir"} and idx + 1 < len(cur):
                    idx += 2
                elif tok.startswith("-"):
                    idx += 1
                else:
                    break
            cur = cur[idx:]
            continue
        if exe == "timeout" and len(cur) >= 3:
            idx = 1
            while idx < len(cur) and cur[idx].startswith("-"):
                if cur[idx] in {"-k", "--kill-after", "-s", "--signal"} and idx + 1 < len(cur):
                    idx += 2
                else:
                    idx += 1
            if idx < len(cur):
                cur = cur[idx + 1 :]
                continue
        break
    return cur


def _record_env_token(raw_env: str, line: int, out: list[EnvAssignment]) -> None:
    if "=" in raw_env:
        k, v = raw_env.split("=", 1)
        k = k.strip()
        if k:
            out.append(EnvAssignment(k, v, line))
    else:
        k = raw_env.strip()
        if k:
            out.append(EnvAssignment(k, None, line))


def parse_container_run_argv(
    tokens: list[str],
    line: int = 1,
) -> ContainerRunInvocation | None:
    """Parse `container run`, `docker run`, or `podman run`; return None for non-run commands."""
    cur = _unwrap_host_prefix(tokens)
    if len(cur) < 2:
        return None
    cli = PurePosixPath(cur[0]).name
    if cli not in CONTAINER_CLI_BINARIES:
        return None

    n = len(cur)
    idx = 1
    while idx < n and cur[idx].startswith("-"):
        tok = cur[idx]
        if tok == "--":
            return None
        if tok.startswith("--") and "=" in tok:
            idx += 1
        elif tok in _GLOBAL_VALUE_FLAGS:
            idx += 2
        else:
            idx += 1

    if idx >= n:
        return None
    sub = cur[idx]
    if sub == "run":
        idx += 1
    elif cli in {"docker", "podman"} and sub == "container" and idx + 1 < n and cur[idx + 1] == "run":
        idx += 2
    else:
        return None

    rm = False
    read_only_rootfs = False
    entrypoint: str | None = None
    workdir: str | None = None
    network: str | None = None
    env_list: list[EnvAssignment] = []
    env_files: list[tuple[str, int]] = []
    mounts: list[MountSpec] = []
    image: str | None = None
    command_argv: tuple[str, ...] = ()
    unresolved_flag: str | None = None

    while idx < n:
        tok = cur[idx]
        if tok == "--":
            idx += 1
            if idx < n:
                image = cur[idx]
                command_argv = tuple(cur[idx + 1 :])
            break

        if tok.startswith("--"):
            if "=" in tok:
                fname, fval = tok.split("=", 1)
                if fname == "--env":
                    _record_env_token(fval, line, env_list)
                elif fname == "--env-file" and fval.strip():
                    env_files.append((fval.strip(), line))
                elif fname == "--mount":
                    ms = _parse_mount_flag(fval)
                    if ms is not None:
                        mounts.append(ms)
                elif fname == "--volume":
                    ms = _parse_volume_flag(fval)
                    if ms is not None:
                        mounts.append(ms)
                elif fname == "--workdir" and fval.strip():
                    workdir = fval.strip()
                elif fname == "--entrypoint":
                    entrypoint = fval.strip()
                elif fname in {"--network", "--net"} and fval.strip():
                    network = fval.strip()
                elif fname in {"--rm", "--remove"}:
                    rm = fval.strip().lower() not in {"0", "false", "no"}
                elif fname == "--read-only":
                    read_only_rootfs = fval.strip().lower() not in {"0", "false", "no"}
                idx += 1
                continue

            if tok in {"--rm", "--remove"}:
                rm = True
                idx += 1
                continue
            if tok == "--read-only":
                read_only_rootfs = True
                idx += 1
                continue
            if tok in _RUN_BOOL_FLAGS:
                idx += 1
                continue
            if tok in _RUN_VALUE_FLAGS:
                fval = cur[idx + 1] if idx + 1 < n else ""
                if tok == "--env":
                    _record_env_token(fval, line, env_list)
                elif tok == "--env-file" and fval.strip():
                    env_files.append((fval.strip(), line))
                elif tok == "--mount":
                    ms = _parse_mount_flag(fval)
                    if ms is not None:
                        mounts.append(ms)
                elif tok == "--volume":
                    ms = _parse_volume_flag(fval)
                    if ms is not None:
                        mounts.append(ms)
                elif tok == "--workdir" and fval.strip():
                    workdir = fval.strip()
                elif tok == "--entrypoint":
                    entrypoint = fval.strip()
                elif tok in {"--network", "--net"} and fval.strip():
                    network = fval.strip()
                idx += 2
                continue
            unresolved_flag = tok
            break

        if tok.startswith("-") and tok != "-":
            chars = tok[1:]
            extra_step = 0
            for ci, ch in enumerate(chars):
                if ch in _RUN_SHORT_BOOL_CHARS:
                    continue
                if ch in _RUN_SHORT_VALUE_CHARS:
                    rem = chars[ci + 1 :]
                    if rem:
                        fval = rem[1:] if rem.startswith("=") and ch != "e" else rem
                    else:
                        fval = cur[idx + 1] if idx + 1 < n else ""
                        extra_step = 1
                    if ch == "e":
                        _record_env_token(fval, line, env_list)
                    elif ch == "v":
                        ms = _parse_volume_flag(fval)
                        if ms is not None:
                            mounts.append(ms)
                    elif ch == "w" and fval.strip():
                        workdir = fval.strip()
                    break
            idx += 1 + extra_step
            continue

        image = tok
        command_argv = tuple(cur[idx + 1 :])
        break

    return ContainerRunInvocation(
        cli=cli,
        line=line,
        image=image,
        command_argv=command_argv,
        entrypoint=entrypoint,
        workdir=workdir,
        rm=rm,
        read_only_rootfs=read_only_rootfs,
        network=network,
        env=tuple(env_list),
        env_files=tuple(env_files),
        mounts=tuple(mounts),
        raw_argv=tuple(cur),
        unresolved_flag=unresolved_flag,
    )


def _join_continued_lines(text: str, *, allow_semicolon_comments: bool = False) -> list[tuple[int, str]]:
    """Join backslash-continued physical lines into `(start_line, logical_line)` pairs."""
    out: list[tuple[int, str]] = []
    buf: list[str] = []
    start_line = 1
    comment_prefixes = ("#", ";") if allow_semicolon_comments else ("#",)
    for lineno, raw in enumerate(text.splitlines(), start=1):
        stripped = raw.strip()
        if not buf:
            if not stripped or raw.lstrip().startswith(comment_prefixes):
                continue
            start_line = lineno
        else:
            if raw.lstrip().startswith(comment_prefixes):
                continue
            if not stripped:
                out.append((start_line, " ".join(buf).strip()))
                buf.clear()
                continue
        rstripped = raw.rstrip()
        if rstripped.endswith("\\") and not rstripped.endswith("\\\\"):
            buf.append(rstripped[:-1].strip())
        else:
            buf.append(stripped)
            out.append((start_line, " ".join(buf).strip()))
            buf.clear()
    if buf:
        out.append((start_line, " ".join(buf).strip()))
    return out


def _sanitize_shell_command_subs(
    raw: str,
    sub_map: dict[str, str],
    inner_cmds: list[str] | None = None,
) -> str:
    """Replace `$(...)` outside single quotes so `shlex` keeps dynamic tags/mounts intact."""
    out: list[str] = []
    in_single = False
    i = 0
    n = len(raw)
    while i < n:
        ch = raw[i]
        if ch == "'" and not in_single:
            in_single = True
            out.append(ch)
            i += 1
            continue
        if ch == "'" and in_single:
            in_single = False
            out.append(ch)
            i += 1
            continue
        if not in_single and ch == "$" and i + 1 < n and raw[i + 1] == "(":
            depth = 1
            j = i + 2
            while j < n and depth > 0:
                if raw[j] == "(":
                    depth += 1
                elif raw[j] == ")":
                    depth -= 1
                j += 1
            inner = raw[i + 2 : j - 1].strip() if depth == 0 else raw[i + 2 :].strip()
            orig = raw[i:j]
            if inner == "pwd":
                out.append("${PWD}")
            else:
                key = f"{_CMD_SUB_TOKEN_PREFIX}{len(sub_map)}__"
                sub_map[key] = orig
                if inner_cmds is not None and inner:
                    inner_cmds.append(inner)
                out.append(f"${{{key}}}")
            i = j
            continue
        out.append(ch)
        i += 1
    return "".join(out)


def _restore_cmd_subs(val: str, sub_map: dict[str, str]) -> str:
    if _CMD_SUB_TOKEN_PREFIX not in val or not sub_map:
        return val
    return _CMD_SUB_PLACEHOLDER_RE.sub(
        lambda m: sub_map.get(m.group(0)[2:-1], m.group(0)),
        val,
    )


def _strip_unquoted_shell_comment(line: str) -> str:
    """Strip POSIX word-initial `#` comments while preserving mid-word `#` (e.g. `${VERSION#v}`)."""
    in_single = False
    in_double = False
    brace_depth = 0
    escaped = False
    for idx, ch in enumerate(line):
        if escaped:
            escaped = False
            continue
        if ch == "\\" and not in_single:
            escaped = True
            continue
        if ch == "'" and not in_double:
            in_single = not in_single
            continue
        if ch == '"' and not in_single:
            in_double = not in_double
            continue
        if not in_single:
            if ch == "{" and idx > 0 and line[idx - 1] == "$":
                brace_depth += 1
                continue
            if ch == "}" and brace_depth > 0:
                brace_depth -= 1
                continue
        if (
            ch == "#"
            and not in_single
            and not in_double
            and brace_depth == 0
            and (idx == 0 or line[idx - 1] in " \t;&|()")
        ):
            return line[:idx].rstrip()
    return line


def _split_shell_commands(line: str) -> list[list[str]]:
    segments: list[list[str]] = []
    uncommented = _strip_unquoted_shell_comment(line)
    try:
        lex = shlex.shlex(uncommented, posix=True, punctuation_chars=";&|")
        lex.commenters = ""
        lex.whitespace_split = True
        tokens = list(lex)
    except ValueError:
        tokens = uncommented.split()
    cur: list[str] = []
    for tok in tokens:
        if set(tok) <= set(";&|"):
            if cur:
                segments.append(cur)
                cur = []
            continue
        cleaned = tok
        if not cur and cleaned.startswith("("):
            cleaned = cleaned.lstrip("(")
        if cleaned.endswith(")") and "(" not in cleaned:
            cleaned = cleaned.rstrip(")")
        if cleaned:
            cur.append(cleaned)
    if cur:
        segments.append(cur)
    return segments


def _expand_leading_var_exe(seg: list[str], static_vars: dict[str, str]) -> list[str]:
    if not static_vars or not seg:
        return seg
    cur = _unwrap_host_prefix(seg)
    if not cur:
        return seg
    m = re.fullmatch(r"\$(?:\{([A-Za-z_][A-Za-z0-9_]*)\}|([A-Za-z_][A-Za-z0-9_]*))", cur[0])
    if not m:
        return seg
    vname = m.group(1) or m.group(2)
    resolved = static_vars.get(vname)
    if not resolved:
        return seg
    try:
        rep_toks = shlex.split(resolved, posix=True)
    except ValueError:
        rep_toks = resolved.split()
    if not rep_toks:
        return seg
    return [*rep_toks, *cur[1:]]


def _extract_build_hint(tokens: list[str]) -> tuple[str, str, str] | None:
    cur = _unwrap_host_prefix(tokens)
    if len(cur) < 3:
        return None
    cli = PurePosixPath(cur[0]).name
    if cli not in CONTAINER_CLI_BINARIES:
        return None
    idx = 1
    if cur[idx] == "build":
        idx += 1
    elif cur[idx] in {"buildx", "image"} and idx + 1 < len(cur) and cur[idx + 1] == "build":
        idx += 2
    else:
        return None
    tag: str | None = None
    df_arg = "Dockerfile"
    ctx_arg = "."
    n = len(cur)
    while idx < n:
        t = cur[idx]
        if t in {"-t", "--tag"} and idx + 1 < n:
            tag = cur[idx + 1].strip()
            idx += 2
        elif t.startswith("--tag="):
            tag = t.split("=", 1)[1].strip()
            idx += 1
        elif t in {"-f", "--file"} and idx + 1 < n:
            df_arg = cur[idx + 1].strip()
            idx += 2
        elif t.startswith("--file="):
            df_arg = t.split("=", 1)[1].strip()
            idx += 1
        elif t.startswith("--") and "=" in t:
            idx += 1
        elif t in {"--build-arg", "--target", "--platform", "--progress", "--cache-from", "--cache-to", "--output", "-o", "--secret", "--ssh", "--network", "--label"} and idx + 1 < n:
            idx += 2
        elif t.startswith("-"):
            idx += 1
        else:
            ctx_arg = t.strip()
            idx += 1
    if not tag or _VAR_TOKEN_RE.search(tag):
        return None
    return tag, df_arg, ctx_arg


def extract_shell_container_runs(
    text: str,
) -> tuple[list[ContainerRunInvocation], list[tuple[str, str, str]], dict[str, str]]:
    """Extract `container`/`docker`/`podman run` invocations from POSIX shell source."""
    invocations: list[ContainerRunInvocation] = []
    build_hints: list[tuple[str, str, str]] = []
    static_vars: dict[str, str] = {}
    sub_map: dict[str, str] = {}

    def _scan_logical(start_line: int, logical: str, depth: int = 0) -> None:
        inner_cmds: list[str] = []
        sanitized = _sanitize_shell_command_subs(logical, sub_map, inner_cmds)
        for raw_seg in _split_shell_commands(sanitized):
            if not raw_seg:
                continue
            first = raw_seg[0]
            if first in {"export", "local"} and len(raw_seg) >= 2:
                for item in raw_seg[1:]:
                    m = _SH_ASSIGN_RE.match(item)
                    if m:
                        k, v = m.group("key"), _restore_cmd_subs(m.group("val"), sub_map)
                        if not _VAR_TOKEN_RE.search(v) and "$(" not in v and "`" not in v:
                            static_vars[k] = v
                        else:
                            static_vars.pop(k, None)
                continue
            if len(raw_seg) == 1:
                m = _SH_ASSIGN_RE.match(first)
                if m:
                    k, v = m.group("key"), _restore_cmd_subs(m.group("val"), sub_map)
                    if not _VAR_TOKEN_RE.search(v) and "$(" not in v and "`" not in v:
                        static_vars[k] = v
                    else:
                        static_vars.pop(k, None)
                    continue

            seg = _expand_leading_var_exe(raw_seg, static_vars)
            bh = _extract_build_hint(seg)
            if bh is not None:
                build_hints.append(bh)
                continue

            inv = parse_container_run_argv(seg, line=start_line)
            if inv is not None:
                restored_img = _restore_cmd_subs(inv.image, sub_map) if inv.image else None
                restored_env = tuple(
                    EnvAssignment(
                        e.key,
                        _restore_cmd_subs(e.value, sub_map) if e.value is not None else None,
                        e.line,
                    )
                    for e in inv.env
                )
                restored_cmd = tuple(_restore_cmd_subs(c, sub_map) for c in inv.command_argv)
                invocations.append(
                    ContainerRunInvocation(
                        cli=inv.cli,
                        line=inv.line,
                        image=restored_img,
                        command_argv=restored_cmd,
                        entrypoint=inv.entrypoint,
                        workdir=inv.workdir,
                        rm=inv.rm,
                        read_only_rootfs=inv.read_only_rootfs,
                        network=inv.network,
                        env=restored_env,
                        env_files=inv.env_files,
                        mounts=inv.mounts,
                        raw_argv=tuple(_restore_cmd_subs(r, sub_map) for r in inv.raw_argv),
                        unresolved_flag=inv.unresolved_flag,
                    )
                )

        if depth < 3:
            for inner in inner_cmds:
                _scan_logical(start_line, inner, depth + 1)

    for start_line, raw_logical in _join_continued_lines(text):
        _scan_logical(start_line, raw_logical)
    return invocations, build_hints, static_vars


_UNPARSED_CLI_RUN_RE = re.compile(
    r"(?:^|[\s;|&(!`])(?:/[\w./-]+/)?(?:docker|podman|container|\$\{?[A-Za-z0-9_]*(?:DOCKER|PODMAN|CONTAINER)[A-Za-z0-9_]*\}?)\s+(?:container\s+)?run(?:\s|$)"
)


def _find_unparsed_shell_cli_lines(
    text: str,
    invocations: list[ContainerRunInvocation],
) -> list[int]:
    parsed_lines = {inv.line for inv in invocations}
    missed: list[int] = []
    for start_line, raw_logical in _join_continued_lines(text):
        if start_line in parsed_lines:
            continue
        uncommented = _strip_unquoted_shell_comment(raw_logical)
        if _UNPARSED_CLI_RUN_RE.search(uncommented):
            missed.append(start_line)
    return missed


def _strip_systemd_exec_prefix(raw_cmd: str) -> tuple[list[str], bool]:
    """Tokenize systemd `ExecStart=`/`ExecStartPre=`, stripping `-@:+!` prefixes."""
    stripped = raw_cmd.strip()
    if not stripped:
        return [], True
    idx = 0
    has_at_argv0 = False
    while idx < len(stripped) and stripped[idx] in "-@:+!":
        if stripped[idx] == "@":
            has_at_argv0 = True
        idx += 1
    body = stripped[idx:].strip()
    if not body:
        return [], True
    try:
        tokens = shlex.split(body, posix=True)
    except ValueError:
        tokens = body.split()
    if not tokens:
        return [], True
    if has_at_argv0 and len(tokens) >= 2:
        tokens = [tokens[0], *tokens[2:]]
    return tokens, False


def parse_systemd_unit(
    unit_path: Path,
    repo_root: Path,
    *,
    notes_out: list[str] | None = None,
) -> ParsedSystemdUnit | None:
    """Statically parse a `.service` unit file without invoking `systemctl`."""
    real_root = repo_root.resolve()
    if unit_path.is_symlink() or not unit_path.is_file() or not _is_within_root(unit_path, real_root):
        return None
    rel_path = unit_path.resolve().relative_to(real_root).as_posix()
    try:
        if unit_path.stat().st_size > MAX_UNIT_FILE_BYTES:
            if notes_out is not None:
                note = f"Skipped systemd unit {rel_path} (exceeds {MAX_UNIT_FILE_BYTES} bytes); unit command evidence absent."
                if note not in notes_out:
                    notes_out.append(note)
            return None
        text = unit_path.read_text(encoding="utf-8")
    except (OSError, UnicodeError):
        if notes_out is not None:
            note = f"Skipped systemd unit {rel_path} (unreadable or non-UTF-8); unit command evidence absent."
            if note not in notes_out:
                notes_out.append(note)
        return None
    section = ""
    has_systemd_section = False
    service_line = 1
    description: str | None = None
    working_dir: str | None = None
    working_dir_line = 1
    env_items: list[EnvAssignment] = []
    env_files: list[tuple[str, bool, int]] = []
    exec_specs: list[SystemdExecSpec] = []
    empty_exec_lines: list[int] = []

    for lineno, logical in _join_continued_lines(text, allow_semicolon_comments=True):
        if logical.startswith("[") and logical.endswith("]"):
            section = logical[1:-1].strip()
            if section in {"Unit", "Service", "Install", "Socket"}:
                has_systemd_section = True
            if section == "Service" and service_line == 1:
                service_line = lineno
            continue
        if "=" not in logical:
            continue
        key_raw, val_raw = logical.split("=", 1)
        key = key_raw.strip()
        val = val_raw.strip()

        if section == "Unit" and key == "Description" and val:
            description = val
        elif section in {"Service", ""}:
            if key in {"ExecStart", "ExecStartPre"}:
                has_systemd_section = True
                if not val:
                    if key == "ExecStart":
                        exec_specs = [e for e in exec_specs if e.directive != "ExecStart"]
                        empty_exec_lines.append(lineno)
                    continue
                argv, is_empty = _strip_systemd_exec_prefix(val)
                if is_empty or not argv:
                    empty_exec_lines.append(lineno)
                else:
                    exec_specs.append(SystemdExecSpec(key, tuple(argv), lineno, val))
            elif key == "WorkingDirectory" and val:
                wd = val[1:].strip() if val.startswith("-") else val
                if wd:
                    working_dir = wd
                    working_dir_line = lineno
            elif key == "Environment" and val:
                try:
                    etoks = shlex.split(val, posix=True)
                except ValueError:
                    etoks = val.split()
                for etok in etoks:
                    _record_env_token(etok, lineno, env_items)
            elif key == "EnvironmentFile" and val:
                optional = val.startswith("-")
                ef_path = val[1:].strip() if optional else val
                if ef_path:
                    env_files.append((ef_path, optional, lineno))

    if not has_systemd_section:
        return None
    anchor_line = exec_specs[0].line if exec_specs else service_line
    return ParsedSystemdUnit(
        rel_path=rel_path,
        description=description,
        line=anchor_line,
        working_dir=working_dir,
        working_dir_line=working_dir_line,
        environment=tuple(env_items),
        env_files=tuple(env_files),
        exec_commands=tuple(exec_specs),
        empty_exec_lines=tuple(empty_exec_lines),
    )


def parse_launchd_plist(
    plist_path: Path,
    repo_root: Path,
) -> tuple[ParsedLaunchdUnit | None, str | None]:
    """Statically parse a `launchd` `.plist` command declaration without `launchctl`."""
    real_root = repo_root.resolve()
    if plist_path.is_symlink() or not plist_path.is_file() or not _is_within_root(plist_path, real_root):
        return None, None
    rel_path = plist_path.resolve().relative_to(real_root).as_posix()
    try:
        if plist_path.stat().st_size > MAX_UNIT_FILE_BYTES:
            return None, f"Skipped launchd source {rel_path} (exceeds {MAX_UNIT_FILE_BYTES} bytes); command evidence absent."
        raw = plist_path.read_bytes()
        data = plistlib.loads(raw)
    except (OSError, ValueError, plistlib.InvalidFileException, ExpatError):
        return None, f"Could not parse launchd source {rel_path}; command evidence absent."

    if not isinstance(data, dict) or not ({"Program", "ProgramArguments"} & data.keys()):
        return None, None

    fields, arg_lines = command_locations(raw)
    env_lines = env_locations(raw)
    prog_raw = data.get("Program")
    args_raw = data.get("ProgramArguments", [])
    prog_line = fields.get("Program", 1)
    args_field_line = fields.get("ProgramArguments", 1)

    structural_problem: tuple[str, int] | None = None
    clean_args: list[str] = []
    if "ProgramArguments" in data:
        if not isinstance(args_raw, list) or any(not isinstance(a, str) for a in args_raw):
            bad_line = args_field_line
            if isinstance(args_raw, list):
                bad_idx = next((i for i, a in enumerate(args_raw) if not isinstance(a, str)), 0)
                if bad_idx < len(arg_lines):
                    bad_line = arg_lines[bad_idx]
            structural_problem = ("ProgramArguments must be an array of strings.", bad_line)
        else:
            clean_args = list(args_raw)

    program: str | None = None
    if prog_raw is not None:
        if not isinstance(prog_raw, str) or not prog_raw.strip():
            structural_problem = ("Program must be a nonempty executable path.", prog_line)
        else:
            program = prog_raw

    if structural_problem is None and program is None and (not clean_args or not clean_args[0].strip()):
        structural_problem = (
            "No executable is supplied by Program or ProgramArguments.",
            arg_lines[0] if arg_lines else args_field_line,
        )

    env_list: list[EnvAssignment] = []
    raw_env = data.get("EnvironmentVariables")
    if isinstance(raw_env, dict):
        for ek, ev in raw_env.items():
            if isinstance(ek, str) and ek.strip() and isinstance(ev, (str, int, float)) and not isinstance(ev, bool):
                clean_ek = ek.strip()
                env_list.append(EnvAssignment(clean_ek, str(ev), env_lines.get(clean_ek, env_lines.get(ek, 1))))

    return (
        ParsedLaunchdUnit(
            rel_path=rel_path,
            disabled=data.get("Disabled") is True,
            program=program,
            program_line=prog_line,
            program_args=tuple(clean_args),
            arg_lines=tuple(arg_lines),
            environment=tuple(env_list),
            structural_problem=structural_problem,
        ),
        None,
    )


def _is_template_env_filename(rel_or_name: str) -> bool:
    low = PurePosixPath(rel_or_name.replace("\\", "/")).name.lower()
    if any(low.endswith(m) or f"{m}." in low for m in _TEMPLATE_ENV_MARKERS):
        return True
    return low in {"example.env", "sample.env", "template.env", "defaults.env"}


def _resolve_contained_repo_path(
    raw_path: str,
    search_dirs: list[Path],
    real_root: Path,
) -> Path | None:
    """Resolve an in-repo file or directory without following symlinks or `..` escaping `real_root`."""
    cleaned = raw_path.strip().replace("\\", "/")
    if not cleaned or "\x00" in cleaned or cleaned.startswith("~") or _VAR_TOKEN_RE.search(cleaned):
        return None
    p = PurePosixPath(cleaned)
    if p.is_absolute():
        try:
            cand = Path(cleaned)
            if cand.is_symlink() or not _is_within_root(cand, real_root):
                return None
            rel_parts = cand.relative_to(real_root).parts
        except ValueError:
            return None
        cur = real_root
        for part in rel_parts:
            cur = cur / part
            if cur.is_symlink() or not _is_within_root(cur, real_root):
                return None
        return cur if cur.exists() else None

    for bdir in search_dirs:
        if bdir.is_symlink() or not _is_within_root(bdir, real_root):
            continue
        cur = bdir
        valid = True
        for part in p.parts:
            if part in ("", "."):
                continue
            if part == "..":
                cur = cur.parent
                if not _is_within_root(cur, real_root):
                    valid = False
                    break
            else:
                cur = cur / part
                if cur.is_symlink() or not _is_within_root(cur, real_root):
                    valid = False
                    break
        if valid and not cur.is_symlink() and _is_within_root(cur, real_root) and cur.exists():
            return cur
    return None


def _parse_static_env_lines(text: str) -> list[EnvAssignment]:
    entries: list[EnvAssignment] = []
    for lineno, raw_ln in enumerate(text.splitlines(), start=1):
        s = raw_ln.strip()
        if not s or s.startswith("#"):
            continue
        if s.startswith("export ") and len(s) > 7:
            s = s[7:].strip()
        if "=" not in s:
            entries.append(EnvAssignment(s, None, lineno))
            continue
        k_raw, v_raw = s.split("=", 1)
        k = k_raw.strip()
        if not k:
            continue
        v = v_raw.strip()
        if len(v) >= 2 and v[0] == v[-1] and v[0] in ("'", '"'):
            v = v[1:-1]
        elif " #" in v:
            v = v.split(" #", 1)[0].strip()
        entries.append(EnvAssignment(k, v, lineno))
    return entries


def _parse_and_audit_env_file(
    raw_env_path: str,
    search_dirs: list[Path],
    real_root: Path,
    owner_node: AtlasNode,
    active_tokens: tuple[str, ...],
    policy_fn: object,
    seen_env_findings: set[tuple[str, int, str]],
    findings_out: list[RawCandidateFinding],
    notes_out: list[str] | None = None,
) -> dict[str, str]:
    """Read a containment-checked in-repo env file and audit non-template policy literals."""
    resolved = _resolve_contained_repo_path(raw_env_path, search_dirs, real_root)
    if resolved is None or not resolved.is_file():
        return {}
    env_rel = resolved.resolve().relative_to(real_root).as_posix()
    try:
        if resolved.stat().st_size > MAX_ENV_FILE_BYTES:
            if notes_out is not None:
                note = f"Skipped env file {env_rel} (exceeds {MAX_ENV_FILE_BYTES} bytes); env policy/binding evidence absent."
                if note not in notes_out:
                    notes_out.append(note)
            return {}
        text = resolved.read_text(encoding="utf-8")
    except (OSError, UnicodeError):
        if notes_out is not None:
            note = f"Skipped env file {env_rel} (unreadable or non-UTF-8); env policy/binding evidence absent."
            if note not in notes_out:
                notes_out.append(note)
        return {}
    parsed_entries = _parse_static_env_lines(text)
    is_template = _is_template_env_filename(env_rel)
    bindings: dict[str, str] = {}

    for entry in parsed_entries:
        if entry.value is not None and not _VAR_TOKEN_RE.search(entry.value):
            bindings[entry.key] = entry.value
        if is_template or entry.value is None:
            continue
        sample = policy_fn(entry.key, entry.value, active_tokens)  # type: ignore[operator]
        dedup_key = (env_rel, entry.line, entry.key)
        if sample is not None and dedup_key not in seen_env_findings:
            seen_env_findings.add(dedup_key)
            owner_node.status = "policy_in_code"
            findings_out.append(
                RawCandidateFinding(
                    rule_code="MANIP-001",
                    node_id=owner_node.id,
                    source_file=env_rel,
                    line=entry.line,
                    title=f"Hardcoded policy threshold `{entry.key}` ({sample}) in `{env_rel}`",
                    detail=(
                        f"Environment file `{env_rel}:{entry.line}` referenced by `{owner_node.source_file}` "
                        f"commits mutable domain policy threshold `{entry.key}={sample}`."
                    ),
                    remediation=(
                        "Store mutable domain policy thresholds in PostgreSQL truth rather than committed "
                        "environment files (keep `.env.example` for documentation only)."
                    ),
                )
            )
    return bindings


def _audit_inline_env_assignments(
    assignments: tuple[EnvAssignment, ...],
    owner_node: AtlasNode,
    source_rel: str,
    surface_desc: str,
    active_tokens: tuple[str, ...],
    policy_fn: object,
    findings_out: list[RawCandidateFinding],
    shell_static_vars: dict[str, str] | None = None,
) -> dict[str, str]:
    bindings: dict[str, str] = {}
    seen_keys: set[tuple[int, str]] = set()
    for item in assignments:
        if item.value is None:
            continue
        val = item.value
        if (
            len(val) >= 2
            and val[0] == val[-1]
            and val[0] in ("'", '"')
        ):
            val = val[1:-1]
        if not _VAR_TOKEN_RE.search(val) and "$(" not in val:
            bindings[item.key] = val
        eff_val = val
        if shell_static_vars:
            m_var = re.fullmatch(r"\$(?:\{([A-Za-z_][A-Za-z0-9_]*)\}|([A-Za-z_][A-Za-z0-9_]*))", val.strip())
            if m_var:
                vname = m_var.group(1) or m_var.group(2)
                if vname in shell_static_vars:
                    eff_val = shell_static_vars[vname]
                    bindings[item.key] = eff_val
        sample = policy_fn(item.key, eff_val, active_tokens)  # type: ignore[operator]
        if sample is not None and (item.line, item.key) not in seen_keys:
            seen_keys.add((item.line, item.key))
            owner_node.status = "policy_in_code"
            findings_out.append(
                RawCandidateFinding(
                    rule_code="MANIP-001",
                    node_id=owner_node.id,
                    source_file=source_rel,
                    line=item.line,
                    title=f"Hardcoded policy threshold `{item.key}` ({sample}) in `{source_rel}`",
                    detail=(
                        f"{surface_desc} at `{source_rel}:{item.line}` hardcodes mutable domain policy "
                        f"threshold `{item.key}={sample}`."
                    ),
                    remediation=(
                        "Store mutable domain policy thresholds in PostgreSQL truth (or pass runtime "
                        "values via bare `-e KEY` / `${VAR}` pass-through without hardcoded literals)."
                    ),
                )
            )
    return bindings


def _has_unexpanded_exec_token(tok: str, *, allow_double_dollar: bool = False) -> bool:
    cleaned = tok.replace("$$", "") if allow_double_dollar else tok
    if _VAR_TOKEN_RE.search(cleaned):
        return True
    return bool(_TILDE_ARG_RE.search(tok))


def _has_unexpanded_systemd_arg_token(tok: str) -> bool:
    """Per `systemd.service(5)`, `${FOO}` anywhere and standalone `$FOO` expand natively."""
    cleaned = tok.replace("$$", "")
    if _TILDE_ARG_RE.search(tok) or "$(" in cleaned or "`" in cleaned:
        return True
    if _SYSTEMD_WHOLE_VAR_RE.fullmatch(cleaned):
        return False
    without_simple_braces = _SYSTEMD_SIMPLE_BRACE_RE.sub("", cleaned)
    return bool(_VAR_TOKEN_RE.search(without_simple_braces))


def _substitute_systemd_env(argv: list[str], env_map: dict[str, str]) -> list[str]:
    if not env_map or not argv:
        return argv
    out: list[str] = [argv[0]]
    for tok in argv[1:]:
        if _SYSTEMD_WHOLE_VAR_RE.fullmatch(tok):
            vname = tok[1:]
            if vname in env_map:
                out.extend(env_map[vname].split() or [""])
                continue
        replaced = _SYSTEMD_SIMPLE_BRACE_RE.sub(
            lambda m: env_map.get(m.group(0)[2:-1], m.group(0)),
            tok,
        )
        out.append(replaced)
    return out


def _check_systemd_exec_expansion(
    unit: ParsedSystemdUnit,
    nid: str,
    findings_out: list[RawCandidateFinding],
) -> None:
    if not unit.exec_commands and unit.empty_exec_lines:
        ln = unit.empty_exec_lines[-1]
        findings_out.append(
            RawCandidateFinding(
                rule_code="MANIP-004",
                node_id=nid,
                source_file=unit.rel_path,
                line=ln,
                title=f"Empty `ExecStart` declaration in `{unit.rel_path}`",
                detail=f"`ExecStart=` at `{unit.rel_path}:{ln}` clears or omits an executable command.",
                remediation="Provide a concrete absolute executable path in `ExecStart=`.",
            )
        )
        return

    for espec in unit.exec_commands:
        argv = list(espec.argv)
        if not argv:
            continue
        bad: list[str] = []
        first = argv[0]
        if _has_unexpanded_exec_token(first, allow_double_dollar=True):
            bad.append(first)
        elif not _exec_invokes_shell(argv):
            for tok in argv[1:]:
                if _has_unexpanded_systemd_arg_token(tok):
                    bad.append(tok)
        if bad:
            sample = ", ".join(f"`{t}`" for t in bad[:3])
            findings_out.append(
                RawCandidateFinding(
                    rule_code="MANIP-004",
                    node_id=nid,
                    source_file=unit.rel_path,
                    line=espec.line,
                    title=f"Systemd `{espec.directive}` uses unexpanded shell syntax ({sample})",
                    detail=(
                        f"`{espec.directive}=` at `{unit.rel_path}:{espec.line}` passes {sample} without "
                        "invoking a shell; systemd does not expand `~` or shell expressions directly."
                    ),
                    remediation='Invoke `/bin/sh -c "..."` when shell expansion is intended, or use concrete paths.',
                )
            )


def _check_launchd_exec_expansion(
    unit: ParsedLaunchdUnit,
    nid: str,
    already_had_node: bool,
    has_container_run: bool,
    findings_out: list[RawCandidateFinding],
) -> None:
    if any(f.rule_code == "MANIP-004" and f.node_id == nid for f in findings_out):
        return
    if already_had_node and not has_container_run:
        return
    if unit.structural_problem is not None:
        msg, bad_ln = unit.structural_problem
        findings_out.append(
            RawCandidateFinding(
                rule_code="MANIP-004",
                node_id=nid,
                source_file=unit.rel_path,
                line=bad_ln,
                title="Review invalid launchd command declaration",
                detail=msg,
                remediation="Use an array of concrete string arguments or an explicit `/bin/sh -c` wrapper.",
            )
        )
        return

    eff_argv = (
        [unit.program, *unit.program_args[1:]]
        if unit.program and unit.program_args
        else ([unit.program] if unit.program else list(unit.program_args))
    )
    if not eff_argv:
        return

    if _has_unexpanded_exec_token(eff_argv[0], allow_double_dollar=False):
        ln = unit.program_line if unit.program else (unit.arg_lines[0] if unit.arg_lines else 1)
        findings_out.append(
            RawCandidateFinding(
                rule_code="MANIP-004",
                node_id=nid,
                source_file=unit.rel_path,
                line=ln,
                title=f"Launchd executable `{eff_argv[0]}` uses unexpanded shell syntax",
                detail=(
                    f"`{unit.rel_path}:{ln}` specifies `{eff_argv[0]}`, "
                    "but `launchd` invokes `posix_spawn` directly without expanding `$VAR` or `~`."
                ),
                remediation="Use an absolute executable path or invoke `/bin/sh -c` explicitly.",
            )
        )
        return

    if _exec_invokes_shell(eff_argv):
        return

    for idx, tok in enumerate(eff_argv[1:], start=1):
        if _has_unexpanded_exec_token(tok, allow_double_dollar=False):
            ln = unit.arg_lines[idx] if idx < len(unit.arg_lines) else 1
            findings_out.append(
                RawCandidateFinding(
                    rule_code="MANIP-004",
                    node_id=nid,
                    source_file=unit.rel_path,
                    line=ln,
                    title=f"Launchd `ProgramArguments` uses unexpanded shell token (`{tok}`)",
                    detail=(
                        f"`{unit.rel_path}:{ln}` passes `{tok}` in non-shell `ProgramArguments`; "
                        "`launchd` does not expand `$VAR` or `~` without a shell."
                    ),
                remediation='Wrap the command in `["/bin/sh", "-c", "..."]` or pass concrete literal arguments.',
                )
            )
            return


def _normalize_image_repo(image: str | None) -> tuple[str | None, str | None]:
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


def _dockerfile_stem_tokens(df_rel: str) -> set[str]:
    p = PurePosixPath(df_rel)
    lower_name = p.name.lower()
    tokens: set[str] = set()
    for pfx in ("dockerfile.", "containerfile."):
        if lower_name.startswith(pfx):
            tokens.update(t for t in re.split(r"[^a-z0-9]+", lower_name[len(pfx) :]) if len(t) >= 2)
    for sfx in (".dockerfile", ".containerfile"):
        if lower_name.endswith(sfx):
            tokens.update(t for t in re.split(r"[^a-z0-9]+", lower_name[: -len(sfx)]) if len(t) >= 2)
    for part in p.parts[:-1]:
        if part.lower() not in {".", ".docker", "backend", "docker", "containers", "deploy"}:
            tokens.update(t for t in re.split(r"[^a-z0-9]+", part.lower()) if len(t) >= 2)
    return tokens


def _is_external_base_image(image: str, backing_fn: object) -> bool:
    if backing_fn(image) is not None:  # type: ignore[operator]
        return True
    low = image.strip().lower()
    if low.startswith(_EXTERNAL_REGISTRY_PREFIXES):
        return True
    norm, leaf = _normalize_image_repo(image)
    if norm is None or leaf is None:
        return False
    if "/" in norm and not norm.startswith("library/"):
        return False
    if leaf in _EXTERNAL_BASE_LEAVES:
        return True
    for base_pfx in ("python", "node", "golang", "rust", "openjdk", "ubuntu", "debian", "alpine"):
        if leaf == base_pfx or leaf.startswith(base_pfx + "-"):
            return True
    return False


def _match_dockerfile_for_run(
    raw_image: str | None,
    launcher_hint: str,
    df_cache: dict[str, ParsedDockerfile],
    compose_img_to_df: dict[str, str],
    compose_svc_to_df: dict[str, str],
    build_img_to_df: dict[str, str],
    backing_fn: object,
    shell_static_vars: dict[str, str] | None = None,
) -> tuple[str | None, ParsedDockerfile | None, str | None, str | None]:
    """Match a CLI `run` image to an in-repo Dockerfile or classify unresolved/external."""
    if not raw_image:
        return None, None, None, None

    eff_img = raw_image.strip()
    if shell_static_vars:
        def _sub_static(m: re.Match[str]) -> str:
            k = m.group(1) or m.group(2)
            return shell_static_vars.get(k, m.group(0))

        eff_img = re.sub(
            r"\$(?:\{([A-Za-z_][A-Za-z0-9_]*)\}|([A-Za-z_][A-Za-z0-9_]*))",
            _sub_static,
            eff_img,
        )

    has_dyn = bool(_VAR_TOKEN_RE.search(eff_img) or "$(" in eff_img or "`" in eff_img)
    dyn_note = f"{launcher_hint} [{raw_image}]" if has_dyn else None

    repo_part = eff_img.split("@", 1)[0]
    last_slash = repo_part.rfind("/")
    colon_idx = repo_part.rfind(":")
    repo_without_tag = repo_part[:colon_idx] if colon_idx > last_slash else repo_part
    if _VAR_TOKEN_RE.search(repo_without_tag) or "$(" in repo_without_tag:
        return None, None, dyn_note, None

    img_repo, img_leaf = _normalize_image_repo(eff_img)
    if img_repo and img_repo in build_img_to_df:
        df_rel = build_img_to_df[img_repo]
        return df_rel, df_cache.get(df_rel), dyn_note, None
    if img_repo and img_repo in compose_img_to_df:
        df_rel = compose_img_to_df[img_repo]
        return df_rel, df_cache.get(df_rel), dyn_note, None

    if _is_external_base_image(eff_img, backing_fn):
        return None, None, dyn_note, f"{launcher_hint} [{eff_img}]"

    if not df_cache:
        ext_note = None if has_dyn else f"{launcher_hint} [{eff_img}]"
        return None, None, dyn_note, ext_note

    if img_leaf and img_leaf in compose_svc_to_df:
        df_rel = compose_svc_to_df[img_leaf]
        return df_rel, df_cache.get(df_rel), dyn_note, None

    ext_note = None if has_dyn else f"{launcher_hint} [{eff_img}]"
    return None, None, dyn_note, ext_note


def discover_launcher_files(repo_root: Path) -> tuple[list[Path], list[Path], list[Path]]:
    """Discover `.plist`, `.service`, and `.sh` files without following symlinks."""
    if repo_root.is_symlink():
        return [], [], []
    real_root = repo_root.resolve()
    plists: list[Path] = []
    services: list[Path] = []
    shells: list[Path] = []

    for parent, dirs, names in os.walk(repo_root, followlinks=False):
        keep: list[str] = []
        for dname in sorted(dirs):
            dpath = Path(parent) / dname
            if (
                dname in EXCLUDED_PARTS
                or (dname.startswith(".") and dname not in ALLOWED_CONTAINER_DOT_DIRS)
                or dpath.is_symlink()
                or not _is_within_root(dpath, real_root)
            ):
                continue
            keep.append(dname)
        dirs[:] = keep

        for fname in sorted(names):
            fpath = Path(parent) / fname
            if fpath.is_symlink() or not fpath.is_file() or not _is_within_root(fpath, real_root):
                continue
            if fname.endswith(".plist"):
                plists.append(fpath)
            elif fname.endswith(".service"):
                services.append(fpath)
            elif fname.endswith(".sh"):
                shells.append(fpath)
    return sorted(plists), sorted(services), sorted(shells)


def _resolve_mount_source(
    raw_src: str | None,
    search_dirs: list[Path],
    real_root: Path,
    shell_static_vars: dict[str, str] | None = None,
) -> Path | None:
    if not raw_src:
        return None
    cleaned = raw_src.strip()
    for pfx in ("${PWD}", "$PWD"):
        if cleaned == pfx:
            cleaned = "."
        elif cleaned.startswith(pfx + "/"):
            cleaned = "./" + cleaned[len(pfx) + 1 :]
    if shell_static_vars:
        def _sub_var(m: re.Match[str]) -> str:
            k = m.group(1) or m.group(2)
            return shell_static_vars.get(k, m.group(0))

        cleaned = re.sub(
            r"\$(?:\{([A-Za-z_][A-Za-z0-9_]*)\}|([A-Za-z_][A-Za-z0-9_]*))",
            _sub_var,
            cleaned,
        )
    return _resolve_contained_repo_path(cleaned, search_dirs, real_root)


def _effective_run_stage(
    inv: ContainerRunInvocation,
    parsed_df: ParsedDockerfile | None,
    env_bindings: dict[str, str],
    search_dirs: list[Path],
    real_root: Path,
    shell_static_vars: dict[str, str] | None = None,
) -> tuple[DockerStage | None, int, int]:
    """Build synthetic `DockerStage` and count `(readonly_binds, writable_binds)`."""
    base_stage = parsed_df.select_stage() if parsed_df is not None else None
    ro_binds = rw_binds = 0
    resolved_mounts: list[tuple[Path, str]] = []
    for ms in inv.mounts:
        if ms.kind != "bind":
            continue
        if ms.readonly:
            ro_binds += 1
        else:
            rw_binds += 1
        hpath = _resolve_mount_source(ms.source, search_dirs, real_root, shell_static_vars)
        if hpath is not None:
            resolved_mounts.append((hpath, ms.target))

    if base_stage is None and not inv.workdir and not env_bindings and not resolved_mounts:
        return None, ro_binds, rw_binds

    eff = (
        copy.deepcopy(base_stage)
        if base_stage is not None
        else DockerStage(index=0, name=None, base_image=inv.image or "scratch", line=inv.line)
    )
    if inv.workdir and not _VAR_TOKEN_RE.search(inv.workdir):
        eff.workdir = _norm_container_path(inv.workdir, eff.workdir)
    eff.env.update(env_bindings)
    for hpath, cont_tgt in resolved_mounts:
        repo_rel = "." if hpath.resolve() == real_root else hpath.resolve().relative_to(real_root).as_posix()
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
    return eff, ro_binds, rw_binds


def _extract_run_command_targets(
    inv: ContainerRunInvocation,
    stage: DockerStage | None,
) -> list[CommandTarget]:
    env = stage.env if stage is not None else {}
    wdir = stage.workdir if stage is not None else (inv.workdir or "/")
    targets: list[CommandTarget] = []
    entrypoint_cleared = inv.entrypoint == ""
    if inv.entrypoint is not None or inv.command_argv:
        ep_tokens = [inv.entrypoint] if inv.entrypoint else []
        cmd_tokens = list(inv.command_argv)
        if ep_tokens and cmd_tokens:
            targets.extend(extract_command_targets_from_argv([*ep_tokens, *cmd_tokens], env, wdir))
        if ep_tokens:
            targets.extend(extract_command_targets_from_argv(ep_tokens, env, wdir))
        if cmd_tokens:
            if (
                not ep_tokens
                and not entrypoint_cleared
                and stage is not None
                and stage.entrypoint is not None
                and stage.entrypoint.is_exec
            ):
                targets.extend(
                    extract_command_targets_from_argv([*stage.entrypoint.argv, *cmd_tokens], env, wdir)
                )
            targets.extend(extract_command_targets_from_argv(cmd_tokens, env, wdir))
            if len(cmd_tokens) == 1 and " " in cmd_tokens[0]:
                targets.extend(extract_command_targets_from_shell(cmd_tokens[0], env, wdir))
        return list(dict.fromkeys(targets))

    if stage is not None:
        return extract_stage_command_targets(stage)[0]
    return []


def _mark_target_referenced(tnode: AtlasNode, result: ManipulatorExtractionResult) -> None:
    result.findings[:] = [
        f for f in result.findings if not (f.rule_code == "MANIP-003" and f.node_id == tnode.id)
    ]
    if tnode.status == "unwired":
        tnode.status = "clean"
    if tnode.id.startswith("m:script:"):
        for stale in (
            " No source caller/reference discovered; external entry points remain unknown.",
            " Deployment references only; no execution caller discovered.",
        ):
            if tnode.summary.endswith(stale):
                tnode.summary = tnode.summary[: -len(stale)] + " Declared source caller/reference found."
                break


def _emit_helper_edge(
    eid: str,
    src_nid: str,
    tnode: AtlasNode,
    syms: tuple[str, ...],
    evidence_path: str,
    evidence_note: str,
    seen_edge_ids: set[str],
    existing_pairs: dict[tuple[str, str], AtlasEdge],
    result: ManipulatorExtractionResult,
) -> None:
    _mark_target_referenced(tnode, result)
    sym_links = effective_node_symbol_links(tnode.id, syms, result)
    pair = (src_nid, tnode.id)
    if pair in existing_pairs:
        prev_edge = existing_pairs[pair]
        if not prev_edge.symbol_links or not sym_links:
            prev_edge.symbol_links = []
        else:
            prev_edge.symbol_links = sorted(set(prev_edge.symbol_links) | set(sym_links))
        if (
            "host_install_path_unverified" in evidence_note
            and "host_install_path_unverified" not in prev_edge.evidence_note
        ):
            prev_edge.evidence_note = f"{prev_edge.evidence_note} (host_install_path_unverified)"
        return
    if eid in seen_edge_ids:
        return
    seen_edge_ids.add(eid)
    edge = AtlasEdge(
        id=eid,
        source_id=src_nid,
        target_id=tnode.id,
        kind="calls_helper",
        verification="declared",
        evidence_path=evidence_path,
        evidence_note=evidence_note,
        symbol_links=sym_links,
    )
    result.edges.append(edge)
    existing_pairs[pair] = edge


def _extract_shell_body_from_exec(argv: list[str]) -> str | None:
    cur = _unwrap_host_prefix(argv)
    if not cur:
        return None
    exe = PurePosixPath(cur[0]).name
    if exe not in {"sh", "bash", "zsh", "dash", "ksh", "ash"}:
        return None
    for idx, tok in enumerate(cur[1:], start=1):
        if tok == "--":
            break
        if tok.startswith("-") and "c" in tok[1:] and idx + 1 < len(cur):
            return cur[idx + 1]
    return None


def _discover_all_repo_scripts(real_root: Path) -> set[str]:
    found: set[str] = set()
    for parent, dirs, names in os.walk(real_root, followlinks=False):
        dirs[:] = [
            d
            for d in sorted(dirs)
            if d not in EXCLUDED_PARTS
            and not d.startswith(".")
            and not (Path(parent) / d).is_symlink()
            and _is_within_root(Path(parent) / d, real_root)
        ]
        for fname in sorted(names):
            if not fname.endswith((".py", ".sh", ".js", ".ts")):
                continue
            fp = Path(parent) / fname
            if not fp.is_symlink() and fp.is_file() and _is_within_root(fp, real_root):
                found.add(fp.resolve().relative_to(real_root).as_posix())
    return found


def _resolve_direct_host_targets(
    argv: list[str],
    env_bindings: dict[str, str],
    owner_rel: str,
    search_roots: list[Path],
    real_root: Path,
    by_src: dict[str, list[AtlasNode]],
    all_repo_scripts: set[str],
) -> list[tuple[str, tuple[str, ...], bool]]:
    candidates = set(by_src) | all_repo_scripts
    cmd_targets = extract_command_targets_from_argv(argv, env_bindings, None)
    triples = resolve_command_targets_with_symbols(
        cmd_targets, real_root, None, search_roots, candidates
    )
    resolved_map: dict[str, tuple[tuple[str, ...], bool]] = {
        rel: (syms, False) for rel, _, syms in triples
    }
    for ct in cmd_targets:
        if ct.kind not in ("file", "node_script"):
            continue
        raw_val = ct.value.strip().replace("\\", "/")
        norm_val = raw_val.removeprefix("./")
        sib_val = str(PurePosixPath(owner_rel).parent / norm_val)
        sref = source_reference(ct.value, owner_rel, candidates)
        if sref is not None:
            if sref not in resolved_map:
                is_suffix = norm_val not in candidates and sib_val not in candidates
                resolved_map[sref] = ((), is_suffix)
            continue
        if (
            norm_val.startswith("/")
            and "\x00" not in norm_val
            and "://" not in norm_val
            and ".." not in PurePosixPath(norm_val).parts
            and not re.search(r"[$~{}]", norm_val)
        ):
            leaf = PurePosixPath(norm_val).name
            if leaf != "__init__.py" and leaf.endswith((".py", ".sh", ".js", ".ts", ".mjs")):
                b_matches = sorted(p for p in candidates if p == leaf or p.endswith("/" + leaf))
                if len(b_matches) == 1 and b_matches[0] not in resolved_map:
                    resolved_map[b_matches[0]] = ((), True)
    return [(k, resolved_map[k][0], resolved_map[k][1]) for k in sorted(resolved_map)]


def augment_container_launchers(
    repo_root: Path,
    backend_subdir: str,
    result: ManipulatorExtractionResult,
    dockerfiles: dict[str, object] | None = None,
) -> None:
    """Inspect `launchd`, `systemd`, and `.sh` container launchers and emit static lineage."""
    from app.adapters.compose_sources import (
        classify_backing_image,
        discover_compose_files,
        parse_compose_file,
        policy_literal_sample,
    )

    plist_paths, systemd_paths, shell_paths = discover_launcher_files(repo_root)
    if not plist_paths and not systemd_paths and not shell_paths:
        return

    real_root = repo_root.resolve()
    if dockerfiles is not None:
        df_cache: dict[str, ParsedDockerfile] = {
            k: v for k, v in dockerfiles.items() if isinstance(v, ParsedDockerfile)
        }
    else:
        df_cache = {}
        df_files, _ = discover_dockerfiles(repo_root)
        for dfp in df_files:
            pdf = parse_dockerfile(dfp, repo_root)
            if pdf is not None:
                df_cache[pdf.rel_path] = pdf

    compose_img_to_df: dict[str, str] = {}
    compose_svc_to_df: dict[str, str] = {}
    for cpath in discover_compose_files(repo_root):
        pcf, _ = parse_compose_file(cpath, repo_root)
        if pcf is None:
            continue
        cdir = cpath.parent.resolve()
        for svc in pcf.services:
            if svc.build_context is None:
                continue
            ctx_dir = (cdir / svc.build_context).resolve()
            if not _is_within_root(ctx_dir, real_root) or not ctx_dir.is_dir():
                continue
            df_name = svc.build_dockerfile or "Dockerfile"
            df_cand = ctx_dir / df_name if (ctx_dir / df_name).is_file() else cdir / df_name
            if not df_cand.is_symlink() and df_cand.is_file() and _is_within_root(df_cand, real_root):
                drel = df_cand.resolve().relative_to(real_root).as_posix()
                compose_svc_to_df.setdefault(svc.name.lower(), drel)
                irepo, _ = _normalize_image_repo(svc.image)
                if irepo:
                    compose_img_to_df.setdefault(irepo, drel)

    by_src = index_nodes_by_source(result)
    node_by_id: dict[str, AtlasNode] = {n.id: n for n in result.nodes}
    seen_edge_ids: set[str] = {e.id for e in result.edges}
    existing_pairs: dict[tuple[str, str], AtlasEdge] = {
        (e.source_id, e.target_id): e for e in result.edges if e.kind == "calls_helper"
    }
    seen_env_findings: set[tuple[str, int, str]] = set()
    active_tokens = get_active_policy_tokens()
    all_repo_scripts = _discover_all_repo_scripts(real_root)

    bdir = (repo_root / backend_subdir).resolve() if backend_subdir else real_root
    base_fallbacks: list[Path] = [real_root]
    if _is_within_root(bdir, real_root) and bdir.is_dir() and bdir not in base_fallbacks:
        base_fallbacks.append(bdir)

    run_count = 0
    run_df_linked = 0
    run_ep_linked = 0
    total_ro_binds = 0
    total_rw_binds = 0
    unresolved_dynamic: list[str] = []
    unresolved_external: list[str] = []

    def _register_build_hint(
        btag: str, bdf_raw: str, bctx_raw: str, search_dirs: list[Path], out_map: dict[str, str]
    ) -> None:
        bctx_fs = _resolve_contained_repo_path(bctx_raw, search_dirs, real_root)
        df_dirs = [bctx_fs, *search_dirs] if bctx_fs is not None and bctx_fs.is_dir() else search_dirs
        bdf_fs = _resolve_contained_repo_path(bdf_raw, df_dirs, real_root)
        if bdf_fs is not None and bdf_fs.is_file():
            drel = bdf_fs.resolve().relative_to(real_root).as_posix()
            irepo, _ = _normalize_image_repo(btag)
            if irepo:
                out_map.setdefault(irepo, drel)
            if drel not in df_cache:
                pdf = parse_dockerfile(bdf_fs, repo_root)
                if pdf is not None:
                    df_cache[drel] = pdf

    repo_build_img_to_df: dict[str, str] = {}
    for sh_cand in shell_paths:
        try:
            if sh_cand.stat().st_size > MAX_UNIT_FILE_BYTES:
                continue
            sh_src = sh_cand.read_text(encoding="utf-8")
        except (OSError, UnicodeError):
            continue
        _, b_hints, _ = extract_shell_container_runs(sh_src)
        sh_dirs = list(dict.fromkeys([sh_cand.parent.resolve(), *base_fallbacks]))
        for btag, bdf_raw, bctx_raw in b_hints:
            _register_build_hint(btag, bdf_raw, bctx_raw, sh_dirs, repo_build_img_to_df)
    for sys_cand in systemd_paths:
        s_pre = parse_systemd_unit(sys_cand, repo_root)
        if s_pre is None:
            continue
        s_dirs = [sys_cand.parent.resolve()]
        if s_pre.working_dir:
            wd_pre = _resolve_contained_repo_path(s_pre.working_dir, [sys_cand.parent.resolve(), real_root], real_root)
            if wd_pre is not None and wd_pre.is_dir():
                s_dirs.insert(0, wd_pre)
        for bf in base_fallbacks:
            if bf not in s_dirs:
                s_dirs.append(bf)
        for espec_pre in s_pre.exec_commands:
            bh_sys = _extract_build_hint(_unwrap_host_prefix(list(espec_pre.argv)))
            if bh_sys is not None:
                _register_build_hint(bh_sys[0], bh_sys[1], bh_sys[2], s_dirs, repo_build_img_to_df)

    def _handle_run_invocation(
        inv: ContainerRunInvocation,
        owner_node: AtlasNode,
        owner_rel: str,
        edge_prefix: str,
        unit_env: dict[str, str],
        search_dirs: list[Path],
        build_img_to_df: dict[str, str],
        shell_static_vars: dict[str, str] | None = None,
    ) -> bool:
        nonlocal run_count, run_df_linked, run_ep_linked, total_ro_binds, total_rw_binds
        run_count += 1
        linked_any = False

        if inv.unresolved_flag:
            note_flag = f"{owner_rel}:{inv.line} [unknown flag {inv.unresolved_flag}]"
            if note_flag not in unresolved_dynamic:
                unresolved_dynamic.append(note_flag)
            return False

        merged_env = dict(unit_env)
        for ef_raw, _ in inv.env_files:
            ef_bindings = _parse_and_audit_env_file(
                ef_raw,
                search_dirs,
                real_root,
                owner_node,
                active_tokens,
                policy_literal_sample,
                seen_env_findings,
                result.findings,
                notes_out=result.notes,
            )
            merged_env.update(ef_bindings)

        inline_bindings = _audit_inline_env_assignments(
            inv.env,
            owner_node,
            owner_rel,
            f"`{inv.cli} run` flag",
            active_tokens,
            policy_literal_sample,
            result.findings,
            shell_static_vars=shell_static_vars,
        )
        merged_env.update(inline_bindings)

        eff_build_map = {**repo_build_img_to_df, **build_img_to_df}
        df_rel, parsed_df, dyn_note, ext_note = _match_dockerfile_for_run(
            inv.image,
            owner_rel,
            df_cache,
            compose_img_to_df,
            compose_svc_to_df,
            eff_build_map,
            classify_backing_image,
            shell_static_vars=shell_static_vars,
        )
        if dyn_note and dyn_note not in unresolved_dynamic:
            unresolved_dynamic.append(dyn_note)
        if ext_note and ext_note not in unresolved_external:
            unresolved_external.append(ext_note)

        if df_rel is not None:
            linked_any = True
            run_df_linked += 1
            df_nid = f"m:dockerfile:{df_rel}"
            if df_nid not in node_by_id:
                df_node = AtlasNode(
                    id=df_nid,
                    tier="manipulate",
                    subkind="cli",
                    label=PurePosixPath(df_rel).name if "/" not in df_rel else df_rel,
                    source_file=df_rel,
                    cluster="containers",
                    summary="Container build declaration; image build and runtime execution are not observed.",
                )
                result.nodes.append(df_node)
                node_by_id[df_nid] = df_node
            eid = f"{edge_prefix}:{owner_rel}->dockerfile:{df_rel}"
            _emit_helper_edge(
                eid,
                owner_node.id,
                node_by_id[df_nid],
                (),
                f"{owner_rel}:{inv.line}",
                f"Host launcher `{inv.cli} run` maps image `{inv.image}` to `{df_rel}`; container runtime is not observed.",
                seen_edge_ids,
                existing_pairs,
                result,
            )

        eff_stage, ro_cnt, rw_cnt = _effective_run_stage(
            inv, parsed_df, merged_env, search_dirs, real_root, shell_static_vars
        )
        total_ro_binds += ro_cnt
        total_rw_binds += rw_cnt

        cmd_targets = _extract_run_command_targets(inv, eff_stage)
        if not cmd_targets:
            return linked_any

        froots: list[Path] = []
        if parsed_df is not None and parsed_df.context_root not in froots:
            froots.append(parsed_df.context_root)
        for sd in (*search_dirs, *base_fallbacks):
            if sd not in froots:
                froots.append(sd)

        triples = resolve_command_targets_with_symbols(
            cmd_targets, real_root, eff_stage, froots, set(by_src) | all_repo_scripts
        )
        ep_hit_here = False
        for repo_rel, _, syms in triples:
            if repo_rel == owner_rel:
                continue
            tnodes = ensure_repo_target_nodes(
                repo_rel, real_root, result, by_src, eff_stage, froots, seen_edge_ids
            )
            for tnode in tnodes:
                node_by_id.setdefault(tnode.id, tnode)
                linked_any = True
                ep_hit_here = True
                eid = f"{edge_prefix}:{owner_rel}->{tnode.id}"
                _emit_helper_edge(
                    eid,
                    owner_node.id,
                    tnode,
                    syms,
                    f"{owner_rel}:{inv.line}",
                    f"Host launcher `{inv.cli} run` command resolves to `{repo_rel}`; container runtime is not observed.",
                    seen_edge_ids,
                    existing_pairs,
                    result,
                )
        if ep_hit_here:
            run_ep_linked += 1
        return linked_any

    created_launchd_count = 0
    created_launchd_linked = 0
    created_launchd_unresolved = 0

    for ppath in plist_paths:
        punit, err_note = parse_launchd_plist(ppath, repo_root)
        if err_note and err_note not in result.notes:
            result.notes.append(err_note)
        if punit is None:
            continue
        rel = punit.rel_path
        nid = f"m:launchd:{rel}"
        already_had_node = nid in node_by_id
        cmd_line = punit.program_line if punit.program else (punit.arg_lines[0] if punit.arg_lines else 1)

        eff_argv = (
            [punit.program, *punit.program_args[1:]]
            if punit.program and punit.program_args
            else ([punit.program] if punit.program else list(punit.program_args))
        )
        plist_runs: list[ContainerRunInvocation] = []
        plist_sh_vars: dict[str, str] | None = None
        plist_build_map: dict[str, str] = {}
        direct_inv = parse_container_run_argv(eff_argv, line=cmd_line)
        if direct_inv is not None:
            plist_runs.append(direct_inv)
        else:
            sh_body = _extract_shell_body_from_exec(eff_argv)
            if sh_body:
                sh_invs, _, sh_vars = extract_shell_container_runs(sh_body)
                if sh_invs:
                    plist_runs.extend(
                        ContainerRunInvocation(
                            cli=si.cli,
                            line=cmd_line,
                            image=si.image,
                            command_argv=si.command_argv,
                            entrypoint=si.entrypoint,
                            workdir=si.workdir,
                            rm=si.rm,
                            read_only_rootfs=si.read_only_rootfs,
                            network=si.network,
                            env=tuple(EnvAssignment(e.key, e.value, cmd_line) for e in si.env),
                            env_files=tuple((ef, cmd_line) for ef, _ in si.env_files),
                            mounts=si.mounts,
                            raw_argv=si.raw_argv,
                            unresolved_flag=si.unresolved_flag,
                        )
                        for si in sh_invs
                    )
                    plist_sh_vars = sh_vars

        if already_had_node:
            lnode = node_by_id[nid]
        else:
            created_launchd_count += 1
            lnode = AtlasNode(
                id=nid,
                tier="manipulate",
                subkind="cli",
                label=ppath.stem,
                source_file=rel,
                line=cmd_line,
                cluster="launchd",
                summary=(
                    ("Disabled launchd declaration. " if punit.disabled else "Launchd command declaration. ")
                    + "Source presence does not establish host installation, admission, or liveness."
                ),
            )
            result.nodes.append(lnode)
            node_by_id[nid] = lnode

        p_env = _audit_inline_env_assignments(
            punit.environment,
            lnode,
            rel,
            "Launchd `EnvironmentVariables`",
            active_tokens,
            policy_literal_sample,
            result.findings,
        )
        _check_launchd_exec_expansion(
            punit, nid, already_had_node, bool(plist_runs), result.findings
        )

        p_search = list(dict.fromkeys([ppath.parent.resolve(), *base_fallbacks]))
        p_linked = False
        if plist_runs:
            for rinv in plist_runs:
                if _handle_run_invocation(
                    rinv, lnode, rel, "e:launchd", p_env, p_search, plist_build_map, plist_sh_vars
                ):
                    p_linked = True
        elif not already_had_node and eff_argv:
            unwrapped = _unwrap_host_prefix(eff_argv)
            if unwrapped and PurePosixPath(unwrapped[0]).name not in CONTAINER_CLI_BINARIES:
                for repo_rel, syms, via_suffix in _resolve_direct_host_targets(
                    eff_argv, p_env, rel, p_search, real_root, by_src, all_repo_scripts
                ):
                    for tnode in ensure_repo_target_nodes(
                        repo_rel, real_root, result, by_src, None, p_search, seen_edge_ids
                    ):
                        node_by_id.setdefault(tnode.id, tnode)
                        p_linked = True
                        l_note = (
                            f"Launchd command suffix-matches `{repo_rel}` (`host_install_path_unverified`); "
                            "host installation path, launchd admission, and execution are not observed."
                            if via_suffix
                            else "Launchd command resolves to this repository source; host admission and execution are not observed."
                        )
                        _emit_helper_edge(
                            f"e:launchd:{rel}->{tnode.id}",
                            nid,
                            tnode,
                            syms,
                            f"{rel}:{cmd_line}",
                            l_note,
                            seen_edge_ids,
                            existing_pairs,
                            result,
                        )
        if not already_had_node:
            if p_linked:
                created_launchd_linked += 1
            else:
                created_launchd_unresolved += 1

    systemd_count = 0
    systemd_linked = 0
    systemd_unresolved = 0

    for spath in systemd_paths:
        sunit = parse_systemd_unit(spath, repo_root, notes_out=result.notes)
        if sunit is None:
            continue
        systemd_count += 1
        rel = sunit.rel_path
        nid = f"m:systemd:{rel}"
        desc_part = f"`{sunit.description}`" if sunit.description else f"`{PurePosixPath(rel).name}`"
        if nid in node_by_id:
            snode = node_by_id[nid]
        else:
            snode = AtlasNode(
                id=nid,
                tier="manipulate",
                subkind="cli",
                label=PurePosixPath(rel).name,
                source_file=rel,
                line=sunit.line,
                cluster="systemd",
                summary=(
                    f"Systemd service unit ({desc_part}). "
                    "Static unit declaration; host installation, systemd admission, and runtime liveness are not observed."
                ),
            )
            result.nodes.append(snode)
            node_by_id[nid] = snode

        s_search: list[Path] = [spath.parent.resolve()]
        if sunit.working_dir:
            wd_fs = _resolve_contained_repo_path(
                sunit.working_dir, [spath.parent.resolve(), real_root], real_root
            )
            if wd_fs is not None and wd_fs.is_dir() and wd_fs not in s_search:
                s_search.insert(0, wd_fs)
        for bf in base_fallbacks:
            if bf not in s_search:
                s_search.append(bf)

        s_env: dict[str, str] = {}
        for ef_raw, _, _ in sunit.env_files:
            s_env.update(
                _parse_and_audit_env_file(
                    ef_raw,
                    s_search,
                    real_root,
                    snode,
                    active_tokens,
                    policy_literal_sample,
                    seen_env_findings,
                    result.findings,
                    notes_out=result.notes,
                )
            )
        s_env.update(
            _audit_inline_env_assignments(
                sunit.environment,
                snode,
                rel,
                "Systemd `Environment=`",
                active_tokens,
                policy_literal_sample,
                result.findings,
            )
        )
        _check_systemd_exec_expansion(sunit, nid, result.findings)

        s_linked = False
        for espec in sunit.exec_commands:
            argv_list = _substitute_systemd_env(list(espec.argv), s_env)
            rinv = parse_container_run_argv(argv_list, line=espec.line)
            if rinv is not None:
                if _handle_run_invocation(rinv, snode, rel, "e:systemd", s_env, s_search, {}, s_env):
                    s_linked = True
                continue
            sh_body = _extract_shell_body_from_exec(argv_list)
            if sh_body:
                sh_invs, _, sh_vars = extract_shell_container_runs(sh_body)
                if sh_invs:
                    eff_sh_vars = {**s_env, **sh_vars}
                    for si in sh_invs:
                        adj = ContainerRunInvocation(
                            cli=si.cli,
                            line=espec.line,
                            image=si.image,
                            command_argv=si.command_argv,
                            entrypoint=si.entrypoint,
                            workdir=si.workdir,
                            rm=si.rm,
                            read_only_rootfs=si.read_only_rootfs,
                            network=si.network,
                            env=tuple(EnvAssignment(e.key, e.value, espec.line) for e in si.env),
                            env_files=tuple((ef, espec.line) for ef, _ in si.env_files),
                            mounts=si.mounts,
                            raw_argv=si.raw_argv,
                            unresolved_flag=si.unresolved_flag,
                        )
                        if _handle_run_invocation(adj, snode, rel, "e:systemd", s_env, s_search, {}, eff_sh_vars):
                            s_linked = True
                    continue
            unwrapped = _unwrap_host_prefix(argv_list)
            if unwrapped and PurePosixPath(unwrapped[0]).name in CONTAINER_CLI_BINARIES:
                continue
            for repo_rel, syms, via_suffix in _resolve_direct_host_targets(
                argv_list, s_env, rel, s_search, real_root, by_src, all_repo_scripts
            ):
                if repo_rel == rel:
                    continue
                for tnode in ensure_repo_target_nodes(
                    repo_rel, real_root, result, by_src, None, s_search, seen_edge_ids
                ):
                    node_by_id.setdefault(tnode.id, tnode)
                    s_linked = True
                    s_note = (
                        f"Systemd `{espec.directive}` suffix-matches `{repo_rel}` (`host_install_path_unverified`); "
                        "host installation path, systemd admission, and service liveness are not observed."
                        if via_suffix
                        else f"Systemd `{espec.directive}` resolves to `{repo_rel}`; host admission and service liveness are not observed."
                    )
                    _emit_helper_edge(
                        f"e:systemd:{rel}->{tnode.id}",
                        nid,
                        tnode,
                        syms,
                        f"{rel}:{espec.line}",
                        s_note,
                        seen_edge_ids,
                        existing_pairs,
                        result,
                    )
        if s_linked:
            systemd_linked += 1
        else:
            systemd_unresolved += 1

    for sh_path in shell_paths:
        sh_rel = sh_path.resolve().relative_to(real_root).as_posix()
        try:
            if sh_path.stat().st_size > MAX_UNIT_FILE_BYTES:
                skip_note = (
                    f"Skipped shell script {sh_rel} (exceeds {MAX_UNIT_FILE_BYTES} bytes); "
                    "container launcher command evidence absent."
                )
                if skip_note not in result.notes:
                    result.notes.append(skip_note)
                continue
            sh_text = sh_path.read_text(encoding="utf-8")
        except (OSError, UnicodeError):
            skip_note = f"Skipped shell script {sh_rel} (unreadable or non-UTF-8); container launcher command evidence absent."
            if skip_note not in result.notes:
                result.notes.append(skip_note)
            continue
        invocations, build_hints, static_vars = extract_shell_container_runs(sh_text)
        for missed_ln in _find_unparsed_shell_cli_lines(sh_text, invocations):
            unparsed_note = (
                f"Shell launcher coverage note: `{sh_rel}:{missed_ln}` mentions a container CLI `run` "
                "command in a dynamic or unsupported shell form; invocation was not resolved statically."
            )
            if unparsed_note not in result.notes:
                result.notes.append(unparsed_note)
        if not invocations:
            continue
        sh_dir = sh_path.parent.resolve()
        sh_search = list(dict.fromkeys([sh_dir, *base_fallbacks]))

        build_img_to_df: dict[str, str] = {}
        for btag, bdf_raw, bctx_raw in build_hints:
            bctx_fs = _resolve_contained_repo_path(bctx_raw, sh_search, real_root)
            df_dirs = [bctx_fs, *sh_search] if bctx_fs is not None and bctx_fs.is_dir() else sh_search
            bdf_fs = _resolve_contained_repo_path(bdf_raw, df_dirs, real_root)
            if bdf_fs is not None and bdf_fs.is_file():
                drel = bdf_fs.resolve().relative_to(real_root).as_posix()
                irepo, _ = _normalize_image_repo(btag)
                if irepo:
                    build_img_to_df.setdefault(irepo, drel)
                if drel not in df_cache:
                    pdf = parse_dockerfile(bdf_fs, repo_root)
                    if pdf is not None:
                        df_cache[drel] = pdf

        existing_sh_nodes = by_src.get(sh_rel)
        sh_nid = f"m:script:{sh_rel}"
        if existing_sh_nodes:
            sh_node = existing_sh_nodes[0]
        elif sh_nid in node_by_id:
            sh_node = node_by_id[sh_nid]
        else:
            sh_node = AtlasNode(
                id=sh_nid,
                tier="manipulate",
                subkind="cli",
                label=PurePosixPath(sh_rel).name,
                source_file=sh_rel,
                line=invocations[0].line,
                cluster="containers",
                summary=(
                    "Shell container launcher script. "
                    "Static CLI declaration; shell execution and container runtime liveness are not observed."
                ),
            )
            result.nodes.append(sh_node)
            node_by_id[sh_nid] = sh_node
            by_src[sh_rel] = [sh_node]

        for inv in invocations:
            _handle_run_invocation(
                inv,
                sh_node,
                sh_rel,
                "e:script",
                {},
                sh_search,
                build_img_to_df,
                static_vars,
            )

    if created_launchd_count:
        result.notes.append(
            f"Launchd source coverage: {created_launchd_count} declaration(s), "
            f"{created_launchd_linked} with source/container references, "
            f"{created_launchd_unresolved} with external or unresolved commands. "
            "Host installation, launchd admission, and service liveness are not observed."
        )

    if systemd_count:
        result.notes.append(
            f"Systemd unit source coverage: {systemd_count} unit(s), "
            f"{systemd_linked} linked to repository entrypoints/Dockerfiles, "
            f"{systemd_unresolved} with external or unresolved commands. "
            "Host installation, systemd admission, and service liveness are not observed."
        )

    if run_count:
        dyn_txt = ", ".join(unresolved_dynamic) if unresolved_dynamic else "none"
        ext_txt = ", ".join(unresolved_external) if unresolved_external else "none"
        result.notes.append(
            f"Container CLI launcher coverage: {run_count} `run` invocation(s), "
            f"{run_df_linked} Dockerfile-linked, {run_ep_linked} entrypoint-linked, "
            f"bind mount(s): {total_ro_binds} read-only / {total_rw_binds} writable, "
            f"unresolved dynamic image reference(s): {dyn_txt}, "
            f"unresolved external/digest-pinned image(s): {ext_txt}. "
            "Container daemon state, micro-VM runtime, and external image registries are not observed."
        )
