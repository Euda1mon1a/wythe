"""Static `Z=0` port/bind extraction and host listener occupancy (`PORT-001`, `PORT-002`)."""

from __future__ import annotations

import ast
import json
import os
import plistlib
import re
import shutil
import subprocess
from collections.abc import Mapping, Sequence
from dataclasses import asdict, dataclass
from datetime import UTC, datetime
from pathlib import Path
from typing import Any, Literal
from xml.parsers import expat

from wythe_plugin_wiretap.otel_ebpf import (
    MAX_WIRETAP_BYTES,
    _check_safe_path_segments,
    ensure_json_depth_bounded,
    read_bounded_regular_bytes,
    validate_non_symlink_path,
)

MAX_PLIST_BYTES = 1 * 1024 * 1024
MAX_TOTAL_PORT_ENTRIES = 4096
_SKIP_REPO_DIRS: frozenset[str] = frozenset(
    {".git", "node_modules", ".venv", "venv", "__pycache__", ".next", "out", "tests", "Tests"}
)
_XML_BUILTIN_ENTITIES: frozenset[str] = frozenset({"amp", "lt", "gt", "apos", "quot"})
_APPLE_PLIST_DOCTYPE_RE = re.compile(
    r"<!DOCTYPE\s+plist\s+PUBLIC\s+"
    r'"-//Apple(?:\s+Computer)?//DTD\s+PLIST\s+1\.0//EN"\s+'
    r'"https?://www\.apple\.com/DTDs/PropertyList-1\.0\.dtd"\s*>',
    re.IGNORECASE,
)
_FORBIDDEN_XML_DECL_RE = re.compile(
    r"<!\s*(?:DOCTYPE|ENTITY|ELEMENT|ATTLIST|NOTATION)\b",
    re.IGNORECASE,
)
_ENTITY_REF_RE = re.compile(r"&([A-Za-z_][A-Za-z0-9_.-]*);")
_RUN_PUBLISH_FLAG_RE = re.compile(
    r"\b(?:container|docker|podman)\s+run\b[^\r\n]{0,240}?(?:-p|--publish)\s+['\"]?([A-Za-z0-9_.:*\[\]-]+)['\"]?"
)
_DOCKERFILE_EXPOSE_RE = re.compile(r"^\s*EXPOSE\s+(.+)$", re.IGNORECASE)
_UVICORN_CLI_PORT_RE = re.compile(r"\buvicorn\b[^\r\n]{0,200}")

PortClassification = Literal[
    "corroborated",
    "squatter_conflict",
    "bind_exposure_drift",
    "dark_listener",
    "unlistening_declared",
]


@dataclass(frozen=True)
class DeclaredPortSpec:
    """Static `Z=0` port and optional bind expectation extracted from repository files."""

    port: int
    protocol: str
    expected_bind: str | None
    process_hint: str
    declaration_kind: str
    source_file: str
    line: int
    node_id: str | None = None


@dataclass(frozen=True)
class ObservedPortListener:
    """Single runtime TCP/UDP listener entry from recorded `lsof`/`ss`/JSON or opt-in probe."""

    port: int
    protocol: str
    bind_address: str
    normalized_bind: Literal["loopback", "wildcard", "specific"]
    command: str
    pid: int
    user: str = "[REDACTED_USER]"
    source_format: str = "json"


def normalize_bind_category(raw_bind: str | None) -> Literal["loopback", "wildcard", "specific"] | None:
    """Classify a bind address into `'loopback'`, `'wildcard'`, or `'specific'`."""
    if raw_bind is None:
        return None
    b = raw_bind.strip().strip("[]").lower()
    if not b:
        return None
    if b in ("127.0.0.1", "localhost", "::1", "::ffff:127.0.0.1") or b.startswith("127."):
        return "loopback"
    if b in ("0.0.0.0", "*", "::", "0.0.0.0/0", "::/0"):
        return "wildcard"
    return "specific"


def canonical_bind_ip(raw_bind: str | None) -> str | None:
    """Return canonical `'127.0.0.1'`, `'0.0.0.0'`, or cleaned interface IP."""
    cat = normalize_bind_category(raw_bind)
    if cat == "loopback":
        return "127.0.0.1"
    if cat == "wildcard":
        return "0.0.0.0"
    return raw_bind.strip() if raw_bind else None


def _safe_scalar_str(val: Any) -> str:
    if isinstance(val, str):
        return val
    if isinstance(val, (int, float)) and not isinstance(val, bool):
        if isinstance(val, int) and val.bit_length() > 128:
            return ""
        try:
            return str(val)
        except ValueError:
            return ""
    return ""


def parse_safe_plist_xml(raw_bytes: bytes) -> dict[str, Any]:
    """Parse an XML `.plist` safely while rejecting XXE `<!ENTITY`/`<!DOCTYPE` payloads."""
    if len(raw_bytes) > MAX_PLIST_BYTES:
        raise ValueError(f"Plist exceeds {MAX_PLIST_BYTES}-byte limit.")
    if raw_bytes.startswith(b"bplist"):
        raise ValueError("Binary plist rejected; expected XML launchd plist.")
    text = raw_bytes.decode("utf-8-sig").strip("\x00 \t\r\n")
    if not text:
        return {}
    if "\x00" in text:
        raise ValueError("Refusing XML plist containing embedded NUL bytes.")
    stripped = _APPLE_PLIST_DOCTYPE_RE.sub("", text, count=1)
    if _FORBIDDEN_XML_DECL_RE.search(stripped):
        raise ValueError("Refusing XML plist with forbidden DOCTYPE/ENTITY declaration (XXE).")
    for ent in _ENTITY_REF_RE.finditer(stripped):
        if ent.group(1) not in _XML_BUILTIN_ENTITIES:
            raise ValueError(f"Refusing XML plist with custom entity '&{ent.group(1)};' (XXE).")

    depth = 0
    count = 0
    guard = expat.ParserCreate("UTF-8")

    def _forbid(*_a: object) -> None:
        raise ValueError("Refusing XML plist DTD/entity construct (XXE protection).")

    def _start(_n: str, _at: dict[str, str]) -> None:
        nonlocal depth, count
        depth += 1
        count += 1
        if depth > 32 or count > 4096:
            raise ValueError("Refusing excessively nested XML plist.")

    def _end(_n: str) -> None:
        nonlocal depth
        depth = max(0, depth - 1)

    guard.StartDoctypeDeclHandler = _forbid
    guard.EntityDeclHandler = _forbid
    guard.ExternalEntityRefHandler = lambda *_a: (_ for _ in ()).throw(ValueError("XXE"))
    guard.StartElementHandler = _start
    guard.EndElementHandler = _end
    guard.Parse(stripped.encode("utf-8"), True)
    try:
        parsed = plistlib.loads(stripped.encode("utf-8"), fmt=plistlib.FMT_XML)
    except (OverflowError, RecursionError) as exc:
        raise ValueError("Refusing malformed or oversized XML plist scalar.") from exc
    return {_safe_scalar_str(k): v for k, v in parsed.items() if isinstance(k, str)} if isinstance(parsed, dict) else {}


def _parse_publish_spec(spec_str: str) -> tuple[str | None, int | None, str]:
    """Parse Docker/Compose/container publish spec `[ip:]host_port[:container_port][/proto]`."""
    raw = spec_str.strip().strip("'\"")
    proto = "tcp"
    if "/" in raw:
        raw, p_tail = raw.rsplit("/", 1)
        proto = p_tail.lower() or "tcp"
    # Handle bracketed IPv6 `[::1]:8080:8080`
    if raw.startswith("[") and "]:" in raw:
        ip_part, rest = raw[1:].split("]:", 1)
        host_p = rest.split(":", 1)[0]
        return (
            canonical_bind_ip(ip_part),
            (int(host_p) if host_p.isascii() and host_p.isdigit() and len(host_p) <= 5 else None),
            proto,
        )
    parts = raw.split(":")
    if len(parts) == 3:
        return (
            canonical_bind_ip(parts[0]),
            (int(parts[1]) if parts[1].isascii() and parts[1].isdigit() and len(parts[1]) <= 5 else None),
            proto,
        )
    if len(parts) == 2:
        return (
            None,
            (int(parts[0]) if parts[0].isascii() and parts[0].isdigit() and len(parts[0]) <= 5 else None),
            proto,
        )
    if len(parts) == 1 and parts[0].isascii() and parts[0].isdigit() and len(parts[0]) <= 5:
        return None, int(parts[0]), proto
    return None, None, proto


def _parse_cli_uvicorn_flags(cmd_text: str) -> tuple[str | None, int | None]:
    tokens = cmd_text.replace("=", " ").split()
    host: str | None = "127.0.0.1"
    port: int | None = None
    for idx, tok in enumerate(tokens):
        if tok == "--host" and idx + 1 < len(tokens):
            host = canonical_bind_ip(tokens[idx + 1].strip("'\""))
        elif tok == "--port" and idx + 1 < len(tokens):
            p_raw = tokens[idx + 1].strip("'\"")
            if p_raw.isascii() and p_raw.isdigit() and len(p_raw) <= 5:
                port = int(p_raw)
    return host, port


def _load_yaml_docs(text: str) -> list[Any]:
    try:
        import yaml  # type: ignore[import-untyped]
    except ImportError:
        return []
    max_nodes = 4096
    max_depth = 64

    class _BoundedSafeLoader(yaml.SafeLoader):  # type: ignore[misc, name-defined]
        def __init__(self, stream: Any) -> None:
            super().__init__(stream)
            self._node_count = 0
            self._alias_count = 0
            self._merge_steps = 0
            self._cur_depth = 0

        def compose_node(self, parent: Any, index: Any) -> Any:
            if self.check_event(yaml.AliasEvent):
                self._alias_count += 1
                if (self._node_count + self._alias_count) > max_nodes:
                    raise yaml.YAMLError(
                        f"YAML alias expansion exceeds budget ({max_nodes})."
                    )
                return super().compose_node(parent, index)
            self._node_count += 1
            if (self._node_count + self._alias_count) > max_nodes:
                raise yaml.YAMLError(f"YAML node count exceeds budget ({max_nodes}).")
            self._cur_depth += 1
            if self._cur_depth > max_depth:
                raise yaml.YAMLError(
                    f"YAML structure exceeds maximum nesting depth ({max_depth})."
                )
            try:
                return super().compose_node(parent, index)
            finally:
                self._cur_depth -= 1

        def flatten_mapping(self, node: Any) -> None:
            self._merge_steps += 1
            if self._merge_steps > max_nodes:
                raise yaml.YAMLError(
                    f"YAML mapping merge exceeds budget ({max_nodes})."
                )
            raw_pairs = getattr(node, "value", ())
            projected = len(raw_pairs)
            if projected > max_nodes:
                raise yaml.YAMLError(
                    f"YAML merged mapping exceeds budget ({max_nodes})."
                )
            for k_node, v_node in raw_pairs:
                if getattr(k_node, "tag", "") == "tag:yaml.org,2002:merge":
                    if isinstance(v_node, yaml.MappingNode):
                        self.flatten_mapping(v_node)
                        projected += len(v_node.value)
                    elif isinstance(v_node, yaml.SequenceNode):
                        for subnode in v_node.value:
                            if isinstance(subnode, yaml.MappingNode):
                                self.flatten_mapping(subnode)
                                projected += len(subnode.value)
                    if projected > max_nodes:
                        raise yaml.YAMLError(
                            f"YAML merged mapping exceeds budget ({max_nodes})."
                        )
            super().flatten_mapping(node)
            if len(getattr(node, "value", ())) > max_nodes:
                raise yaml.YAMLError(
                    f"YAML merged mapping exceeds budget ({max_nodes})."
                )

        def construct_yaml_int(self, node: Any) -> int:
            if isinstance(node.value, str) and len(node.value) > 4096:
                raise yaml.YAMLError("YAML integer exceeds maximum bit length")
            val = super().construct_yaml_int(node)
            if isinstance(val, int) and not isinstance(val, bool) and val.bit_length() > 4096:
                raise yaml.YAMLError("YAML integer exceeds maximum bit length")
            return val

    _BoundedSafeLoader.add_constructor(  # type: ignore[attr-defined]
        "tag:yaml.org,2002:int", _BoundedSafeLoader.construct_yaml_int
    )

    try:
        return [d for d in yaml.load_all(text, Loader=_BoundedSafeLoader) if d is not None]
    except (yaml.YAMLError, RecursionError, ValueError):
        return []


def _extract_python_ports(text: str, rel_path: str, node_id: str | None) -> list[DeclaredPortSpec]:
    try:
        tree = ast.parse(text)
    except (SyntaxError, ValueError, RecursionError):
        return []
    consts: dict[str, int | str] = {}
    for stmt in tree.body:
        if (
            isinstance(stmt, ast.Assign)
            and len(stmt.targets) == 1
            and isinstance(stmt.targets[0], ast.Name)
            and isinstance(stmt.value, ast.Constant)
            and isinstance(stmt.value.value, (int, str))
            and not isinstance(stmt.value.value, bool)
        ):
            consts[stmt.targets[0].id] = stmt.value.value

    def _val(expr: ast.AST | None) -> int | str | None:
        if isinstance(expr, ast.Constant) and isinstance(expr.value, (int, str)) and not isinstance(expr.value, bool):
            return expr.value
        if isinstance(expr, ast.Name) and expr.id in consts:
            return consts[expr.id]
        return None

    out: list[DeclaredPortSpec] = []
    for node in ast.walk(tree):
        if not isinstance(node, ast.Call):
            continue
        fn_name = (
            node.func.attr
            if isinstance(node.func, ast.Attribute)
            else (node.func.id if isinstance(node.func, ast.Name) else "")
        )
        recv_name = (
            node.func.value.id
            if isinstance(node.func, ast.Attribute) and isinstance(node.func.value, ast.Name)
            else ""
        )
        if (recv_name == "uvicorn" and fn_name == "run") or fn_name in ("Config", "start_server"):
            kw_map = {kw.arg: _val(kw.value) for kw in node.keywords if kw.arg}
            port_v = kw_map.get("port")
            host_v = kw_map.get("host")
            if isinstance(port_v, int) and not isinstance(port_v, bool) and 1 <= port_v <= 65535:
                exp_bind = canonical_bind_ip(str(host_v)) if isinstance(host_v, str) else "127.0.0.1"
                out.append(
                    DeclaredPortSpec(
                        port=port_v,
                        protocol="tcp",
                        expected_bind=exp_bind,
                        process_hint="uvicorn" if recv_name == "uvicorn" or fn_name == "Config" else "python",
                        declaration_kind="python_server",
                        source_file=rel_path,
                        line=getattr(node, "lineno", 1),
                        node_id=node_id,
                    )
                )
        elif fn_name in ("HTTPServer", "ThreadingHTTPServer", "TCPServer", "ThreadingTCPServer") and node.args:
            addr = node.args[0]
            if isinstance(addr, (ast.Tuple, ast.List)) and len(addr.elts) == 2:
                h_v = _val(addr.elts[0])
                p_v = _val(addr.elts[1])
                if isinstance(p_v, int) and not isinstance(p_v, bool) and 1 <= p_v <= 65535:
                    exp_bind = canonical_bind_ip(str(h_v) if h_v != "" else "0.0.0.0") if isinstance(h_v, str) else None
                    out.append(
                        DeclaredPortSpec(
                            port=p_v,
                            protocol="tcp",
                            expected_bind=exp_bind,
                            process_hint="python",
                            declaration_kind="python_http_server",
                            source_file=rel_path,
                            line=getattr(node, "lineno", 1),
                            node_id=node_id,
                        )
                    )
    return out


def _extract_yaml_ports(text: str, rel_path: str, fname_low: str, node_id: str | None) -> list[DeclaredPortSpec]:
    out: list[DeclaredPortSpec] = []
    docs = _load_yaml_docs(text)
    is_compose_name = "compose" in fname_low
    steps = 0
    for doc in docs:
        if len(out) >= MAX_TOTAL_PORT_ENTRIES or steps >= MAX_TOTAL_PORT_ENTRIES:
            break
        steps += 1
        if not isinstance(doc, Mapping):
            continue
        if isinstance(doc.get("services"), Mapping):
            for svc_name, svc_cfg in doc["services"].items():
                if len(out) >= MAX_TOTAL_PORT_ENTRIES or steps >= MAX_TOTAL_PORT_ENTRIES:
                    break
                steps += 1
                if not isinstance(svc_cfg, Mapping):
                    continue
                raw_ports = svc_cfg.get("ports")
                if not isinstance(raw_ports, list):
                    raw_ports = []
                for p_entry in raw_ports:
                    if len(out) >= MAX_TOTAL_PORT_ENTRIES or steps >= MAX_TOTAL_PORT_ENTRIES:
                        break
                    steps += 1
                    if isinstance(p_entry, (str, int)) and not isinstance(p_entry, bool):
                        p_scalar = _safe_scalar_str(p_entry)
                        b_ip, h_port, proto = _parse_publish_spec(p_scalar)
                        if h_port and 1 <= h_port <= 65535:
                            out.append(
                                DeclaredPortSpec(
                                    port=h_port,
                                    protocol=proto,
                                    expected_bind=b_ip,
                                    process_hint=_safe_scalar_str(svc_name) or "compose-service",
                                    declaration_kind="compose_ports",
                                    source_file=rel_path,
                                    line=1,
                                    node_id=node_id,
                                )
                            )
                    elif isinstance(p_entry, Mapping):
                        pub = p_entry.get("published") or p_entry.get("target")
                        if isinstance(pub, int) and not isinstance(pub, bool) and 1 <= pub <= 65535:
                            raw_proto = _safe_scalar_str(p_entry.get("protocol")).strip().lower() or "tcp"
                            raw_hip = _safe_scalar_str(p_entry.get("host_ip")).strip()
                            out.append(
                                DeclaredPortSpec(
                                    port=pub,
                                    protocol=raw_proto,
                                    expected_bind=canonical_bind_ip(raw_hip) if raw_hip else None,
                                    process_hint=_safe_scalar_str(svc_name) or "compose-service",
                                    declaration_kind="compose_ports",
                                    source_file=rel_path,
                                    line=1,
                                    node_id=node_id,
                                )
                            )
        elif "apiVersion" in doc and "kind" in doc:
            raw_meta = doc.get("metadata")
            meta_name = (
                _safe_scalar_str(raw_meta.get("name")).strip() or "k8s-workload"
                if isinstance(raw_meta, Mapping)
                else "k8s-workload"
            )
            visited: set[int] = set()
            stack: list[tuple[Any, int]] = [(doc.get("spec"), 0)]
            while stack and len(out) < MAX_TOTAL_PORT_ENTRIES and steps < MAX_TOTAL_PORT_ENTRIES:
                cur, d = stack.pop()
                if d > 24:
                    continue
                if isinstance(cur, (Mapping, list)):
                    oid = id(cur)
                    if oid in visited:
                        continue
                    visited.add(oid)
                    steps += 1
                    if len(visited) > MAX_TOTAL_PORT_ENTRIES:
                        break
                if isinstance(cur, Mapping):
                    if isinstance(cur.get("ports"), list):
                        c_name = _safe_scalar_str(cur.get("name")).strip() or meta_name
                        for kp in cur["ports"]:
                            if len(out) >= MAX_TOTAL_PORT_ENTRIES or steps >= MAX_TOTAL_PORT_ENTRIES:
                                break
                            steps += 1
                            if not isinstance(kp, Mapping):
                                continue
                            p_num = kp.get("hostPort") or kp.get("nodePort") or kp.get("containerPort") or kp.get("port")
                            if isinstance(p_num, int) and not isinstance(p_num, bool) and 1 <= p_num <= 65535:
                                raw_khip = _safe_scalar_str(kp.get("hostIP")).strip()
                                h_ip = canonical_bind_ip(raw_khip) if raw_khip else None
                                raw_kproto = _safe_scalar_str(kp.get("protocol")).strip().lower() or "tcp"
                                out.append(
                                    DeclaredPortSpec(
                                        port=p_num,
                                        protocol=raw_kproto,
                                        expected_bind=h_ip,
                                        process_hint=c_name,
                                        declaration_kind="k8s_manifest",
                                        source_file=rel_path,
                                        line=1,
                                        node_id=node_id,
                                    )
                                )
                    for v in cur.values():
                        if isinstance(v, (Mapping, list)) and id(v) not in visited:
                            stack.append((v, d + 1))
                elif isinstance(cur, list):
                    for item in cur[:MAX_TOTAL_PORT_ENTRIES]:
                        if isinstance(item, (Mapping, list)) and id(item) not in visited:
                            stack.append((item, d + 1))

    # Fallback line scan when PyYAML is unavailable in an isolated wheel environment
    if not out and is_compose_name and steps < MAX_TOTAL_PORT_ENTRIES:
        cur_svc = "compose-service"
        for idx, line in enumerate(text.splitlines()[:MAX_TOTAL_PORT_ENTRIES], start=1):
            if len(out) >= MAX_TOTAL_PORT_ENTRIES:
                break
            s = line.strip()
            if line.startswith("  ") and not line.startswith("    ") and s.endswith(":"):
                cand_s = s[:-1].strip()
                if cand_s and cand_s != "services":
                    cur_svc = cand_s
            if s.startswith("- "):
                b_ip, h_port, proto = _parse_publish_spec(s[2:].strip())
                if h_port and 1 <= h_port <= 65535:
                    out.append(
                        DeclaredPortSpec(
                            port=h_port,
                            protocol=proto,
                            expected_bind=b_ip,
                            process_hint=cur_svc,
                            declaration_kind="compose_ports",
                            source_file=rel_path,
                            line=idx,
                            node_id=node_id,
                        )
                    )
    return out[:MAX_TOTAL_PORT_ENTRIES]


def extract_declared_ports(repo_root: Path, report: Any = None) -> list[DeclaredPortSpec]:
    """Extract `Z=0` static port and bind declarations across containers, plists, and code."""
    _check_safe_path_segments(repo_root, str(repo_root))
    try:
        exists = repo_root.exists()
    except OSError as exc:
        raise ValueError(f"Invalid repository path '{repo_root}': {exc}") from exc
    if not exists:
        return []
    validate_non_symlink_path(repo_root)
    real_root = repo_root.resolve()
    node_by_file = {n.source_file: n.id for n in getattr(report, "nodes", ())}
    found: list[DeclaredPortSpec] = []

    def _walk_dir(cur: Path, depth: int) -> None:
        if depth > 8 or len(found) >= 256:
            return
        try:
            with os.scandir(cur) as it:
                entries = sorted(it, key=lambda e: e.name)
        except OSError:
            return
        for entry in entries:
            if entry.name in _SKIP_REPO_DIRS:
                continue
            try:
                if entry.is_symlink():
                    continue
                p = Path(entry.path)
                if entry.is_dir(follow_symlinks=False):
                    _walk_dir(p, depth + 1)
                    continue
                if not entry.is_file(follow_symlinks=False):
                    continue
                f_sz = entry.stat(follow_symlinks=False).st_size
                rel = p.resolve().relative_to(real_root).as_posix()
            except (OSError, ValueError):
                continue
            nid = node_by_file.get(rel)
            fname_low = entry.name.lower()

            if fname_low.endswith(".plist"):
                if f_sz > MAX_PLIST_BYTES:
                    continue
                try:
                    _, raw_b = read_bounded_regular_bytes(p, repo_root=real_root, max_bytes=MAX_PLIST_BYTES)
                    plist_d = parse_safe_plist_xml(raw_b)
                except (OSError, ValueError, expat.ExpatError, plistlib.InvalidFileException):
                    continue
                lbl = _safe_scalar_str(plist_d.get("Label")).strip() or p.stem
                prog_args = plist_d.get("ProgramArguments")
                if isinstance(prog_args, list):
                    joined = " ".join(
                        s for x in prog_args[:128] if (s := _safe_scalar_str(x))
                    )
                    if "uvicorn" in joined or "--port" in joined:
                        h_ip, p_num = _parse_cli_uvicorn_flags(joined)
                        if p_num:
                            found.append(
                                DeclaredPortSpec(
                                    port=p_num,
                                    protocol="tcp",
                                    expected_bind=h_ip,
                                    process_hint=lbl,
                                    declaration_kind="launchd_plist",
                                    source_file=rel,
                                    line=1,
                                    node_id=nid,
                                )
                            )
                sockets = plist_d.get("Sockets")
                if isinstance(sockets, Mapping):
                    for sock_cfg in sockets.values():
                        sock_items = sock_cfg if isinstance(sock_cfg, list) else [sock_cfg]
                        for si in sock_items:
                            if not isinstance(si, Mapping):
                                continue
                            s_port = si.get("SockServiceName")
                            p_int: int | None = None
                            if (
                                isinstance(s_port, int)
                                and not isinstance(s_port, bool)
                                and s_port.bit_length() <= 32
                            ):
                                p_int = s_port
                            elif (
                                isinstance(s_port, str)
                                and s_port.isascii()
                                and s_port.isdigit()
                                and len(s_port) <= 5
                            ):
                                p_int = int(s_port)
                            if p_int is not None and 1 <= p_int <= 65535:
                                node_nm = _safe_scalar_str(si.get("SockNodeName")).strip()
                                sock_type = _safe_scalar_str(si.get("SockType")).strip().lower() or "tcp"
                                found.append(
                                    DeclaredPortSpec(
                                        port=p_int,
                                        protocol=sock_type,
                                        expected_bind=canonical_bind_ip(node_nm) if node_nm else "0.0.0.0",
                                        process_hint=lbl,
                                        declaration_kind="launchd_plist",
                                        source_file=rel,
                                        line=1,
                                        node_id=nid,
                                    )
                                )
            elif fname_low.startswith(("dockerfile", "containerfile")) or fname_low.endswith((".dockerfile", ".containerfile")):
                if f_sz > 2 * 1024 * 1024:
                    continue
                try:
                    _, raw_b = read_bounded_regular_bytes(p, repo_root=real_root, max_bytes=2 * 1024 * 1024)
                except (OSError, ValueError):
                    continue
                txt = raw_b.decode("utf-8-sig", errors="replace")
                for ln_no, ln in enumerate(txt.splitlines(), start=1):
                    m_exp = _DOCKERFILE_EXPOSE_RE.match(ln)
                    if m_exp:
                        for tok in m_exp.group(1).split():
                            _b, p_int, proto = _parse_publish_spec(tok)
                            if p_int and 1 <= p_int <= 65535:
                                found.append(
                                    DeclaredPortSpec(
                                        port=p_int,
                                        protocol=proto,
                                        expected_bind=None,
                                        process_hint="container",
                                        declaration_kind="dockerfile_expose",
                                        source_file=rel,
                                        line=ln_no,
                                        node_id=nid,
                                    )
                                )
                    for m_uv in _UVICORN_CLI_PORT_RE.finditer(ln):
                        h_ip, p_num = _parse_cli_uvicorn_flags(m_uv.group(0))
                        if p_num:
                            found.append(
                                DeclaredPortSpec(
                                    port=p_num,
                                    protocol="tcp",
                                    expected_bind=h_ip,
                                    process_hint="uvicorn",
                                    declaration_kind="dockerfile_cmd",
                                    source_file=rel,
                                    line=ln_no,
                                    node_id=nid,
                                )
                            )
            elif fname_low.endswith((".yaml", ".yml")):
                if f_sz > 2 * 1024 * 1024:
                    continue
                try:
                    _, raw_b = read_bounded_regular_bytes(p, repo_root=real_root, max_bytes=2 * 1024 * 1024)
                except (OSError, ValueError):
                    continue
                found.extend(_extract_yaml_ports(raw_b.decode("utf-8-sig", errors="replace"), rel, fname_low, nid))
            elif fname_low.endswith(".py"):
                if f_sz > 2 * 1024 * 1024:
                    continue
                try:
                    _, raw_b = read_bounded_regular_bytes(p, repo_root=real_root, max_bytes=2 * 1024 * 1024)
                except (OSError, ValueError):
                    continue
                found.extend(_extract_python_ports(raw_b.decode("utf-8-sig", errors="replace"), rel, nid))
            elif fname_low.endswith((".sh", ".bash", ".zsh")) or entry.name in ("Makefile", "Justfile"):
                if f_sz > 2 * 1024 * 1024:
                    continue
                try:
                    _, raw_b = read_bounded_regular_bytes(p, repo_root=real_root, max_bytes=2 * 1024 * 1024)
                except (OSError, ValueError):
                    continue
                txt = raw_b.decode("utf-8-sig", errors="replace")
                for ln_no, ln in enumerate(txt.splitlines(), start=1):
                    for m_run in _RUN_PUBLISH_FLAG_RE.finditer(ln):
                        b_ip, h_port, proto = _parse_publish_spec(m_run.group(1))
                        if h_port and 1 <= h_port <= 65535:
                            found.append(
                                DeclaredPortSpec(
                                    port=h_port,
                                    protocol=proto,
                                    expected_bind=b_ip,
                                    process_hint="container",
                                    declaration_kind="container_run_flag",
                                    source_file=rel,
                                    line=ln_no,
                                    node_id=nid,
                                )
                            )

    _walk_dir(real_root, 0)
    return found[:MAX_TOTAL_PORT_ENTRIES]


_SS_PROC_RE = re.compile(r'\(\("([^"]+)",pid=(\d+)')


def _safe_nonneg_int(raw: object, *, max_digits: int = 10) -> int | None:
    if raw is None or isinstance(raw, bool):
        return None
    if isinstance(raw, int):
        return raw if 0 <= raw < (10**max_digits) else None
    if isinstance(raw, float):
        return None
    s = str(raw).strip()
    if not s or not s.isascii() or not s.isdigit() or len(s) > max_digits:
        return None
    return int(s)


def _parse_bounded_json_int(raw_digits: str) -> int:
    s = raw_digits.strip()
    if s.startswith("-"):
        return 0
    return int(s) if len(s) <= 10 else 0


def _split_addr_port(addr_port: str) -> tuple[str, int | None]:
    s = addr_port.strip()
    if s.startswith("[") and "]:" in s:
        h, p_s = s[1:].rsplit("]:", 1)
        return h, (int(p_s) if p_s.isascii() and p_s.isdigit() and len(p_s) <= 5 else None)
    if ":" in s:
        h, p_s = s.rsplit(":", 1)
        return h, (int(p_s) if p_s.isascii() and p_s.isdigit() and len(p_s) <= 5 else None)
    return s, None


def parse_port_listeners_text(raw_text: str) -> tuple[list[ObservedPortListener], str, str | None]:
    """Parse recorded `lsof -nP -iTCP -sTCP:LISTEN`, Linux `ss -tulnp`, or JSON listener text."""
    stripped = raw_text.strip()
    if not stripped:
        return [], "empty", None
    if "\x00" in stripped:
        raise ValueError("Refusing listener capture containing NUL bytes.")

    if stripped.startswith(("{", "[")):
        ensure_json_depth_bounded(stripped)
        data = json.loads(stripped, parse_int=_parse_bounded_json_int)
        captured_at = str(data.get("captured_at")) if isinstance(data, Mapping) and data.get("captured_at") else None
        items = data.get("listeners", []) if isinstance(data, Mapping) else data
        if not isinstance(items, list):
            raise ValueError("Listener JSON capture must contain a listeners list.")
        out_json: list[ObservedPortListener] = []
        for item in items[:MAX_TOTAL_PORT_ENTRIES]:
            if not isinstance(item, Mapping):
                continue
            p_num = _safe_nonneg_int(item.get("port"), max_digits=5) or 0
            if not (1 <= p_num <= 65535):
                continue
            b_addr = str(item.get("bind_address") or item.get("host") or "0.0.0.0")
            norm_b = normalize_bind_category(b_addr) or "wildcard"
            out_json.append(
                ObservedPortListener(
                    port=p_num,
                    protocol=str(item.get("protocol") or "tcp").lower(),
                    bind_address=b_addr,
                    normalized_bind=norm_b,
                    command=str(item.get("command") or item.get("process") or "unknown"),
                    pid=_safe_nonneg_int(item.get("pid"), max_digits=10) or 0,
                    user="[REDACTED_USER]",
                    source_format="json",
                )
            )
        return out_json, "json", captured_at

    lines = stripped.splitlines()
    out: list[ObservedPortListener] = []
    detected_fmt = "lsof"
    for line in lines[:16384]:
        if len(out) >= MAX_TOTAL_PORT_ENTRIES:
            break
        s = line.strip()
        if not s or s.startswith(("COMMAND", "Netid", "State")):
            if s.startswith("Netid"):
                detected_fmt = "ss"
            continue
        toks = s.split()
        # `lsof -nP -iTCP -sTCP:LISTEN`: `Python 41822 user 6u IPv4 ... TCP 127.0.0.1:8780 (LISTEN)`
        if len(toks) >= 9 and toks[1].isascii() and toks[1].isdigit() and ("TCP" in toks or "UDP" in toks):
            detected_fmt = "lsof"
            if not any(t.upper() == "(LISTEN)" for t in toks):
                continue
            pid_val = _safe_nonneg_int(toks[1], max_digits=10)
            if pid_val is None:
                continue
            cmd = toks[0]
            proto_idx = toks.index("TCP") if "TCP" in toks else toks.index("UDP")
            proto = toks[proto_idx].lower()
            addr_tok = toks[proto_idx + 1] if proto_idx + 1 < len(toks) else ""
            b_addr, p_num = _split_addr_port(addr_tok)
            if p_num and 1 <= p_num <= 65535:
                out.append(
                    ObservedPortListener(
                        port=p_num,
                        protocol=proto,
                        bind_address=b_addr,
                        normalized_bind=normalize_bind_category(b_addr) or "wildcard",
                        command=cmd,
                        pid=pid_val,
                        user="[REDACTED_USER]",
                        source_format="lsof",
                    )
                )
            continue
        # `ss -tulnp`: `tcp LISTEN 0 128 0.0.0.0:8080 0.0.0.0:* users:(("uvicorn",pid=4210,fd=3))`
        if len(toks) >= 5 and toks[0].lower() in ("tcp", "udp", "tcp6", "udp6"):
            detected_fmt = "ss"
            if toks[1].upper() != "LISTEN":
                continue
            proto = "udp" if toks[0].lower().startswith("udp") else "tcp"
            local_tok = toks[4]
            b_addr, p_num = _split_addr_port(local_tok)
            if p_num and 1 <= p_num <= 65535:
                m_pr = _SS_PROC_RE.search(s)
                cmd = m_pr.group(1) if m_pr else "unknown"
                pid = (_safe_nonneg_int(m_pr.group(2), max_digits=10) or 0) if m_pr else 0
                out.append(
                    ObservedPortListener(
                        port=p_num,
                        protocol=proto,
                        bind_address=b_addr,
                        normalized_bind=normalize_bind_category(b_addr) or "wildcard",
                        command=cmd,
                        pid=pid,
                        user="[REDACTED_USER]",
                        source_format="ss",
                    )
                )

    return out, detected_fmt, None


def parse_port_listeners_file(
    raw_path: Path | str,
    *,
    repo_root: Path | None = None,
    allow_external: bool = False,
) -> tuple[Path, list[ObservedPortListener], str, str | None]:
    """Read and parse a recorded listener file (`<= 32 MiB`, non-symlink)."""
    resolved, raw_b = read_bounded_regular_bytes(
        raw_path,
        repo_root=repo_root,
        allow_external=allow_external,
        max_bytes=MAX_WIRETAP_BYTES,
    )
    listeners, fmt, cap_at = parse_port_listeners_text(raw_b.decode("utf-8-sig"))
    return resolved, listeners, fmt, cap_at


def capture_local_port_listeners() -> tuple[list[ObservedPortListener], str, str]:
    """Opt-in read-only host listener snapshot (`probe_local_ports=True` ONLY)."""
    captured_at = datetime.now(UTC).isoformat()
    lsof_bin = "/usr/sbin/lsof" if Path("/usr/sbin/lsof").is_file() else shutil.which("lsof")
    if lsof_bin:
        proc = subprocess.run(
            [lsof_bin, "-nP", "-iTCP", "-sTCP:LISTEN"],
            capture_output=True,
            text=True,
            timeout=5.0,
            check=False,
        )
        listeners, _fmt, _ = parse_port_listeners_text(proc.stdout or "")
        return listeners, "lsof", captured_at

    ss_bin = shutil.which("ss")
    if ss_bin:
        proc = subprocess.run(
            [ss_bin, "-tulnp"],
            capture_output=True,
            text=True,
            timeout=5.0,
            check=False,
        )
        listeners, _fmt, _ = parse_port_listeners_text(proc.stdout or "")
        return listeners, "ss", captured_at

    return [], "unavailable", captured_at


_PYTHON_RUNTIME_CMDS = frozenset({"python", "python3", "uvicorn", "gunicorn", "hypercorn", "fastapi"})
_CONTAINER_RUNTIME_CMDS = frozenset(
    {"com.docke", "com.docker.backend", "vpnkit", "docker-proxy", "rootlesskit", "gvproxy", "container", "containerd", "lima"}
)


def _process_matches_declaration(decl: DeclaredPortSpec, listener: ObservedPortListener) -> bool:
    cmd_low = listener.command.lower()
    hint_low = decl.process_hint.lower()
    cmd_clean = re.sub(r"[^a-z0-9]+", "", cmd_low)
    hint_clean = re.sub(r"[^a-z0-9]+", "", hint_low)
    if cmd_clean and hint_clean and (cmd_clean in hint_clean or hint_clean in cmd_clean):
        return True
    if hint_low in _PYTHON_RUNTIME_CMDS and any(cmd_low.startswith(p) for p in _PYTHON_RUNTIME_CMDS):
        return True
    if decl.declaration_kind in ("compose_ports", "dockerfile_expose", "dockerfile_cmd", "container_run_flag", "k8s_manifest"):
        if any(cmd_low.startswith(c) for c in _CONTAINER_RUNTIME_CMDS):
            return True
        if hint_low in ("api", "web", "backend", "app", "server", "container") and any(
            cmd_low.startswith(p) for p in (*_PYTHON_RUNTIME_CMDS, "node", "bun", "deno", "go", "nginx")
        ):
            return True
    return decl.declaration_kind == "launchd_plist" and any(
        cmd_low.startswith(p) for p in _PYTHON_RUNTIME_CMDS
    )


def correlate_port_occupancy(
    repo_root: Path,
    report: Any = None,
    *,
    port_listeners_paths: Sequence[str | Path] = (),
    probe_local_ports: bool = False,
) -> dict[str, object]:
    """Correlate `Z=0` declared ports against recorded or opt-in runtime listeners."""
    declared = extract_declared_ports(repo_root, report=report)
    listeners: list[ObservedPortListener] = []
    source_paths: list[str] = []
    formats: list[str] = []
    captured_timestamps: list[str] = []
    subprocesses_invoked = 0

    truncated = len(declared) >= MAX_TOTAL_PORT_ENTRIES
    for raw_p in port_listeners_paths:
        res_p, parsed_l, fmt, cap_at = parse_port_listeners_file(raw_p, repo_root=None)
        rem = MAX_TOTAL_PORT_ENTRIES - len(listeners)
        if rem > 0:
            listeners.extend(parsed_l[:rem])
        if len(parsed_l) > max(0, rem):
            truncated = True
        source_paths.append(str(res_p))
        if fmt not in formats:
            formats.append(fmt)
        if cap_at:
            captured_timestamps.append(cap_at)

    if probe_local_ports:
        live_l, live_fmt, live_at = capture_local_port_listeners()
        subprocesses_invoked += 1
        rem_live = MAX_TOTAL_PORT_ENTRIES - len(listeners)
        if rem_live > 0:
            listeners.extend(live_l[:rem_live])
        if len(live_l) > max(0, rem_live):
            truncated = True
        if live_fmt not in formats:
            formats.append(live_fmt)
        captured_timestamps.append(live_at)

    has_capture = bool(port_listeners_paths or probe_local_ports)
    capture_mode = (
        "recorded_and_live"
        if (port_listeners_paths and probe_local_ports)
        else ("live_local_snapshot" if probe_local_ports else ("recorded_artifact" if port_listeners_paths else "none"))
    )

    by_port_decl: dict[tuple[int, str], list[DeclaredPortSpec]] = {}
    for d in declared:
        by_port_decl.setdefault((d.port, d.protocol), []).append(d)

    by_port_obs: dict[tuple[int, str], list[ObservedPortListener]] = {}
    for ls in listeners:
        by_port_obs.setdefault((ls.port, ls.protocol), []).append(ls)

    entries: list[dict[str, object]] = []
    findings: list[dict[str, object]] = []
    fallback_nid = next(
        (n.id for n in getattr(report, "nodes", ()) if n.tier == "manipulate"),
        None,
    )

    if has_capture:
        for (port, proto), decl_list in sorted(by_port_decl.items()):
            obs_list = by_port_obs.get((port, proto), [])
            primary_decl = next((d for d in decl_list if d.expected_bind is not None), decl_list[0])
            nid = primary_decl.node_id or fallback_nid

            if not obs_list:
                entries.append(
                    {
                        "port": port,
                        "protocol": proto,
                        "classification": "unlistening_declared",
                        "epistemic_status": "unexercised_in_sample",
                        "declared": [asdict(d) for d in decl_list],
                        "observed": [],
                    }
                )
                continue

            matching_proc = [o for o in obs_list if any(_process_matches_declaration(d, o) for d in decl_list)]
            if not matching_proc:
                squatter = obs_list[0]
                entries.append(
                    {
                        "port": port,
                        "protocol": proto,
                        "classification": "squatter_conflict",
                        "rule_code": "PORT-001",
                        "declared": [asdict(d) for d in decl_list],
                        "observed": [asdict(o) for o in obs_list],
                    }
                )
                findings.append(
                    {
                        "rule_code": "PORT-001",
                        "tier": "manipulate",
                        "severity": "blocking",
                        "blocks_gate": True,
                        "node_id": nid,
                        "source_file": primary_decl.source_file,
                        "line": primary_decl.line,
                        "title": (
                            f"Port {port}/{proto} declared by `{primary_decl.process_hint}` "
                            f"is occupied by unexpected process `{squatter.command}` (pid {squatter.pid})"
                        ),
                        "detail": (
                            f"{primary_decl.source_file}:{primary_decl.line} declares {proto.upper()} "
                            f"port {port} for `{primary_decl.process_hint}`, but runtime capture "
                            f"observes `{squatter.command}` (pid {squatter.pid}) on `{squatter.bind_address}:{port}`."
                        ),
                        "remediation": (
                            f"Reclaim {proto.upper()} port {port} from squatter `{squatter.command}` "
                            f"or update `{primary_decl.source_file}` to the intended non-conflicting port."
                        ),
                    }
                )
                continue

            exp_cat = normalize_bind_category(primary_decl.expected_bind)
            obs_cats = {o.normalized_bind for o in matching_proc}
            drift_obs: ObservedPortListener | None = None
            if exp_cat == "loopback":
                drift_obs = next(
                    (o for o in matching_proc if o.normalized_bind in ("wildcard", "specific")),
                    None,
                )
            elif exp_cat == "wildcard":
                if obs_cats == {"loopback"}:
                    drift_obs = matching_proc[0]
            elif exp_cat == "specific":
                exp_norm_ip = canonical_bind_ip(primary_decl.expected_bind)
                drift_obs = next(
                    (
                        o
                        for o in matching_proc
                        if o.normalized_bind == "wildcard"
                        or canonical_bind_ip(o.bind_address) != exp_norm_ip
                    ),
                    None,
                )
            elif exp_cat is None:
                drift_obs = next((o for o in matching_proc if o.normalized_bind == "specific"), None)

            if drift_obs is not None:
                exp_ip = canonical_bind_ip(primary_decl.expected_bind) or "loopback/wildcard"
                obs_ip = canonical_bind_ip(drift_obs.bind_address) or drift_obs.bind_address
                entries.append(
                    {
                        "port": port,
                        "protocol": proto,
                        "classification": "bind_exposure_drift",
                        "rule_code": "PORT-002",
                        "expected_bind": exp_ip,
                        "observed_bind": obs_ip,
                        "declared": [asdict(d) for d in decl_list],
                        "observed": [asdict(o) for o in matching_proc],
                    }
                )
                findings.append(
                    {
                        "rule_code": "PORT-002",
                        "tier": "manipulate",
                        "severity": "blocking",
                        "blocks_gate": True,
                        "node_id": nid,
                        "source_file": primary_decl.source_file,
                        "line": primary_decl.line,
                        "title": (
                            f"Port {port}/{proto} bind exposure drifts: declared `{exp_ip}` "
                            f"vs runtime `{obs_ip}` (`{drift_obs.command}`)"
                        ),
                        "detail": (
                            f"{primary_decl.source_file}:{primary_decl.line} expects `{exp_ip}:{port}`, "
                            f"but runtime listener `{drift_obs.command}` binds `{drift_obs.bind_address}:{port}` ({obs_ip})."
                        ),
                        "remediation": (
                            f"Align runtime `--host` / publish bind address with `{exp_ip}` "
                            f"(never expose loopback-only services on `0.0.0.0`)."
                        ),
                    }
                )
            else:
                entries.append(
                    {
                        "port": port,
                        "protocol": proto,
                        "classification": "corroborated",
                        "declared": [asdict(d) for d in decl_list],
                        "observed": [asdict(o) for o in matching_proc],
                    }
                )

        for (port, proto), obs_list in sorted(by_port_obs.items()):
            if (port, proto) not in by_port_decl:
                entries.append(
                    {
                        "port": port,
                        "protocol": proto,
                        "classification": "dark_listener",
                        "overlay_kind": "runtime_only",
                        "declared": [],
                        "observed": [asdict(o) for o in obs_list],
                    }
                )

    counts = {
        k: sum(1 for e in entries if e["classification"] == k)
        for k in ("corroborated", "squatter_conflict", "bind_exposure_drift", "dark_listener", "unlistening_declared")
    }
    return {
        "present": has_capture,
        "declared_port_count": len(declared),
        "observed_listener_count": len(listeners),
        "declared_ports": [asdict(d) for d in declared],
        "counts": counts,
        "entries": entries,
        "findings": findings,
        "provenance": {
            "capture_mode": capture_mode,
            "source_paths": source_paths,
            "parser_formats": formats,
            "captured_at": captured_timestamps[0] if captured_timestamps else None,
            "subprocesses_invoked": subprocesses_invoked,
            "redacted_os_users": True,
            "truncated": truncated,
            "sampling_note": (
                "Listener snapshot reflects point-in-time socket occupancy; "
                "unlistening_declared ports may belong to on-demand or unstarted services."
            ),
        },
    }
