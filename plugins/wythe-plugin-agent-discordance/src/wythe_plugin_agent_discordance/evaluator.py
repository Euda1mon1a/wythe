"""Pure-Python evaluator for cross-channel continuity and cross-agent isolation (#117).

Enforces strict boundaries:
- Never ingests or echoes transcripts, audio payloads, credentials, or raw memory dumps.
- Separates proven mismatch (`DISC-001` / `DISC-002`) from missing receipts (`unverified`)
  and intermediate hop-only observations (`hop_only`).
- Never treats KV-cache misses or response wording differences as identity drift.
"""

from __future__ import annotations

import json
import os
import stat
from collections.abc import Mapping, Sequence
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

MAX_ARTIFACT_BYTES = 2 * 1024 * 1024
MAX_JSON_DEPTH = 128
FORBIDDEN_PAYLOAD_KEYS = frozenset(
    {
        "transcript",
        "raw_transcript",
        "utterance_text",
        "audio_bytes",
        "audio_base64",
        "pcm_bytes",
        "api_key",
        "secret_key",
        "authorization",
        "bearer_token",
        "password",
        "raw_memory",
        "production_memory_dump",
    }
)


@dataclass(frozen=True)
class RouteContinuityObservation:
    """Evaluated continuity/isolation status for a single declared route."""

    route_id: str
    declared_agent_id: str
    declared_principal: str
    continuity_group: str | None
    expected_policy_version: str | None
    observed_agent_id: str | None
    observed_hop: str | None
    observed_policy_version: str | None
    status: str  # "supported" | "proven_mismatch" | "hop_only" | "unverified" | "valid_boundary_difference"
    missing_receipts: tuple[str, ...] = ()
    note: str = ""


@dataclass(frozen=True)
class DiscordanceViolation:
    """Actionable candidate finding produced by `evaluate_agent_discordance`."""

    rule_code: str  # "DISC-001" | "DISC-002"
    route_id: str
    title: str
    detail: str
    remediation: str
    source_file: str
    line: int = 1


@dataclass(frozen=True)
class DiscordanceEvaluationReport:
    """Deterministic read-only evaluation summary across declared agent routes & receipts."""

    evaluated_route_count: int
    supported_routes: list[str] = field(default_factory=list)
    valid_boundary_routes: list[str] = field(default_factory=list)
    hop_only_routes: list[str] = field(default_factory=list)
    unverified_routes: list[str] = field(default_factory=list)
    mismatched_routes: list[str] = field(default_factory=list)
    route_observations: list[RouteContinuityObservation] = field(default_factory=list)
    violations: list[DiscordanceViolation] = field(default_factory=list)
    notes: list[str] = field(default_factory=list)


def _check_raw_json_nesting(raw_bytes: bytes, *, max_depth: int = MAX_JSON_DEPTH) -> None:
    """Linear O(N) string-aware bracket-nesting pre-check before `json.loads`."""
    depth = 0
    in_str = False
    esc = False
    start = 3 if raw_bytes.startswith(b"\xef\xbb\xbf") else 0
    for idx in range(start, len(raw_bytes)):
        b = raw_bytes[idx]
        if in_str:
            if esc:
                esc = False
            elif b == 0x5C:
                esc = True
            elif b == 0x22:
                in_str = False
            continue
        if b == 0x22:
            in_str = True
        elif b in (0x5B, 0x7B):
            depth += 1
            if depth > max_depth:
                raise ValueError(f"JSON nesting depth exceeds maximum ({max_depth}).")
        elif b in (0x5D, 0x7D) and depth > 0:
            depth -= 1


def _contains_forbidden_keys(obj: Any, *, max_depth: int = MAX_JSON_DEPTH) -> str | None:
    stack: list[tuple[Any, int]] = [(obj, 0)]
    while stack:
        cur, depth = stack.pop()
        if depth > max_depth:
            raise ValueError(f"JSON nesting depth exceeds maximum ({max_depth}).")
        if isinstance(cur, Mapping):
            for k, v in cur.items():
                k_norm = str(k).strip().lower()
                if k_norm in FORBIDDEN_PAYLOAD_KEYS:
                    return k_norm
                if isinstance(v, (Mapping, list)):
                    stack.append((v, depth + 1))
        elif isinstance(cur, list):
            for item in cur:
                if isinstance(item, (Mapping, list)):
                    stack.append((item, depth + 1))
    return None


def _read_contained_json(repo_root: Path, rel_path: str) -> tuple[dict[str, Any] | None, str | None]:
    root_res = repo_root.resolve()
    cur = root_res
    for part in Path(rel_path).parts:
        if part in ("", "."):
            continue
        if part == "..":
            return None, f"Rejected traversal path '{rel_path}'."
        cur = cur / part
        if cur.is_symlink():
            return None, f"Rejected symlink artifact '{rel_path}'."
    if not cur.exists():
        return None, None
    resolved = cur.resolve(strict=True)
    if not resolved.is_relative_to(root_res):
        return None, f"Artifact '{rel_path}' escapes repository root."
    flags = os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0) | getattr(os, "O_NONBLOCK", 0)
    try:
        fd = os.open(resolved, flags)
    except OSError as exc:
        return None, f"Artifact '{rel_path}' could not be opened safely: {exc}"
    with os.fdopen(fd, "rb") as fh:
        st = os.fstat(fh.fileno())
        if not stat.S_ISREG(st.st_mode) or st.st_size > MAX_ARTIFACT_BYTES:
            return None, f"Artifact '{rel_path}' is not a bounded regular JSON file."
        raw = fh.read(MAX_ARTIFACT_BYTES + 1)
    if len(raw) > MAX_ARTIFACT_BYTES:
        return None, f"Artifact '{rel_path}' exceeds 2 MiB limit."
    try:
        _check_raw_json_nesting(raw, max_depth=MAX_JSON_DEPTH)
        data = json.loads(raw.decode("utf-8"))
    except (ValueError, UnicodeDecodeError) as exc:
        return None, f"Artifact '{rel_path}' is not valid bounded JSON: {exc}"
    if not isinstance(data, dict):
        return None, f"Artifact '{rel_path}' top-level JSON must be an object."
    forbidden = _contains_forbidden_keys(data)
    if forbidden is not None:
        raise ValueError(
            f"Refused '{rel_path}': forbidden sensitive/transcript key '{forbidden}' is prohibited (#117)."
        )
    return data, None


def load_repo_discordance_artifacts(
    repo_root: Path,
) -> tuple[dict[str, Any] | None, dict[str, Any] | None, str, list[str]]:
    """Discover optional declarative route map and redacted SDK receipts in `repo_root`."""
    notes: list[str] = []
    routes_doc: dict[str, Any] | None = None
    routes_rel = ".wythe/agent_routes.json"
    for cand in (".wythe/agent_routes.json", "config/agent_routes.json", "configs/agent_routes.json"):
        doc, err = _read_contained_json(repo_root, cand)
        if err:
            notes.append(err)
        if doc is not None:
            routes_doc = doc
            routes_rel = cand
            break

    receipts_doc: dict[str, Any] | None = None
    for r_cand in (".wythe/agent_receipts.json", "config/agent_receipts.json"):
        rdoc, rerr = _read_contained_json(repo_root, r_cand)
        if rerr:
            notes.append(rerr)
        if rdoc is not None:
            receipts_doc = rdoc
            break
    return routes_doc, receipts_doc, routes_rel, notes


def _opt_str(val: Any) -> str | None:
    if val is None or isinstance(val, bool):
        return None
    s = str(val).strip()
    return s if s else None


def _strict_bool_opt(val: Any) -> bool | None:
    if isinstance(val, bool):
        return val
    if isinstance(val, (int, float)):
        if val == 0:
            return False
        if val == 1:
            return True
    if isinstance(val, str):
        low = val.strip().lower()
        if low in ("true", "1", "yes"):
            return True
        if low in ("false", "0", "0.0", "no"):
            return False
    return None


def _strict_bool(val: Any, *, default: bool = False) -> bool:
    parsed = _strict_bool_opt(val)
    if parsed is not None:
        return parsed
    if isinstance(val, str) and val.strip().lower() in ("none", "null", ""):
        return False
    return default


def evaluate_agent_discordance(
    routes_manifest: Mapping[str, Any],
    receipts_bundle: Mapping[str, Any] | None = None,
    *,
    source_file: str = ".wythe/agent_routes.json",
) -> DiscordanceEvaluationReport:
    """Evaluate cross-channel continuity (`DISC-001`) and cross-agent isolation (`DISC-002`)."""
    forbidden_m = _contains_forbidden_keys(routes_manifest)
    if forbidden_m is not None:
        raise ValueError(f"Forbidden sensitive/transcript key '{forbidden_m}' in route manifest.")
    if receipts_bundle is not None:
        forbidden_r = _contains_forbidden_keys(receipts_bundle)
        if forbidden_r is not None:
            raise ValueError(f"Forbidden sensitive/transcript key '{forbidden_r}' in receipts bundle.")

    raw_routes: Sequence[Any] = routes_manifest.get("routes") or []
    raw_obs_list: Sequence[Any] = (receipts_bundle or {}).get("observations") or (
        (receipts_bundle or {}).get("route_receipts") or []
    )
    obs_list_by_route: dict[str, list[Mapping[str, Any]]] = {}
    for ro in raw_obs_list:
        if isinstance(ro, Mapping) and _opt_str(ro.get("route_id") or ro.get("route")):
            rid = str(ro.get("route_id") or ro.get("route")).strip()
            obs_list_by_route.setdefault(rid, []).append(ro)

    supported: list[str] = []
    valid_boundaries: list[str] = []
    hop_only: list[str] = []
    unverified: list[str] = []
    mismatched: list[str] = []
    observations: list[RouteContinuityObservation] = []
    violations: list[DiscordanceViolation] = []
    notes: list[str] = []

    # Group declared routes by continuity_group for same-agent handoff comparison
    group_canary_expected: dict[str, str] = {}
    for rt in raw_routes:
        if not isinstance(rt, Mapping):
            continue
        grp = _opt_str(rt.get("continuity_group"))
        canary_id = _opt_str(rt.get("canary_task_id"))
        if grp and canary_id and grp not in group_canary_expected:
            group_canary_expected[grp] = canary_id

    declared_agent_by_task: dict[str, tuple[str, str]] = {}
    for rt in raw_routes:
        if not isinstance(rt, Mapping):
            continue
        t_id = _opt_str(rt.get("canary_task_id") or rt.get("owned_task_id"))
        ag = _opt_str(rt.get("agent_id"))
        pr = _opt_str(rt.get("principal_scope")) or "owner"
        if t_id and ag and t_id not in declared_agent_by_task:
            declared_agent_by_task[t_id] = (ag, pr)

    for rt in raw_routes:
        if not isinstance(rt, Mapping):
            continue
        rid = _opt_str(rt.get("route_id") or rt.get("route")) or "unnamed_route"
        decl_agent = _opt_str(rt.get("agent_id")) or "unknown_agent"
        decl_principal = _opt_str(rt.get("principal_scope")) or "owner"
        cont_group = _opt_str(rt.get("continuity_group"))
        exp_pol_ver = _opt_str(rt.get("expected_policy_version") or rt.get("policy_version"))
        explicit_boundary = _strict_bool(rt.get("explicit_privacy_boundary"), default=False)
        device_only_caps = tuple(str(x) for x in (rt.get("device_only_capabilities") or []))
        isolated_from = {str(x).strip() for x in (rt.get("isolated_from_agents") or []) if str(x).strip()}

        route_obs_items = obs_list_by_route.get(rid) or []
        if not route_obs_items:
            unverified.append(rid)
            observations.append(
                RouteContinuityObservation(
                    route_id=rid,
                    declared_agent_id=decl_agent,
                    declared_principal=decl_principal,
                    continuity_group=cont_group,
                    expected_policy_version=exp_pol_ver,
                    observed_agent_id=None,
                    observed_hop=None,
                    observed_policy_version=None,
                    status="unverified",
                    missing_receipts=("route_observation_receipt",),
                    note=f"No redacted SDK receipt supplied for route '{rid}'; marked unverified (never passed).",
                )
            )
            continue

        # Evaluate EVERY observation for `rid` so a later clean receipt cannot erase a leak/mismatch
        route_statuses: list[RouteContinuityObservation] = []
        for ro in route_obs_items:
            caller_rcpt = _opt_str(ro.get("caller_receipt_id"))
            authz_rcpt = _opt_str(ro.get("authz_receipt_id"))
            obs_hop = _opt_str(ro.get("observed_hop") or ro.get("hop"))
            obs_agent = _opt_str(ro.get("observed_agent_id") or ro.get("agent_id")) if caller_rcpt else None
            obs_pol_ver = _opt_str(ro.get("observed_policy_version") or ro.get("policy_version"))
            canary_recovered = _strict_bool_opt(ro.get("canary_recovered"))
            accessed_task = _opt_str(ro.get("accessed_task_id") or ro.get("canary_task_id"))
            leaked_from_agent = _opt_str(ro.get("leaked_context_from_agent"))
            cache_hit = _strict_bool_opt(ro.get("cache_hit"))
            wording_differs = _strict_bool(ro.get("wording_differs_from_sibling"), default=False)

            missing_rcpts: list[str] = []
            if not caller_rcpt:
                missing_rcpts.append("caller_receipt_id")
            if not authz_rcpt:
                missing_rcpts.append("authz_receipt_id")

            # 1. Cross-agent / cross-principal leak (`DISC-002`) checked first on every receipt
            task_owner = declared_agent_by_task.get(accessed_task or "")
            cross_leak = False
            leak_detail = ""
            if leaked_from_agent and (leaked_from_agent != decl_agent or leaked_from_agent in isolated_from):
                cross_leak = True
                leak_detail = (
                    f"Route `{rid}` (`{decl_agent}`, principal `{decl_principal}`) observed context/permissions "
                    f"originating from distinct agent `{leaked_from_agent}`."
                )
            elif (
                canary_recovered is True
                and task_owner is not None
                and (task_owner[0] != decl_agent or decl_principal != task_owner[1] or explicit_boundary)
            ):
                cross_leak = True
                leak_detail = (
                    f"Route `{rid}` (`{decl_agent}`, principal `{decl_principal}`) recovered task "
                    f"`{accessed_task}` owned by `{task_owner[0]}` (`{task_owner[1]}`), crossing an isolation boundary."
                )

            if cross_leak:
                violations.append(
                    DiscordanceViolation(
                        rule_code="DISC-002",
                        route_id=rid,
                        title=f"Cross-agent or cross-principal continuity leak on route `{rid}` (`{decl_agent}`)",
                        detail=leak_detail,
                        remediation=(
                            "Enforce principal and agent_id namespace isolation in the SDK session/storage "
                            "resolver so shared host/model endpoints cannot read another agent's state."
                        ),
                        source_file=source_file,
                    )
                )
                route_statuses.append(
                    RouteContinuityObservation(
                        route_id=rid,
                        declared_agent_id=decl_agent,
                        declared_principal=decl_principal,
                        continuity_group=cont_group,
                        expected_policy_version=exp_pol_ver,
                        observed_agent_id=obs_agent,
                        observed_hop=obs_hop,
                        observed_policy_version=obs_pol_ver,
                        status="proven_mismatch",
                        missing_receipts=tuple(missing_rcpts),
                        note=leak_detail,
                    )
                )
                continue

            # 2. Missing caller or authz receipts -> `hop_only` or `unverified` (never passed!)
            if missing_rcpts:
                st_kind = "hop_only" if (obs_hop and not caller_rcpt) else "unverified"
                note = (
                    f"Observed hop `{obs_hop}` on `{rid}`, but `caller_receipt_id` is missing; "
                    f"cannot attribute call to `{decl_agent}` (#105)."
                    if st_kind == "hop_only"
                    else f"Route `{rid}` is unverified because {', '.join(missing_rcpts)} is missing."
                )
                route_statuses.append(
                    RouteContinuityObservation(
                        route_id=rid,
                        declared_agent_id=decl_agent,
                        declared_principal=decl_principal,
                        continuity_group=cont_group,
                        expected_policy_version=exp_pol_ver,
                        observed_agent_id=obs_agent,
                        observed_hop=obs_hop,
                        observed_policy_version=obs_pol_ver,
                        status=st_kind,
                        missing_receipts=tuple(missing_rcpts),
                        note=note,
                    )
                )
                continue

            is_device_cap_boundary = bool(
                device_only_caps and _opt_str(ro.get("device_capability_omitted")) in device_only_caps
            )
            is_valid_boundary = explicit_boundary or is_device_cap_boundary

            # 3. Same-agent identity & policy version mismatch (`DISC-001`) checked BEFORE boundary short-circuit!
            frag_reasons: list[str] = []
            if obs_agent != decl_agent:
                frag_reasons.append(f"declared agent `{decl_agent}` resolved to `{obs_agent}`")
            if exp_pol_ver and obs_pol_ver and obs_pol_ver != exp_pol_ver:
                frag_reasons.append(f"policy version drifted (`{obs_pol_ver}` != expected `{exp_pol_ver}`)")
            if (
                not is_valid_boundary
                and cont_group
                and cont_group in group_canary_expected
                and canary_recovered is False
            ):
                frag_reasons.append(
                    f"failed to recover continuity canary `{group_canary_expected[cont_group]}` on `{rid}`"
                )

            if frag_reasons:
                detail_msg = f"Route `{rid}` fragmented same-agent continuity: {'; '.join(frag_reasons)}."
                violations.append(
                    DiscordanceViolation(
                        rule_code="DISC-001",
                        route_id=rid,
                        title=f"Same-agent cross-channel discordance on `{rid}` (`{decl_agent}`)",
                        detail=detail_msg,
                        remediation=(
                            "Bind equivalent owner routes to the same SDK agent identity, continuity scope, "
                            "and policy version, or declare an explicit privacy/device boundary."
                        ),
                        source_file=source_file,
                    )
                )
                route_statuses.append(
                    RouteContinuityObservation(
                        route_id=rid,
                        declared_agent_id=decl_agent,
                        declared_principal=decl_principal,
                        continuity_group=cont_group,
                        expected_policy_version=exp_pol_ver,
                        observed_agent_id=obs_agent,
                        observed_hop=obs_hop,
                        observed_policy_version=obs_pol_ver,
                        status="proven_mismatch",
                        note=detail_msg,
                    )
                )
                continue

            # 4. Missing observed_policy_version or canary_recovered when required -> `unverified`
            extra_missing: list[str] = []
            if exp_pol_ver and not obs_pol_ver:
                extra_missing.append("observed_policy_version")
            if (
                not is_valid_boundary
                and cont_group
                and cont_group in group_canary_expected
                and canary_recovered is None
            ) or (
                task_owner is not None
                and (task_owner[0] != decl_agent or decl_principal != task_owner[1] or explicit_boundary)
                and canary_recovered is None
            ):
                extra_missing.append("canary_recovered")
            if extra_missing:
                route_statuses.append(
                    RouteContinuityObservation(
                        route_id=rid,
                        declared_agent_id=decl_agent,
                        declared_principal=decl_principal,
                        continuity_group=cont_group,
                        expected_policy_version=exp_pol_ver,
                        observed_agent_id=obs_agent,
                        observed_hop=obs_hop,
                        observed_policy_version=obs_pol_ver,
                        status="unverified",
                        missing_receipts=tuple(extra_missing),
                        note=f"Route `{rid}` is unverified because {', '.join(extra_missing)} is missing.",
                    )
                )
                continue

            # 5. Valid explicit privacy/session or device-only differences
            if is_valid_boundary:
                route_statuses.append(
                    RouteContinuityObservation(
                        route_id=rid,
                        declared_agent_id=decl_agent,
                        declared_principal=decl_principal,
                        continuity_group=cont_group,
                        expected_policy_version=exp_pol_ver,
                        observed_agent_id=obs_agent,
                        observed_hop=obs_hop,
                        observed_policy_version=obs_pol_ver,
                        status="valid_boundary_difference",
                        note="Explicit privacy/session or device-capability boundary honored.",
                    )
                )
                continue

            # 6. Cache miss or differing wording explicitly noted as benign, never identity drift
            benign_notes: list[str] = []
            if cache_hit is False:
                benign_notes.append("KV-cache miss ignored (not identity drift)")
            if wording_differs:
                benign_notes.append("surface wording variance ignored (not identity drift)")
            if benign_notes:
                notes.append(f"Route '{rid}': {', '.join(benign_notes)}.")
            route_statuses.append(
                RouteContinuityObservation(
                    route_id=rid,
                    declared_agent_id=decl_agent,
                    declared_principal=decl_principal,
                    continuity_group=cont_group,
                    expected_policy_version=exp_pol_ver,
                    observed_agent_id=obs_agent,
                    observed_hop=obs_hop,
                    observed_policy_version=obs_pol_ver,
                    status="supported",
                    note="; ".join(benign_notes) if benign_notes else "Continuity & policy verified.",
                )
            )

        # Aggregate worst-case status for `rid` across all receipts (fail-closed lattice)
        rank = {
            "proven_mismatch": 0,
            "hop_only": 1,
            "unverified": 2,
            "valid_boundary_difference": 3,
            "supported": 4,
        }
        chosen_obs = min(route_statuses, key=lambda o: rank.get(o.status, 99))
        observations.append(chosen_obs)
        if chosen_obs.status == "proven_mismatch":
            mismatched.append(rid)
        elif chosen_obs.status == "hop_only":
            hop_only.append(rid)
        elif chosen_obs.status == "unverified":
            unverified.append(rid)
        elif chosen_obs.status == "valid_boundary_difference":
            valid_boundaries.append(rid)
        else:
            supported.append(rid)

    return DiscordanceEvaluationReport(
        evaluated_route_count=len(observations),
        supported_routes=supported,
        valid_boundary_routes=valid_boundaries,
        hop_only_routes=hop_only,
        unverified_routes=unverified,
        mismatched_routes=mismatched,
        route_observations=observations,
        violations=violations,
        notes=notes,
    )
