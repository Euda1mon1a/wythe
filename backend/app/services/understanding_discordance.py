"""Core domain-neutral schemas & evaluators for #117 single-view divergence & continuity.

Provides three orthogonal read-only capabilities layered onto the 6-link Understanding Chain:
1. Rule vs. Implementation Prediction(s) vs. Observed Result (`RulePredictionComparison`),
   enforcing positive delivery receipts (`#104`) on open downstream notifications.
2. Participant Epistemic State at Decision Time (`FirstDivergencePoint`), separating
   `exists_in_storage`, `eligible_for_actor`, and `present_in_turn`, and separating
   endpoint hop observation (`hop_only`) from caller attribution (`caller_verified`, `#105`).
3. Single-Variable Perturbation Matrix (`PerturbationCaseResult`) and Evidence-Linked
   Verdict Clauses (`VerdictClause`) where missing receipts force `unverified`.
"""

from __future__ import annotations

import re
import urllib.parse
from collections.abc import Mapping, Sequence
from typing import Any, Literal

from pydantic import Field

from app.schemas.atlas import StrictSchema

FactPresenceState = Literal["present", "absent", "unverified"]
CallerAttributionState = Literal["caller_verified", "hop_only", "unverified", "conflicting"]
PredictionMatchState = Literal[
    "consistent_with_observation",
    "refuted_by_observation",
    "undistinguished",
    "unverified",
]
VerdictClauseState = Literal["supported", "unverified", "degraded_or_drifted", "indeterminate"]

_MAX_ANALYZED_TEXT_CHARS = 16_384
_SAFE_VERDICT_URL_RE = re.compile(r"^[A-Za-z0-9_./:#?&=%~+-]{1,240}$")
_SAFE_FRAGMENT_RE = re.compile(r"^[A-Za-z0-9_.:-]{1,120}$")
_SAFE_PATH_SEG_RE = re.compile(r"^[A-Za-z0-9_.-]{1,120}$")
_FILE_LINE_SUFFIX_RE = re.compile(r"^([^:]+):(\d+)(?::\d+)?$")
_FB_CLEAN_RE = re.compile(r"[^A-Za-z0-9_.-]")
_CTRL_WS_RE = re.compile(r"[\x00-\x20\x7f]")
_VERDICT_TEXT_CTRL_RE = re.compile(r"[\x00-\x1f\x7f]+")
_KNOWN_SOURCE_LOC_EXTS = frozenset(
    {
        ".py",
        ".ts",
        ".tsx",
        ".js",
        ".jsx",
        ".mjs",
        ".cjs",
        ".json",
        ".yaml",
        ".yml",
        ".toml",
        ".sql",
        ".md",
        ".txt",
        ".html",
        ".css",
        ".scss",
        ".rs",
        ".go",
        ".java",
        ".kt",
        ".swift",
        ".c",
        ".cc",
        ".cpp",
        ".h",
        ".hpp",
        ".sh",
        ".tf",
        ".proto",
        ".graphql",
    }
)


def _pick_val(mapping: Mapping[str, Any], *keys: str, default: Any = None) -> Any:
    for key in keys:
        if key in mapping and mapping[key] is not None:
            return mapping[key]
    return default


def _clean_opt_str(value: Any) -> str | None:
    if value is None or isinstance(value, bool):
        return None
    text = str(value).strip()
    return text if text else None


def _strict_bool(value: Any, *, default: bool = False) -> bool:
    if isinstance(value, bool):
        return value
    if isinstance(value, (int, float)):
        if value == 0:
            return False
        if value == 1:
            return True
    if isinstance(value, str):
        low = value.strip().lower()
        if low in ("true", "1", "yes"):
            return True
        if low in ("false", "0", "0.0", "no", "none", "null", ""):
            return False
    return default


def _sanitize_http_receipt_url(cleaned: str) -> str | None:
    if not cleaned.lower().startswith(("http://", "https://")):
        return None
    if not _SAFE_VERDICT_URL_RE.match(cleaned):
        return None
    parts = urllib.parse.urlsplit(cleaned)
    if parts.scheme.lower() not in ("http", "https") or not parts.hostname:
        return None
    if parts.username is not None or parts.password is not None:
        return None
    try:
        _ = parts.port
    except ValueError:
        return None
    return cleaned


def _sanitize_repo_relative_target(cleaned: str, *, normalize_line_anchor: bool) -> str | None:
    if (
        not cleaned
        or len(cleaned) > 240
        or cleaned.startswith(("/", "\\"))
        or "\\" in cleaned
        or any(ch in cleaned for ch in ("?", "&", "=", "(", ")", "[", "]", "<", ">"))
    ):
        return None
    path_and_line, sep_hash, frag = cleaned.partition("#")
    if sep_hash and not _SAFE_FRAGMENT_RE.match(frag):
        return None
    m_line = _FILE_LINE_SUFFIX_RE.match(path_and_line)
    if m_line is not None:
        rel_path, line_no = m_line.group(1), m_line.group(2)
        low_rel = rel_path.lower()
        if "/" not in rel_path and not any(low_rel.endswith(ext) for ext in _KNOWN_SOURCE_LOC_EXTS):
            return None
    else:
        rel_path, line_no = path_and_line, None
        if ":" in rel_path:
            return None
    segs = rel_path.split("/")
    if not segs or any(seg in ("", ".", "..") or not _SAFE_PATH_SEG_RE.match(seg) for seg in segs):
        return None
    if line_no is not None and sep_hash:
        return f"{rel_path}#{frag}"
    if normalize_line_anchor and line_no is not None:
        return f"{rel_path}#L{line_no}"
    return cleaned


_FORBIDDEN_EVIDENCE_REF_SCHEMES = frozenset(
    {
        "javascript",
        "vbscript",
        "data",
        "file",
        "blob",
        "about",
        "mailto",
        "tel",
        "sms",
        "shortcuts",
        "intent",
        "http",
        "https",
        "ftp",
        "ws",
        "wss",
        "ssh",
        "git",
    }
)
_SAFE_EVIDENCE_REF_RE = re.compile(r"^[A-Za-z0-9_./#-][A-Za-z0-9_.:/#-]{0,239}$")


def _sanitize_verdict_evidence_ref(raw_ref: str | None) -> str | None:
    if not raw_ref:
        return None
    cleaned = _CTRL_WS_RE.sub("", raw_ref.strip())
    if (
        not cleaned
        or "://" in cleaned
        or cleaned.startswith(("/", "\\", "//"))
        or ".." in cleaned
        or not _SAFE_EVIDENCE_REF_RE.match(cleaned)
    ):
        return None
    if ":" in cleaned:
        scheme_cand = cleaned.split(":", 1)[0].lower()
        if scheme_cand in _FORBIDDEN_EVIDENCE_REF_SCHEMES or scheme_cand.startswith("ms-"):
            return None
    return cleaned


def _sanitize_verdict_source_location(raw_loc: str | None) -> str | None:
    if not raw_loc:
        return None
    cleaned = _CTRL_WS_RE.sub("", raw_loc.strip())
    if not cleaned:
        return None
    return _sanitize_repo_relative_target(cleaned, normalize_line_anchor=False)


def _sanitize_markdown_target(
    raw_target: str | None,
    fallback_id: str,
    *,
    verified: bool = True,
) -> str:
    safe_fb = _FB_CLEAN_RE.sub("_", fallback_id).strip("._")[:120] or "clause"
    if not verified or not raw_target:
        return f"#unverified:{safe_fb}"
    cleaned = _CTRL_WS_RE.sub("", raw_target.strip())
    if not cleaned:
        return f"#unverified:{safe_fb}"
    valid_rel = _sanitize_repo_relative_target(cleaned, normalize_line_anchor=True)
    if valid_rel is not None:
        return valid_rel
    if "://" not in cleaned and not cleaned.startswith("//"):
        safe_ev = re.sub(r"[^A-Za-z0-9_.:-]", "_", cleaned).strip("._:")[:120]
        if safe_ev:
            return f"#evidence:{safe_ev}"
    return f"#unverified:{safe_fb}"


class OwnerRuleSpec(StrictSchema):
    """Owner-declared domain or operational rule linked to its canonical source."""

    rule_id: str
    label: str
    statement: str
    source_ref: str
    authority_ref: str | None = None


class ImplementationPrediction(StrictSchema):
    """What one reading or branch of the implementation predicts before and at a boundary."""

    prediction_id: str
    reading_label: str
    predicted_before_boundary: str = ""
    predicted_at_boundary: str
    source_ref: str
    match_state: PredictionMatchState = "undistinguished"


class ObservedBoundaryResult(StrictSchema):
    """Empirical or captured observation distinguishing implementation predictions."""

    observation_id: str
    summary: str
    observed_at: str | None = None
    source_ref: str
    delivery_verified: bool = False
    delivery_receipt_ref: str | None = None


class RulePredictionComparison(StrictSchema):
    """AC 1: Owner rule, implementation predictions, and observed result in one record."""

    comparison_id: str
    subject_id: str
    owner_rule: OwnerRuleSpec
    implementation_predictions: list[ImplementationPrediction] = Field(default_factory=list)
    observed_result: ObservedBoundaryResult | None = None
    discriminating_observation: str | None = None
    matched_prediction_ids: list[str] = Field(default_factory=list)
    refuted_prediction_ids: list[str] = Field(default_factory=list)
    open_questions: list[str] = Field(default_factory=list)
    state: Literal["supported", "degraded_or_drifted", "unverified", "unresolved"] = "unverified"
    missing_joins: list[str] = Field(default_factory=list)


class FirstDivergencePoint(StrictSchema):
    """AC 2: First point where observed behavior differed from intent + actor knowledge."""

    divergence_id: str
    stage_label: str
    summary: str
    expected_by_owner: str
    actual_observed: str
    actor: str
    channel: str
    observed_at: str | None = None
    exists_in_storage: FactPresenceState = "unverified"
    storage_source_ref: str | None = None
    eligible_for_actor: FactPresenceState = "unverified"
    eligibility_source_ref: str | None = None
    present_in_turn: FactPresenceState = "unverified"
    turn_context_source_ref: str | None = None
    evidence_reaching_turn: list[str] = Field(default_factory=list)
    observed_hop: str | None = None
    hop_evidence_ref: str | None = None
    caller_attribution_state: CallerAttributionState = "unverified"
    attributed_caller: str | None = None
    caller_receipt_ref: str | None = None
    unattributed_candidate_callers: list[str] = Field(default_factory=list)
    missing_joins: list[str] = Field(default_factory=list)


class PerturbationCaseResult(StrictSchema):
    """AC 3: Single-variable fresh-case perturbation check and missing-receipt detector."""

    case_id: str
    label: str
    varied_factor: str
    held_fixed: list[str] = Field(default_factory=list)
    expected_outcome: str
    observed_outcome: str
    conclusion_state: Literal["supported", "unverified", "failed_regression"]
    passed: bool
    decisive_receipt_ref: str | None = None
    missing_receipt_id: str | None = None
    unverified_conclusion: str | None = None


class VerdictClause(StrictSchema):
    """Single clause in the top-level verdict sentence linked to its exact evidence."""

    clause_id: str
    text: str
    state: VerdictClauseState
    evidence_ref: str | None = None
    source_location: str | None = None
    missing_receipt: str | None = None


def _norm_fact(val: Any) -> FactPresenceState:
    if val is True:
        return "present"
    if val is False:
        return "absent"
    if isinstance(val, str):
        low = val.strip().lower()
        if low in ("present", "true", "yes", "offered", "included", "eligible"):
            return "present"
        if low in ("absent", "false", "no", "missing", "omitted", "excluded", "denied"):
            return "absent"
    return "unverified"


def evaluate_rule_prediction_comparisons(
    raw_items: Sequence[Any],
) -> list[RulePredictionComparison]:
    """Evaluate AC 1 rule-vs-prediction-vs-observation records with fail-closed delivery."""
    results: list[RulePredictionComparison] = []
    for idx, item in enumerate(raw_items):
        if not isinstance(item, Mapping):
            continue
        comp_id = _clean_opt_str(_pick_val(item, "comparison_id", "id")) or f"rule-comp-{idx + 1}"
        subj_id = _clean_opt_str(_pick_val(item, "subject_id", "target")) or comp_id

        raw_rule = _pick_val(item, "owner_rule", default={})
        rule_map = raw_rule if isinstance(raw_rule, Mapping) else {}
        owner_rule = OwnerRuleSpec(
            rule_id=_clean_opt_str(_pick_val(rule_map, "rule_id", "id")) or f"{comp_id}:rule",
            label=_clean_opt_str(_pick_val(rule_map, "label", "title")) or comp_id,
            statement=str(_pick_val(rule_map, "statement", "rule", default="Owner rule statement.")),
            source_ref=_clean_opt_str(_pick_val(rule_map, "source_ref", "source_location"))
            or "unresolved:owner_rule_source",
            authority_ref=_clean_opt_str(_pick_val(rule_map, "authority_ref")),
        )

        preds: list[ImplementationPrediction] = []
        matched_ids: list[str] = []
        refuted_ids: list[str] = []
        for p_idx, rp in enumerate(_pick_val(item, "implementation_predictions", "predictions", default=[]) or []):
            if not isinstance(rp, Mapping):
                continue
            pid = _clean_opt_str(_pick_val(rp, "prediction_id", "id")) or f"{comp_id}:pred-{p_idx + 1}"
            m_raw = str(_pick_val(rp, "match_state", "status", default="undistinguished")).strip().lower()
            m_state: PredictionMatchState = (
                m_raw  # type: ignore[assignment]
                if m_raw in (
                    "consistent_with_observation",
                    "refuted_by_observation",
                    "undistinguished",
                    "unverified",
                )
                else "undistinguished"
            )
            p_src = _clean_opt_str(_pick_val(rp, "source_ref", "source_location"))
            if not p_src:
                m_state = "unverified"
                p_src = "unresolved:prediction_source"
            if m_state == "consistent_with_observation":
                matched_ids.append(pid)
            elif m_state == "refuted_by_observation":
                refuted_ids.append(pid)
            preds.append(
                ImplementationPrediction(
                    prediction_id=pid,
                    reading_label=str(_pick_val(rp, "reading_label", "label", default=pid)),
                    predicted_before_boundary=str(
                        _pick_val(rp, "predicted_before_boundary", "predicted_short_run", default="")
                    ),
                    predicted_at_boundary=str(
                        _pick_val(rp, "predicted_at_boundary", "prediction", default="")
                    ),
                    source_ref=p_src,
                    match_state=m_state,
                )
            )

        missing: list[str] = [
            str(m) for m in (_pick_val(item, "missing_joins", default=[]) or []) if str(m).strip()
        ]
        open_q: list[str] = [
            str(q) for q in (_pick_val(item, "open_questions", default=[]) or []) if str(q).strip()
        ]
        if owner_rule.source_ref.startswith("unresolved:"):
            missing.append("owner_rule_source_reference")

        obs_obj: ObservedBoundaryResult | None = None
        raw_obs = _pick_val(item, "observed_result", "observation")
        requires_delivery = _strict_bool(_pick_val(item, "requires_device_delivery_receipt"), default=False)
        if isinstance(raw_obs, Mapping):
            obs_src = _clean_opt_str(_pick_val(raw_obs, "source_ref", "source_location"))
            deliv_rcpt = _clean_opt_str(_pick_val(raw_obs, "delivery_receipt_ref", "delivery_receipt_id"))
            claimed_deliv = _strict_bool(_pick_val(raw_obs, "delivery_verified"), default=False)
            verified_deliv = bool(claimed_deliv and deliv_rcpt is not None)
            if (claimed_deliv and deliv_rcpt is None) or (requires_delivery and not verified_deliv):
                if "positive_device_delivery_receipt" not in missing:
                    missing.append("positive_device_delivery_receipt")
                if not open_q:
                    open_q.append(
                        "Downstream notification/device delivery remains unverified without a positive delivery receipt."
                    )
            if not obs_src:
                missing.append("observed_boundary_result_source_reference")
                obs_src = "unresolved:observation_source"
            obs_obj = ObservedBoundaryResult(
                observation_id=_clean_opt_str(_pick_val(raw_obs, "observation_id", "id"))
                or f"{comp_id}:obs",
                summary=str(_pick_val(raw_obs, "summary", default="")),
                observed_at=_clean_opt_str(_pick_val(raw_obs, "observed_at")),
                source_ref=obs_src,
                delivery_verified=verified_deliv,
                delivery_receipt_ref=deliv_rcpt if verified_deliv else None,
            )
        else:
            missing.append("discriminating_boundary_observation")

        disc = _clean_opt_str(_pick_val(item, "discriminating_observation"))
        if obs_obj is None or owner_rule.source_ref.startswith("unresolved:"):
            comp_state: Literal["supported", "degraded_or_drifted", "unverified", "unresolved"] = (
                "unresolved"
            )
        elif open_q or missing or not matched_ids:
            comp_state = "degraded_or_drifted" if refuted_ids else "unverified"
        else:
            comp_state = "supported"

        results.append(
            RulePredictionComparison(
                comparison_id=comp_id,
                subject_id=subj_id,
                owner_rule=owner_rule,
                implementation_predictions=preds,
                observed_result=obs_obj,
                discriminating_observation=disc,
                matched_prediction_ids=matched_ids,
                refuted_prediction_ids=refuted_ids,
                open_questions=list(dict.fromkeys(open_q)),
                state=comp_state,
                missing_joins=list(dict.fromkeys(missing)),
            )
        )
    return results


def evaluate_first_divergence(raw_div: Any) -> FirstDivergencePoint | None:
    """Evaluate AC 2 participant knowledge state & caller-vs-hop attribution (#105)."""
    if not isinstance(raw_div, Mapping):
        return None
    div_id = _clean_opt_str(_pick_val(raw_div, "divergence_id", "id")) or "first-divergence-1"
    storage_state = _norm_fact(_pick_val(raw_div, "exists_in_storage"))
    eligible_state = _norm_fact(_pick_val(raw_div, "eligible_for_actor"))
    turn_state = _norm_fact(_pick_val(raw_div, "present_in_turn", "present_in_voice_turn"))

    storage_ref = _clean_opt_str(_pick_val(raw_div, "storage_source_ref"))
    elig_ref = _clean_opt_str(_pick_val(raw_div, "eligibility_source_ref"))
    turn_ref = _clean_opt_str(_pick_val(raw_div, "turn_context_source_ref"))

    missing: list[str] = [
        str(m) for m in (_pick_val(raw_div, "missing_joins", default=[]) or []) if str(m).strip()
    ]
    if storage_state == "present" and not storage_ref:
        storage_state = "unverified"
        missing.append("storage_existence_receipt")
    if eligible_state == "present" and not elig_ref:
        eligible_state = "unverified"
        missing.append("actor_eligibility_policy_source")

    hop = _clean_opt_str(_pick_val(raw_div, "observed_hop", "hop"))
    hop_ref = _clean_opt_str(_pick_val(raw_div, "hop_evidence_ref"))
    caller_rcpt = _clean_opt_str(_pick_val(raw_div, "caller_receipt_ref", "caller_identity_receipt"))
    claimed_caller = _clean_opt_str(_pick_val(raw_div, "attributed_caller", "caller"))
    cand_callers = [
        str(c).strip()
        for c in (_pick_val(raw_div, "unattributed_candidate_callers", "candidate_callers", default=[]) or [])
        if str(c).strip()
    ]

    # Enforce #105: hop observation never attributes a specific caller without caller_receipt_ref
    if caller_rcpt and claimed_caller:
        caller_state: CallerAttributionState = "caller_verified"
        resolved_actor = claimed_caller
    elif hop:
        caller_state = "hop_only"
        if claimed_caller and claimed_caller not in cand_callers:
            cand_callers.append(claimed_caller)
        claimed_caller = None
        resolved_actor = _clean_opt_str(_pick_val(raw_div, "actor")) or f"unattributed_caller_at_{hop}"
        if "caller_identity_receipt_for_observed_hop" not in missing:
            missing.append("caller_identity_receipt_for_observed_hop")
    else:
        caller_state = "unverified"
        claimed_caller = None
        resolved_actor = _clean_opt_str(_pick_val(raw_div, "actor")) or "unverified_caller"
        if "caller_and_hop_identity_receipt" not in missing:
            missing.append("caller_and_hop_identity_receipt")

    ev_in_turn = [
        str(e).strip()
        for e in (_pick_val(raw_div, "evidence_reaching_turn", default=[]) or [])
        if str(e).strip()
    ]
    return FirstDivergencePoint(
        divergence_id=div_id,
        stage_label=str(_pick_val(raw_div, "stage_label", default="Turn Context Assembly")),
        summary=str(_pick_val(raw_div, "summary", default="")),
        expected_by_owner=str(_pick_val(raw_div, "expected_by_owner", default="")),
        actual_observed=str(_pick_val(raw_div, "actual_observed", default="")),
        actor=resolved_actor,
        channel=str(_pick_val(raw_div, "channel", default="unknown")),
        observed_at=_clean_opt_str(_pick_val(raw_div, "observed_at")),
        exists_in_storage=storage_state,
        storage_source_ref=storage_ref,
        eligible_for_actor=eligible_state,
        eligibility_source_ref=elig_ref,
        present_in_turn=turn_state,
        turn_context_source_ref=turn_ref,
        evidence_reaching_turn=ev_in_turn,
        observed_hop=hop,
        hop_evidence_ref=hop_ref,
        caller_attribution_state=caller_state,
        attributed_caller=claimed_caller,
        caller_receipt_ref=caller_rcpt if caller_state == "caller_verified" else None,
        unattributed_candidate_callers=cand_callers,
        missing_joins=list(dict.fromkeys(missing)),
    )


_HORIZ_WS_RE = re.compile(r"[^\S\n]+")
_ALNUM_TOKEN_RE = re.compile(r"[a-z0-9]+")
_KEY_NEG_PREFIX_WORDS = frozenset(
    {"not", "non", "no", "un", "dis", "never", "without", "zero"}
)
_SHORT_PERTURBATION_TOKENS = frozenset(
    {
        "pass",
        "passed",
        "ok",
        "allowed",
        "blocked",
        "denied",
        "rejected",
        "isolated",
        "leaked",
        "fail",
        "failed",
        "supported",
        "unverified",
    }
)
_NEG_MARKER_TOKENS = frozenset(
    {
        "fail",
        "failed",
        "failing",
        "failure",
        "failures",
        "regression",
        "regressions",
        "leak",
        "leaked",
        "leaking",
        "leaks",
        "violated",
        "violation",
        "violations",
        "error",
        "errors",
        "err",
        "exception",
        "exceptions",
        "bypass",
        "bypassed",
        "bypassing",
        "bypasses",
        "exposed",
        "expose",
        "exposing",
        "exposure",
        "unauthorized",
        "unblocked",
        "unredacted",
        "unmasked",
        "broken",
        "breach",
        "breached",
        "breaches",
        "compromised",
        "compromise",
        "exfiltrated",
        "exfiltrate",
        "exfiltration",
        "disclosed",
        "disclose",
        "disclosure",
    }
)
_DEFENSIVE_PHRASE_RE = re.compile(
    r"(?<![a-z0-9])fail[\s_-]+closed(?![a-z0-9])"
    r"|(?<![a-z0-9])(?:no|without|zero|non|not)[\s_-]+(?:(?:any|a|an|the)[\s_-]+)?(?:(?:delivery[\s_-]+)?(?:errors?|failures?|exceptions?)|leaks?|violations?|bypass(?:es)?|breach(?:es)?|compromises?|regressions?)(?![a-z0-9])"
    r"|(?<![a-z0-9])(?:error|errors|err|failure|failures|fault|faults|exception|exceptions|violation|violations|bypass|bypasses|compromise|compromises|regression|regressions|failing|leak|leaks|breach|breaches|exposure|disclosure|exfiltration|pending|queued)[\s_-]*free(?![a-z0-9])"
    r"|(?<![A-Za-z0-9_-])(?P<ekq>['\"]?)(?P<err_prefix>(?:[a-z0-9]{1,48}[_-]{1,4}){0,8})?(?:(?:error|errors|err)(?:[\s_-]*(?:code|count))?(?P=ekq)[\s_:=-]+|(?:failure|failures|fail|failed)[\s_-]*(?:code|count)(?P=ekq)[\s_:=-]+|(?:failure|failures|fail|failed)(?P=ekq)\s*[:=]\s*)(?P<evq>['\"]?)(?:0+(?:\.0+)?|none|null|false|ok)(?P=evq)(?![a-z0-9_]|(?:\.\d))"
)
_BREACH_ERR_PREFIX_WORDS = frozenset(
    {
        "leak",
        "leaks",
        "leaked",
        "leaking",
        "leakage",
        "expose",
        "exposed",
        "exposes",
        "exposing",
        "exposure",
        "disclose",
        "disclosed",
        "discloses",
        "disclosing",
        "disclosure",
        "exfiltrate",
        "exfiltrated",
        "exfiltrates",
        "exfiltrating",
        "exfiltration",
        "breach",
        "breached",
        "breaches",
        "breaching",
        "compromise",
        "compromised",
        "compromises",
        "bypass",
        "bypassed",
        "bypasses",
        "bypassing",
        "unauthorized",
        "unredacted",
        "unmasked",
        "unblocked",
        "violated",
        "violation",
        "violations",
    }
)
_CONTRACTION_NEG_RE = re.compile(
    r"(?<![a-z0-9])(?:wasn'?t|isn'?t|didn'?t|couldn'?t|wouldn'?t|shouldn'?t"
    r"|haven'?t|hasn'?t|hadn'?t|weren'?t|aren'?t|won'?t|can'?t|cannot|don'?t|doesn'?t)(?![a-z0-9])"
)
_NO_LONGER_RE = re.compile(r"(?<![a-z0-9])no[\s_-]+longer(?![a-z0-9])")
_KEY_FALSE_RE = re.compile(
    r"(?<![A-Za-z0-9_-])(?P<kq>['\"]?)"
    r"(?P<kprefix>(?:[a-z0-9]{1,48}[-_]{1,4}){0,8})?"
    r"(?P<key>authorized|ok|allowed|served|success|permitted|granted|accepted|passed|delivered"
    r"|blocked|denied|rejected|refused)"
    r"(?P=kq)\s*[:=]\s*(?P<vq>['\"]?)(?:false|0)(?P=vq)(?![a-z0-9_]|(?:\.\d))"
)


def _defensive_phrase_repl(match: re.Match[str]) -> str:
    err_prefix = match.group("err_prefix")
    if err_prefix and (set(_ALNUM_TOKEN_RE.findall(err_prefix)) & _BREACH_ERR_PREFIX_WORDS):
        return match.group(0)
    return " "


def _key_false_repl(match: re.Match[str]) -> str:
    kprefix = match.group("kprefix") or ""
    if kprefix and (set(_ALNUM_TOKEN_RE.findall(kprefix)) & _KEY_NEG_PREFIX_WORDS):
        return match.group(0)
    return f" not {match.group('key')} "


def _normalize_perturbation_text(raw_low: str) -> str:
    return _HORIZ_WS_RE.sub(
        " ",
        _DEFENSIVE_PHRASE_RE.sub(
            _defensive_phrase_repl,
            _KEY_FALSE_RE.sub(
                _key_false_repl,
                _NO_LONGER_RE.sub("not", _CONTRACTION_NEG_RE.sub("not", raw_low)),
            ),
        ),
    ).strip()


_PROTECTIVE_TOKENS = frozenset(
    {
        "blocked",
        "block",
        "denied",
        "deny",
        "rejected",
        "reject",
        "isolated",
        "isolate",
        "redacted",
        "redact",
        "prohibited",
        "prohibit",
        "refused",
        "refuse",
        "prevented",
        "prevent",
        "disallowed",
        "disallow",
    }
)
_PERMISSIVE_EXPECT_TOKENS = frozenset(
    {
        "allowed",
        "allow",
        "permitted",
        "permit",
        "accepted",
        "accept",
        "granted",
        "grant",
        "succeeded",
        "succeed",
        "passed",
        "pass",
    }
)
_PERMISSIVE_BREACH_TOKENS = _PERMISSIVE_EXPECT_TOKENS | frozenset(
    {
        "authorized",
        "success",
        "bypassed",
        "bypass",
        "exposed",
        "expose",
        "leaked",
        "leak",
        "unauthorized",
        "unblocked",
        "unredacted",
        "unmasked",
        "executed",
        "execute",
        "returned",
        "return",
        "completed",
        "complete",
        "committed",
        "commit",
        "wrote",
        "written",
        "shared",
        "share",
        "served",
        "delivered",
        "plaintext",
        "emitted",
        "emit",
        "exfiltrated",
        "exfiltrate",
        "disclosed",
        "disclose",
        "revealed",
        "reveal",
    }
)
_NEG_PREFIX_WORDS = (
    r"not|never|no|non|cannot"
    r"|wasn'?t|isn'?t|didn'?t|couldn'?t|wouldn'?t|shouldn'?t"
    r"|haven'?t|hasn'?t|hadn'?t|weren'?t|aren'?t|won'?t|can'?t"
)
_NEG_VERB_ADV_MODS = (
    r"(?:(?:be|been|being|have|having|ever|actually|even|yet|really|still|explicitly|"
    r"properly|successfully|directly|fully|just|also|only|to)[\s_-]+){0,5}"
)
_NEG_ABLE_TO_CLAUSE = (
    r"(?:unable|failed|failing"
    r"|(?:(?:not|never)[\s_-]+|without[\s_-]+(?:(?:being|having|getting)[\s_-]+)?)"
    + _NEG_VERB_ADV_MODS
    + r"(?:(?:get|getting|got)[\s_-]+"
    + _NEG_VERB_ADV_MODS
    + r")?able"
    r")[\s_-]+to[\s_-]+"
)
_NEG_VERB_AUX_CLAUSE = (
    r"(?:(?:not|never|without)[\s_-]+"
    + _NEG_VERB_ADV_MODS
    + r"(?:(?:be|been|being|get|getting|got)[\s_-]+"
    + _NEG_VERB_ADV_MODS
    + r")?"
    + r"|(?:"
    + _NEG_PREFIX_WORDS
    + r"|zero)[\s_-]+(?:(?:be|been|being|get|getting|got)[\s_-]+)?"
    + r"|"
    + _NEG_ABLE_TO_CLAUSE
    + _NEG_VERB_ADV_MODS
    + r"(?:(?:be|get)[\s_-]+"
    + _NEG_VERB_ADV_MODS
    + r")?)"
)
_NEGATED_PROTECTIVE_RE = re.compile(
    r"(?<![a-z0-9])"
    + _NEG_VERB_AUX_CLAUSE
    + r"(?:"
    + "|".join(sorted(_PROTECTIVE_TOKENS))
    + r")(?![a-z0-9])"
)
_NEGATED_PERMISSIVE_RE = re.compile(
    r"(?<![a-z0-9])"
    + _NEG_VERB_AUX_CLAUSE
    + r"(?:"
    + "|".join(sorted(_PERMISSIVE_EXPECT_TOKENS))
    + r")(?![a-z0-9])"
)
_NEGATED_PERMISSIVE_TO_RE = re.compile(
    r"(?<![a-z0-9])"
    + _NEG_VERB_AUX_CLAUSE
    + r"(?:"
    + "|".join(sorted(_PERMISSIVE_EXPECT_TOKENS))
    + r")(?=[\s_-]+to(?![a-z0-9]))"
)
_NEGATED_PERMISSIVE_CONFIRM_RE = re.compile(
    r"(?<![a-z0-9])"
    + _NEG_VERB_AUX_CLAUSE
    + r"(?:ok|served?|success|authoriz(?:e|ed)|deliver(?:ed)?)(?![a-z0-9])"
)
_PERMISSIVE_CONFIRM_EXTRA = frozenset({"ok", "served", "success"})
_CLAUSE_DELIM_RE = re.compile(
    r"(?:[;,\n]|(?<!\d)\.(?!\d))+|\b(?:and|but|however|yet|though|although|while)\b"
)
_NEG_YET_PREFIX_RE = re.compile(
    r"(?<![a-z0-9])(?:not|never|without|no[ \t_-]+longer|(?:unable|failed|(?:(?:not|never)[ \t_-]+|without[ \t_-]+(?:(?:being|having|getting)[ \t_-]+)?)(?:(?:be|been|being|have|having|get|getting|got|ever|actually|even|really|still|explicitly|properly|successfully|directly|fully|just|also|only|to)[ \t_-]+){0,5}able)[ \t_-]+to)[ \t_-]+"
    r"(?:(?:be|been|being|have|having|get|getting|got|ever|actually|even|really|still|"
    r"explicitly|properly|successfully|directly|fully|just|also|only|to)[ \t_-]+){0,5}\s*$"
)


def _split_clauses(text: str, *, include_delims: bool = False) -> list[str]:
    parts: list[str] = []
    last = 0
    for match in _CLAUSE_DELIM_RE.finditer(text):
        if match.group(0) == "yet":
            win_start = max(0, match.start() - 120)
            win_low = text[win_start : match.start()].lower()
            if (
                "not" in win_low
                or "never" in win_low
                or "without" in win_low
                or "longer" in win_low
                or "unable" in win_low
                or "failed" in win_low
            ):
                if win_start > 0 and text[win_start - 1].isalnum():
                    win_low = "a" + win_low
                if _NEG_YET_PREFIX_RE.search(win_low):
                    continue
        parts.append(text[last : match.start()])
        if include_delims:
            parts.append(match.group(0))
        last = match.end()
    parts.append(text[last:])
    return parts


_NEGATORS = frozenset({"not", "never", "no", "non", "without", "zero"})
_NOT_NEG_BRIDGE_TOKENS = frozenset(
    {
        "be",
        "been",
        "being",
        "have",
        "had",
        "having",
        "able",
        "ever",
        "actually",
        "even",
        "yet",
        "really",
        "still",
        "explicitly",
        "properly",
        "successfully",
        "directly",
        "fully",
        "just",
        "also",
        "only",
        "to",
        "get",
        "getting",
        "got",
        "any",
        "a",
        "an",
        "the",
    }
)
_INHERENT_BREACH_STATES = frozenset(
    {"bypassed", "unauthorized", "unblocked", "unredacted", "unmasked"}
)
_DIRECT_NEGATABLE_INHERENT_BREACH_STATES = frozenset(
    {"bypassed", "unblocked", "unredacted", "unmasked"}
)
_BENIGN_DETERMINERS = frozenset({"any", "a", "an", "the"})
_BENIGN_OBJECT_NOUNS = frozenset(
    {
        "record",
        "records",
        "data",
        "row",
        "rows",
        "field",
        "fields",
        "item",
        "items",
        "file",
        "files",
        "pii",
        "secret",
        "secrets",
    }
)
_BENIGN_WRITE_NOUNS = frozenset({"write", "writes"})
_BENIGN_WRITE_VERBS = frozenset(
    {"executed", "execute", "committed", "commit", "performed", "applied"}
)
_CREDENTIAL_NOUNS = frozenset({"credential", "credentials"})
_LEAKAGE_NEG_TOKENS = frozenset(
    {
        "leak",
        "leaked",
        "leaking",
        "leaks",
        "exposed",
        "expose",
        "exposing",
        "exposure",
        "exfiltrated",
        "exfiltrate",
        "exfiltration",
        "disclosed",
        "disclose",
        "disclosure",
    }
)
_LEAKAGE_BREACH_TOKENS = frozenset(
    {
        "exposed",
        "expose",
        "leaked",
        "leak",
        "exfiltrated",
        "exfiltrate",
        "disclosed",
        "disclose",
        "revealed",
        "reveal",
        "emitted",
        "emit",
    }
)
_OBJECT_SHARING_TOKENS = frozenset(
    {
        "shared",
        "share",
        "exposed",
        "expose",
        "disclosed",
        "disclose",
        "returned",
        "return",
        "delivered",
    }
)
_OBJECT_SHARING_NEG_TOKENS = _OBJECT_SHARING_TOKENS | _LEAKAGE_NEG_TOKENS
_OBJECT_SHARING_BREACH_TOKENS = _OBJECT_SHARING_TOKENS | _LEAKAGE_BREACH_TOKENS
_FAILURE_NEG_TOKENS = frozenset(
    {
        "fail",
        "failed",
        "failing",
        "failure",
        "failures",
        "error",
        "errors",
        "exception",
        "exceptions",
        "regression",
        "regressions",
    }
)
_BENIGN_PLURAL_CHECK_NOUNS = frozenset({"checks", "tests"})

def _is_lookback_negated(
    clause_tokens: list[str],
    idx: int,
    tok: str,
    *,
    sharing_tokens: frozenset[str],
    leakage_tokens: frozenset[str],
    allow_writes: bool = False,
    allow_check_counts: bool = False,
) -> bool:
    if (
        tok in _INHERENT_BREACH_STATES
        and tok not in _DIRECT_NEGATABLE_INHERENT_BREACH_STATES
    ):
        return False
    inf_window_start = max(0, idx - 7)
    for neg_idx in range(inf_window_start, max(0, idx - 1)):
        if (
            clause_tokens[neg_idx] in ("unable", "failed", "failing")
            and clause_tokens[neg_idx + 1] == "to"
            and all(mid in _NOT_NEG_BRIDGE_TOKENS for mid in clause_tokens[neg_idx + 2 : idx])
        ):
            return True
    neg_window_start = max(0, idx - 8)
    for neg_idx in range(neg_window_start, idx):
        prev = clause_tokens[neg_idx]
        if prev not in _NEGATORS:
            continue
        between = clause_tokens[neg_idx + 1 : idx]
        if prev in ("not", "never"):
            if all(mid in _NOT_NEG_BRIDGE_TOKENS for mid in between):
                return True
        elif tok in _INHERENT_BREACH_STATES:
            continue
        elif prev == "without":
            if all(mid in _NOT_NEG_BRIDGE_TOKENS for mid in between) or (
                tok in sharing_tokens
                and bool(between)
                and any(mid in _BENIGN_OBJECT_NOUNS for mid in between)
                and all(mid in (_BENIGN_OBJECT_NOUNS | _BENIGN_DETERMINERS) for mid in between)
            ):
                return True
        elif prev in ("no", "zero"):
            if (
                all(mid in _NOT_NEG_BRIDGE_TOKENS for mid in between)
                or (
                    tok in sharing_tokens
                    and bool(between)
                    and any(mid in _BENIGN_OBJECT_NOUNS for mid in between)
                    and all(mid in (_BENIGN_OBJECT_NOUNS | _BENIGN_DETERMINERS) for mid in between)
                )
                or (
                    tok in leakage_tokens
                    and bool(between)
                    and any(mid in _CREDENTIAL_NOUNS for mid in between)
                    and all(mid in (_CREDENTIAL_NOUNS | _BENIGN_DETERMINERS) for mid in between)
                )
                or (
                    allow_writes
                    and tok in _BENIGN_WRITE_VERBS
                    and bool(between)
                    and any(mid in _BENIGN_WRITE_NOUNS for mid in between)
                    and all(mid in (_BENIGN_WRITE_NOUNS | _BENIGN_DETERMINERS) for mid in between)
                )
                or (
                    allow_check_counts
                    and tok in _FAILURE_NEG_TOKENS
                    and bool(between)
                    and any(mid in _BENIGN_PLURAL_CHECK_NOUNS for mid in between)
                    and all(
                        mid in (_BENIGN_PLURAL_CHECK_NOUNS | _BENIGN_DETERMINERS)
                        for mid in between
                    )
                )
            ):
                return True
        elif prev == "non" and all(mid in _NOT_NEG_BRIDGE_TOKENS for mid in between):
            return True
    return False


_HTTP_OUTCOME_VERBS = (
    r"(?:return(?:ed|ing)?|responded|respond(?:ing)?|repl(?:y|ied|ying)"
    r"|deliver(?:ed|ing)?|receiv(?:e|ed|ing)|achiev(?:e|ed|ing)|observ(?:e|ed|ing)"
    r"|creat(?:e|ed|ing)|accept(?:ed|ing)?"
    r"|emit(?:ted|ting)?|yield(?:ed|ing)?|produce(?:d|ing)?|send(?:ing)?|sent"
    r"|giv(?:e|en|ing)|gave|got(?:ten)?|get(?:ting)?|serv(?:e|ed|ing))"
)
_HTTP_OUTCOME_BASE_VERBS = (
    r"(?:return|respond|reply|deliver|receive|achieve|observe|create|accept|emit|yield|produce|send|give|get|serve)"
)
_HTTP_STATUS_PREFIX_WORDS = (
    r"http[-_]status[-_]code|http[-_]status|response[-_]status|response[-_]code"
    r"|status[-_]code|http[-_]code|status|code|response"
)
_HTTP_STATUS_OR_VER_PREFIX = (
    r"(?:http(?:/\d+(?:\.\d+)?)?|" + _HTTP_STATUS_PREFIX_WORDS + r")[\s_:=-]+"
)
_NEG_ALLOWED_TO_PREFIX = (
    r"(?:(?:not|never|without)[\s_-]+"
    + _NEG_VERB_ADV_MODS
    + r"(?:(?:be|been|being|get|getting|got)[\s_-]+"
    + _NEG_VERB_ADV_MODS
    + r")?"
    + r"|(?:"
    + _NEG_PREFIX_WORDS
    + r")[\s_-]+(?:(?:be|been|being|get|getting|got)[\s_-]+)?)"
)
_HTTP_4XX_5XX_REASON_SUFFIX = (
    r"(?:[\s_:-]+(?:(?:forbidden|unauthorized|bad[\s_-]+request|not[\s_-]+found"
    r"|method[\s_-]+not[\s_-]+allowed|(?:internal[\s_-]+)?server|(?:bad[\s_-]+)?gateway"
    r"|service[\s_-]+unavailable|gateway[\s_-]+timeout|too[\s_-]+many[\s_-]+requests"
    r"|request[\s_-]+timeout|conflict|unprocessable[\s_-]+(?:entity|content))"
    r"(?:[\s_-]+error)?|error))?"
)
_NEGATED_4XX_5XX_RE = re.compile(
    r"(?<![a-z0-9])(?:" + _NEG_PREFIX_WORDS + r"|without|zero)[\s_-]+"
    r"(?:(?:any|a|an|the)[\s_-]+)?"
    r"(?:" + _HTTP_STATUS_OR_VER_PREFIX + r")?"
    r"(?:\(\s*(?:4\d\d|5\d\d)\s*\)|(?:4\d\d|5\d\d))"
    + _HTTP_4XX_5XX_REASON_SUFFIX
    + r"(?![a-z0-9])"
)
_4XX_5XX_VERB_TAIL = (
    r"[\s_-]+(?:with[\s_-]+)?"
    r"(?:(?:any|a|an|the)[\s_-]+)?"
    r"(?:" + _HTTP_STATUS_OR_VER_PREFIX + r")?"
    r"(?:\(\s*(?:4\d\d|5\d\d)\s*\)|(?:4\d\d|5\d\d))"
    + _HTTP_4XX_5XX_REASON_SUFFIX
    + r"(?![a-z0-9])"
)
_NEGATED_VERB_4XX_5XX_RE = re.compile(
    r"(?<![a-z0-9])(?:"
    r"(?:not|never)[\s_-]+" + _NEG_VERB_ADV_MODS + _HTTP_OUTCOME_VERBS
    + r"|" + _NEG_ABLE_TO_CLAUSE + _NEG_VERB_ADV_MODS + r"(?:" + _HTTP_OUTCOME_BASE_VERBS + r"|(?:be|get)[\s_-]+" + _NEG_VERB_ADV_MODS + _HTTP_OUTCOME_VERBS + r")"
    + r"|" + _NEG_ALLOWED_TO_PREFIX + r"(?:allowed|permitted|authorized|granted|accepted)[\s_-]+to[\s_-]+(?:" + _HTTP_OUTCOME_BASE_VERBS + r"|(?:be|get)[\s_-]+" + _HTTP_OUTCOME_VERBS + r")"
    + r"|without[\s_-]+" + _NEG_VERB_ADV_MODS + _HTTP_OUTCOME_VERBS
    + r")" + _4XX_5XX_VERB_TAIL
)
_PASSIVE_NEGATED_4XX_5XX_RE = re.compile(
    r"(?<![a-z0-9])"
    r"(?:" + _HTTP_STATUS_OR_VER_PREFIX + r")?"
    r"(?:\(\s*(?:4\d\d|5\d\d)\s*\)|(?:4\d\d|5\d\d))"
    + _HTTP_4XX_5XX_REASON_SUFFIX
    + r"[\s_-]+(?:"
    + r"(?:(?:was|were|is|are|has|have|had|did|could|would|should)[\s_-]+)?(?:not|never)[\s_-]+"
    + _NEG_VERB_ADV_MODS
    + r"(?:(?:be|been|being|get|getting|got|gotten)[\s_-]+"
    + _NEG_VERB_ADV_MODS
    + r")?"
    + r"|without[\s_-]+"
    + _NEG_VERB_ADV_MODS
    + r"(?:be|been|being|get|getting|got|gotten)[\s_-]+"
    + _NEG_VERB_ADV_MODS
    + r"|(?:(?:was|were|is|are|has|have|had|did|could|would|should)[\s_-]+)?" + _NEG_ABLE_TO_CLAUSE
    + _NEG_VERB_ADV_MODS
    + r"(?:be|get)[\s_-]+"
    + _NEG_VERB_ADV_MODS
    + r")"
    + r"(?:returned|received|delivered|sent|served|emitted|produced|yielded|given|achieved|observed|seen|triggered|reached|applied|issued|raised)(?![a-z0-9])"
)


def _strip_negated_4xx_5xx(text: str) -> str:
    parts = _split_clauses(text, include_delims=True)
    return "".join(
        _PASSIVE_NEGATED_4XX_5XX_RE.sub(
            " ",
            _NEGATED_VERB_4XX_5XX_RE.sub(" ", _NEGATED_4XX_5XX_RE.sub(" ", part)),
        )
        if idx % 2 == 0
        else part
        for idx, part in enumerate(parts)
    )

_BREACH_INFINITIVE_TARGETS = (
    (
        _PERMISSIVE_BREACH_TOKENS
        | _LEAKAGE_NEG_TOKENS
        | {
            "bypass",
            "bypasses",
            "bypassing",
            "violate",
            "violates",
            "violating",
            "breach",
            "breaches",
            "breaching",
            "compromise",
            "compromises",
            "compromising",
        }
    )
    - (_INHERENT_BREACH_STATES - _DIRECT_NEGATABLE_INHERENT_BREACH_STATES)
)


def _extract_unnegated_neg_markers(
    text: str, *, ignore_failed_breach_infinitive: bool = False
) -> set[str]:
    found: set[str] = set()
    for clause in _split_clauses(text):
        clause_tokens = _ALNUM_TOKEN_RE.findall(clause)
        for idx, tok in enumerate(clause_tokens):
            if tok in _NEG_MARKER_TOKENS:
                if (
                    ignore_failed_breach_infinitive
                    and tok in ("failed", "failing")
                    and idx + 2 < len(clause_tokens)
                    and clause_tokens[idx + 1] == "to"
                ):
                    target_idx = idx + 2
                    bridge_limit = min(len(clause_tokens), idx + 7)
                    while (
                        target_idx < bridge_limit
                        and clause_tokens[target_idx] in _NOT_NEG_BRIDGE_TOKENS
                    ):
                        target_idx += 1
                    if (
                        target_idx < len(clause_tokens)
                        and clause_tokens[target_idx] in _BREACH_INFINITIVE_TARGETS
                    ):
                        continue
                if _is_lookback_negated(
                    clause_tokens,
                    idx,
                    tok,
                    sharing_tokens=_OBJECT_SHARING_NEG_TOKENS,
                    leakage_tokens=_LEAKAGE_NEG_TOKENS,
                    allow_check_counts=True,
                ):
                    continue
                found.add(tok)
    return found


_HTTP_401_UNAUTHORIZED_RE = re.compile(
    r"(?<![a-z0-9])"
    r"(?P<neg>(?:" + _NEG_PREFIX_WORDS + r"|without|zero)[\s_-]+)?"
    r"(?:" + _HTTP_STATUS_OR_VER_PREFIX + r")?"
    r"(?:\(\s*401\s*\)|401)[\s_:,-]+unauthorized(?![a-z0-9])"
)
_HTTP_5XX_SERVER_ERROR_RE = re.compile(
    r"(?<![a-z0-9])"
    r"(?:" + _HTTP_STATUS_OR_VER_PREFIX + r")?"
    r"(?:"
    r"(?:\(\s*(?P<code1>(?:4\d\d|5\d\d))\s*\)|(?P<code2>(?:4\d\d|5\d\d)))"
    r"[\s_:,-]+(?:(?:(?:internal[\s_-]+)?server|(?:bad[\s_-]+)?gateway"
    r"|service[\s_-]+unavailable|gateway[\s_-]+timeout|bad[\s_-]+request"
    r"|unauthorized|forbidden|not[\s_-]+found|method[\s_-]+not[\s_-]+allowed"
    r"|not[\s_-]+acceptable|not[\s_-]+implemented|conflict"
    r"|too[\s_-]+many[\s_-]+requests|unprocessable[\s_-]+(?:entity|content)"
    r"|request[\s_-]+timeout)[\s_-]+)?errors?(?![a-z0-9])"
    r"|(?:\(\s*(?P<code4_1>4\d\d)\s*\)|(?P<code4_2>4\d\d))"
    r"[\s_:,-]+(?P<qual4>(?:[a-z0-9]{1,32}[\s_-]+){1,3})errors?(?![a-z0-9])"
    r")"
)
_DISALLOWED_4XX_ERROR_QUALIFIERS = (
    _PERMISSIVE_BREACH_TOKENS
    | _LEAKAGE_NEG_TOKENS
    | frozenset(
        {
            "not",
            "never",
            "without",
            "zero",
            "bypass",
            "bypasses",
            "bypassing",
            "violated",
            "violation",
            "violations",
            "breach",
            "breached",
            "breaches",
            "compromise",
            "compromised",
            "regression",
            "regressions",
        }
    )
) - frozenset({"unauthorized"})


def _collect_negated_4xx_5xx_spans(text: str) -> list[tuple[int, int]]:
    return (
        [m.span() for m in _NEGATED_4XX_5XX_RE.finditer(text)]
        + [m.span() for m in _NEGATED_VERB_4XX_5XX_RE.finditer(text)]
        + [m.span() for m in _PASSIVE_NEGATED_4XX_5XX_RE.finditer(text)]
    )


_UNNEG_5XX_STATUS_RE = re.compile(
    r"(?<![a-z0-9_-])(?:\(\s*5\d\d\s*\)|5\d\d)(?![a-z0-9_-])"
)


def _replace_unnegated_5xx_server_error(text: str, *, allow_5xx: bool = True) -> str:
    neg_spans = _collect_negated_4xx_5xx_spans(text)

    def _repl(match: re.Match[str]) -> str:
        s_start, s_end = match.span()
        if any(s_start < n_end and n_start < s_end for n_start, n_end in neg_spans):
            return match.group(0)
        qual4 = match.group("qual4")
        if qual4:
            q_toks = set(_ALNUM_TOKEN_RE.findall(qual4))
            if q_toks & _DISALLOWED_4XX_ERROR_QUALIFIERS:
                return match.group(0)
        code = (
            match.group("code4_1")
            or match.group("code4_2")
            or match.group("code1")
            or match.group("code2")
        )
        if code and code.startswith("5") and not allow_5xx:
            return match.group(0)
        return f" {code} "

    return _HTTP_5XX_SERVER_ERROR_RE.sub(_repl, text)


def _replace_unnegated_401_unauthorized(text: str) -> str:
    neg_spans = _collect_negated_4xx_5xx_spans(text)

    def _repl(match: re.Match[str]) -> str:
        if match.group("neg"):
            return match.group(0)
        s_start, s_end = match.span()
        if any(s_start < n_end and n_start < s_end for n_start, n_end in neg_spans):
            return match.group(0)
        return " 401 "

    return _HTTP_401_UNAUTHORIZED_RE.sub(_repl, text)

_HTTP_2XX_REASON_SUFFIX = (
    r"(?:[\s_-]+(?:ok|created|accepted|no[\s_-]+content|success|succeeded|served))?"
)
_2XX_VERB_TAIL = (
    r"[\s_-]+(?:with[\s_-]+)?"
    r"(?:(?:any|a|an|the)[\s_-]+)?"
    r"(?:" + _HTTP_STATUS_OR_VER_PREFIX + r")?"
    r"(?:\(\s*(?:200|201|202|204)\s*\)|(?:200|201|202|204))"
    + _HTTP_2XX_REASON_SUFFIX
    + r"(?![a-z0-9])"
)
_NEGATED_VERB_2XX_RE = re.compile(
    r"(?<![a-z0-9])(?:"
    r"(?:not|never)[\s_-]+" + _NEG_VERB_ADV_MODS + _HTTP_OUTCOME_VERBS
    + r"|" + _NEG_ABLE_TO_CLAUSE + _NEG_VERB_ADV_MODS + r"(?:" + _HTTP_OUTCOME_BASE_VERBS + r"|(?:be|get)[\s_-]+" + _NEG_VERB_ADV_MODS + _HTTP_OUTCOME_VERBS + r")"
    + r"|" + _NEG_ALLOWED_TO_PREFIX + r"(?:allowed|permitted|authorized|granted|accepted)[\s_-]+to[\s_-]+(?:" + _HTTP_OUTCOME_BASE_VERBS + r"|(?:be|get)[\s_-]+" + _HTTP_OUTCOME_VERBS + r")"
    + r"|without[\s_-]+" + _NEG_VERB_ADV_MODS + _HTTP_OUTCOME_VERBS
    + r")" + _2XX_VERB_TAIL
)
_PASSIVE_NEGATED_2XX_RE = re.compile(
    r"(?<![a-z0-9])"
    r"(?:" + _HTTP_STATUS_OR_VER_PREFIX + r")?"
    r"(?:\(\s*(?:200|201|202|204)\s*\)|(?:200|201|202|204))"
    + _HTTP_2XX_REASON_SUFFIX
    + r"[\s_-]+(?:"
    + r"(?:(?:was|were|is|are|has|have|had|did|could|would|should)[\s_-]+)?(?:not|never)[\s_-]+"
    + _NEG_VERB_ADV_MODS
    + r"(?:(?:be|been|being|get|getting|got|gotten)[\s_-]+"
    + _NEG_VERB_ADV_MODS
    + r")?"
    + r"|without[\s_-]+"
    + _NEG_VERB_ADV_MODS
    + r"(?:be|been|being|get|getting|got|gotten)[\s_-]+"
    + _NEG_VERB_ADV_MODS
    + r"|(?:(?:was|were|is|are|has|have|had|did|could|would|should)[\s_-]+)?" + _NEG_ABLE_TO_CLAUSE
    + _NEG_VERB_ADV_MODS
    + r"(?:be|get)[\s_-]+"
    + _NEG_VERB_ADV_MODS
    + r")"
    + r"(?:returned|received|delivered|sent|served|created|accepted|emitted|produced|yielded|given|achieved|observed|seen|triggered|reached|issued)(?![a-z0-9])"
)
_PERMISSIVE_FAILURE_WORDS = _PROTECTIVE_TOKENS | frozenset(
    {
        "forbidden",
        "unauthorized",
        "timeout",
        "throttled",
        "unavailable",
        "dropped",
        "aborted",
        "cancelled",
        "canceled",
        "conflict",
    }
)
_NEGATED_PERMISSIVE_FAILURE_RE = re.compile(
    r"(?<![a-z0-9])"
    + _NEG_VERB_AUX_CLAUSE
    + r"(?:(?:any|a|an|the)[\s_-]+)?"
    + r"(?:tim(?:e|ed)[\s_-]+out|rate[\s_-]+limit(?:s|ed|ing)?(?:[\s_-]+(?:exceeded|triggered|hit|reached|applied))?|"
    + "|".join(sorted(_PERMISSIVE_FAILURE_WORDS, key=len, reverse=True))
    + r")(?![a-z0-9])"
    r"|(?<![a-z0-9])rate[\s_-]+limit(?:s|ed|ing)?[\s_-]+(?:"
    r"(?:(?:was|were|is|are|has|have|had|will|would|could|should|may|might|must|can|do|does|did)[\s_-]+)?(?:"
    + _NEG_PREFIX_WORDS
    + r"|without)[\s_-]+"
    + _NEG_VERB_ADV_MODS
    + r"(?:(?:(?:get|getting|got)[\s_-]+"
    + _NEG_VERB_ADV_MODS
    + r")?able[\s_-]+to[\s_-]+)?"
    + r"|(?:(?:was|were|is|are|has|have|had|get|getting|got)[\s_-]+(?:been[\s_-]+)?)?(?:unable|failed|failing)[\s_-]+to[\s_-]+"
    + _NEG_VERB_ADV_MODS
    + r")(?:(?:be|been|being|get|getting|got)[\s_-]+"
    + _NEG_VERB_ADV_MODS
    + r")?(?:exceeded|reached|hit|triggered|applied)(?![a-z0-9])"
    r"|(?<![a-z0-9])rate[\s_-]+limit(?:s|ed|ing)?[\s_-]+(?:"
    r"(?:(?:do|does|did|can|could|will|would|may|might|must|should)[\s_-]+(?:not|never)|didn'?t|couldn'?t|wouldn'?t|shouldn'?t|doesn'?t|don'?t|can'?t|cannot|won'?t|not|never)[\s_-]+"
    + _NEG_VERB_ADV_MODS
    + r"(?:(?:(?:get|getting|got)[\s_-]+"
    + _NEG_VERB_ADV_MODS
    + r")?able[\s_-]+to[\s_-]+)?"
    + r"|(?:(?:was|were|is|are|has|have|had)[\s_-]+(?:not|never)|wasn'?t|weren'?t|isn'?t|aren'?t|hasn'?t|haven'?t|hadn'?t)[\s_-]+"
    + _NEG_VERB_ADV_MODS
    + r"(?:(?:get|getting|got)[\s_-]+"
    + _NEG_VERB_ADV_MODS
    + r")?able[\s_-]+to[\s_-]+"
    + r"|(?:(?:was|were|is|are|has|have|had|get|getting|got)[\s_-]+(?:been[\s_-]+)?)?(?:unable|failed|failing)[\s_-]+to[\s_-]+"
    + r"|without[\s_-]+(?:(?:being|having|getting)[\s_-]+)?"
    + _NEG_VERB_ADV_MODS
    + r"(?:(?:get|getting|got)[\s_-]+"
    + _NEG_VERB_ADV_MODS
    + r")?able[\s_-]+to[\s_-]+"
    + r")"
    + _NEG_VERB_ADV_MODS
    + r"(?:exceed|reach|hit|trigger|apply)(?![a-z0-9])"
    r"|(?<![a-z0-9])rate[\s_-]+limit(?:s|ed|ing)?[\s_-]+(?:(?:was|were|is|are|has|have|had)[\s_-]+(?:not|never)|wasn'?t|weren'?t|isn'?t|aren'?t|hasn'?t|haven'?t|hadn'?t|not|never|without)[\s_-]+"
    + _NEG_VERB_ADV_MODS
    + r"(?:been[\s_-]+)?"
    + r"(?:exceeding|reaching|hitting|triggering|applying)(?![a-z0-9])"
    r"|(?<![a-z0-9])(?:"
    r"(?:(?:do|does|did|can|could|will|would|may|might|must|should|was|were|is|are|has|have|had)[\s_-]+)?(?:not|never|without|cannot|can'?t|won'?t|don'?t|doesn'?t|didn'?t|couldn'?t|wouldn'?t|shouldn'?t|wasn'?t|weren'?t|isn'?t|aren'?t|hasn'?t|haven'?t|hadn'?t)[\s_-]+"
    r"|(?:(?:was|were|is|are|has|have|had|get|getting|got)[\s_-]+(?:been[\s_-]+)?)?(?:unable|failed|failing)[\s_-]+to[\s_-]+"
    r"|(?:(?:was|were|is|are|has|have|had)[\s_-]+)?(?:(?:not|never)[\s_-]+|without[\s_-]+(?:(?:being|having|getting)[\s_-]+)?)"
    + _NEG_VERB_ADV_MODS
    + r"(?:(?:get|getting|got)[\s_-]+"
    + _NEG_VERB_ADV_MODS
    + r")?able[\s_-]+to[\s_-]+"
    r")"
    + _NEG_VERB_ADV_MODS
    + r"(?:exceed(?:ing|ed)?|reach(?:ing|ed)?|hit(?:ting)?|trigger(?:ing|ed)?|appl(?:y|ying|ied))[\s_-]+"
    + r"(?:(?:any|a|an|the)[\s_-]+)?rate[\s_-]+limit(?:s|ed|ing)?(?![a-z0-9])"
    r"|(?<![a-z0-9])(?:"
    r"(?:(?:was|were|is|are|has|have|had|will|would|could|should|may|might|must|can|do|does|did)[\s_-]+)?(?:not|never|without|cannot|can'?t|won'?t|don'?t|doesn'?t|didn'?t|couldn'?t|wouldn'?t|shouldn'?t|wasn'?t|weren'?t|isn'?t|aren'?t|hasn'?t|haven'?t|hadn'?t)[\s_-]+"
    + _NEG_VERB_ADV_MODS
    + r"(?:(?:be|been|being|get|getting|got)[\s_-]+"
    + _NEG_VERB_ADV_MODS
    + r")?"
    r"|(?:(?:was|were|is|are|has|have|had|get|getting|got)[\s_-]+(?:been[\s_-]+)?)?(?:unable|failed|failing)[\s_-]+to[\s_-]+"
    + _NEG_VERB_ADV_MODS
    + r"(?:be|been|being|get|getting|got)[\s_-]+"
    + _NEG_VERB_ADV_MODS
    + r"|(?:(?:was|were|is|are|has|have|had)[\s_-]+)?(?:(?:not|never)[\s_-]+|without[\s_-]+(?:(?:being|having|getting)[\s_-]+)?)"
    + _NEG_VERB_ADV_MODS
    + r"(?:(?:get|getting|got)[\s_-]+"
    + _NEG_VERB_ADV_MODS
    + r")?able[\s_-]+to[\s_-]+"
    + _NEG_VERB_ADV_MODS
    + r"(?:be|get)[\s_-]+"
    + _NEG_VERB_ADV_MODS
    + r")"
    + r"(?:exceeded|reached|hit|triggered|applied)[\s_-]+"
    + r"(?:by|via|from|through|with)[\s_-]+(?:(?:any|a|an|the)[\s_-]+)?rate[\s_-]+limit(?:s|ed|ing)?(?![a-z0-9])"
)
_NOT_UNAUTHORIZED_RE = re.compile(
    r"(?<![a-z0-9])(?:not|never)[\s_-]+" + _NEG_VERB_ADV_MODS + r"unauthorized(?![a-z0-9])"
)
_FAILED_TO_RE = re.compile(r"(?<![a-z0-9])(?:failed|failing)[\s_-]+to(?![a-z0-9])")
_RATE_LIMIT_WORD_RE = re.compile(r"(?<![a-z0-9])rate[\s_-]+limit(?:s|ed|ing)?(?![a-z0-9])")

_NEG_NOUN_MODS = (
    r"(?:(?:have|had|having|any|a|an|the|ever|actually|even|yet|really|still|explicitly|"
    r"properly|successfully|directly|fully|just|also|only|"
    r"actual|valid|proper|explicit|direct|full|real|authoritative|"
    r"authenticated|client|human|final|positive|successful|recorded)[\s_-]+){0,5}"
)
_NEGATED_CONFIRMATION_RE = re.compile(
    r"(?<![a-z0-9])(?:"
    r"(?:" + _NEG_PREFIX_WORDS + r"|without|zero)[\s_-]+"
    + _NEG_NOUN_MODS
    + r"(?:confirmations?(?![\s_-]+(?:errors?|failures?|faults?|issues?|problems?|exceptions?)(?![a-z0-9]))"
    r"|receiv(?:e|ed|ing)[\s_-]+(?:" + _NEG_NOUN_MODS + r")?confirmations?(?![\s_-]+(?:errors?|failures?|faults?|issues?|problems?|exceptions?)(?![a-z0-9])))"
    r"|"
    + _NEG_VERB_AUX_CLAUSE
    + r"(?:confirm(?:ed|ing)?(?![\s_-]+(?:errors?|failures?|faults?|issues?|problems?|exceptions?|leaks?|breach(?:es)?|violations?|compromises?|regressions?|bypasses?|bugs?|defects?|vulnerabilit(?:y|ies)|findings?|incidents?|alerts?)(?![a-z0-9]))"
    r"|receiv(?:e|ed|ing)[\s_-]+(?:" + _NEG_NOUN_MODS + r")?confirmations?(?![\s_-]+(?:errors?|failures?|faults?|issues?|problems?|exceptions?)(?![a-z0-9])))"
    r")(?![a-z0-9])"
)
_DISCLOSURE_LOGGED_RE = re.compile(
    r"(?<![a-z0-9])(?:secret|secrets|token|tokens|credential|credentials|key|keys|pii|raw|plaintext|sensitive|unmasked)"
    r"(?:[\s_-]+(?:was|were|is|are|got|value|values|data|payload))?[\s_-]*logged(?![a-z0-9])"
)
_NEGATED_DISCLOSURE_LOGGED_RE = re.compile(
    r"(?<![a-z0-9])(?:" + _NEG_PREFIX_WORDS + r"|without|zero)[\s_-]+"
    r"(?:secret|secrets|token|tokens|credential|credentials|key|keys|pii|raw|plaintext|sensitive|unmasked)"
    r"(?:[\s_-]+(?:was|were|is|are|got|value|values|data|payload))?[\s_-]*logged(?![a-z0-9])"
)
_CROSS_TENANT_RE = re.compile(r"(?<![a-z0-9])cross[\s_-]*tenant(?![a-z0-9])")
_NEGATED_CROSS_TENANT_RE = re.compile(
    r"(?<![a-z0-9])(?:" + _NEG_PREFIX_WORDS + r"|without|zero)[\s_-]+cross[\s_-]*tenant(?![a-z0-9])"
)
_PROTECTIVE_CROSS_TENANT_RE = re.compile(
    r"(?<![a-z0-9])cross[\s_-]*tenant(?:[\s_-]+[a-z0-9]+){0,2}[\s_-]+(?:"
    + "|".join(sorted(_PROTECTIVE_TOKENS))
    + r")(?![a-z0-9])"
)
_HTTP_2XX_BREACH_RE = re.compile(
    r"(?<![a-z0-9])(?:"
    r"200[\s,;_:-]*ok"
    r"|201[\s,;_:-]*created"
    r"|202[\s,;_:-]*accepted"
    r"|204[\s,;_:-]*(?:no[\s_-]*content|ok)"
    r"|(?:200|201|202|204)[\s,;_:-]+(?:ok|created|accepted|success|succeeded|served)"
    r"|" + _HTTP_STATUS_OR_VER_PREFIX + r"(?:\(\s*(?:200|201|202|204)\s*\)|(?:200|201|202|204))"
    r")(?![a-z0-9])"
)
_NEGATED_2XX_RE = re.compile(
    r"(?<![a-z0-9])(?:" + _NEG_PREFIX_WORDS + r"|without|zero)[\s_-]+"
    r"(?:(?:any|a|an|the)[\s_-]+)?"
    r"(?:" + _HTTP_STATUS_OR_VER_PREFIX + r")?"
    r"(?:\(\s*(?:200|201|202|204)\s*\)|(?:200|201|202|204))"
    + _HTTP_2XX_REASON_SUFFIX
    + r"(?![a-z0-9])"
)
_REF_NO_RE = re.compile(
    r"(?<![a-z0-9])(?:receipt|order|invoice|ticket|case|ref|item|id|task|request|attempt|run|build|step|line|page|record|row)"
    r"[\s_-]+no(?![\s_-]+(?:ok|created|accepted|content|success|succeeded|served|http|status))(?![a-z0-9])"
)
_NEGATED_2XX_PERM_RE = re.compile(
    r"(?<![a-z0-9])(?:" + _NEG_PREFIX_WORDS + r"|without|zero)[\s_-]+"
    r"(?:(?:any|a|an|the)[\s_-]+)?"
    r"(?:"
    + _HTTP_STATUS_OR_VER_PREFIX
    + r"(?:\(\s*(?:200|201|202|204)\s*\)|(?:200|201|202|204))"
    + _HTTP_2XX_REASON_SUFFIX
    + r"|"
    r"(?:\(\s*(?:200|201|202|204)\s*\)|(?:200|201|202|204))"
    + _HTTP_2XX_REASON_SUFFIX
    + r"(?![\s_-]+(?:ms|us|ns|bytes|kb|mb|gb|items|rows|chars|tokens|records|words|lines|pages|users)(?![a-z0-9]))"
    + r")(?![a-z0-9])"
)
_BARE_2XX_CLAUSE_RE = re.compile(
    r"(?:^|[;,:\s])(?:"
    r"\(\s*(?:200|201|202|204)\s*\)"
    r"|(?<![a-z0-9_-])(?:200|201|202|204)(?![a-z0-9_-])"
    r")(?=$|[;,:\s]|\.(?:$|\s))"
)
_TIMED_OUT_RE = re.compile(r"(?<![a-z0-9])timed[\s_-]+out(?![a-z0-9])")
_RATE_LIMITED_RE = re.compile(
    r"(?<![a-z0-9])(?:"
    r"rate[\s_-]+limit(?:ed|(?:s|ing)?[\s_-]+(?:(?:have|has|had|will|would|could|should|may|might|must|can|do|does|did|were|was|is|are|be|been|being|get|getting|got)[\s_-]+){0,4}(?:exceeded|exceeding|triggered|triggering|hit|hitting|reached|reaching|applied|applying))?"
    r"|(?:exceed(?:ing|ed)?|trigger(?:ing|ed)?|hit(?:ting)?|reach(?:ing|ed)?|appl(?:y|ying|ied))[\s_-]+(?:(?:by|via|from|through|with)[\s_-]+)?(?:(?:any|a|an|the)[\s_-]+)?rate[\s_-]+limit(?:s|ed|ing)?"
    r")(?![a-z0-9])"
)
_HTTP_4XX_5XX_RE = re.compile(
    r"(?<![a-z0-9])" + _HTTP_STATUS_OR_VER_PREFIX + r"(?:\(\s*(?:4\d\d|5\d\d)\s*\)|(?:4\d\d|5\d\d))(?![a-z0-9])"
)
_BARE_4XX_5XX_CLAUSE_RE = re.compile(
    r"(?:^|[;,:\s])(?:"
    r"\(\s*(?:4\d\d|5\d\d)\s*\)"
    r"|(?<![a-z0-9_-])(?:400|401|403|404|408|409|422|429|500|502|503|504)(?![a-z0-9_-])"
    r")(?=$|[;,:\s]|\.(?:$|\s))"
)
_BENIGN_OK_SUBJECT_NOUNS = frozenset(
    {
        "check",
        "checks",
        "test",
        "tests",
        "syntax",
        "schema",
        "lint",
        "config",
        "configuration",
        "build",
        "validation",
        "health",
        "healthcheck",
        "healthchecks",
        "guard",
        "guards",
        "assertion",
        "assertions",
        "typecheck",
        "types",
        "format",
        "formatting",
        "compile",
        "compilation",
        "policy",
        "policies",
        "invariant",
        "invariants",
    }
)


def _strip_negated_2xx(text: str) -> str:
    parts = _split_clauses(text, include_delims=True)
    return "".join(
        _PASSIVE_NEGATED_2XX_RE.sub(
            " ",
            _NEGATED_VERB_2XX_RE.sub(" ", _NEGATED_2XX_RE.sub(" ", part)),
        )
        if idx % 2 == 0
        else part
        for idx, part in enumerate(parts)
    )


def _perturbation_outcomes_contradict(expected: str, observed: str) -> bool:
    if len(expected) > _MAX_ANALYZED_TEXT_CHARS or len(observed) > _MAX_ANALYZED_TEXT_CHARS:
        return True
    exp_l = expected.strip().lower()
    obs_l = observed.strip().lower()
    if not exp_l or not obs_l or exp_l == obs_l:
        return False
    if exp_l in _SHORT_PERTURBATION_TOKENS and obs_l in _SHORT_PERTURBATION_TOKENS:
        return exp_l != obs_l

    exp_clean = _normalize_perturbation_text(exp_l)
    obs_clean = _normalize_perturbation_text(obs_l)
    exp_tokens = set(_ALNUM_TOKEN_RE.findall(exp_clean))

    exp_prot_norm = _replace_unnegated_401_unauthorized(exp_clean)
    exp_no_neg_2xx = _strip_negated_2xx(exp_prot_norm)
    exp_has_unneg_2xx = bool(
        _BARE_2XX_CLAUSE_RE.search(exp_no_neg_2xx)
        or _HTTP_2XX_BREACH_RE.search(exp_no_neg_2xx)
    )
    exp_no_neg_4xx_5xx = _strip_negated_4xx_5xx(exp_clean)
    exp_no_neg_fail = _NEGATED_PERMISSIVE_FAILURE_RE.sub(" ", exp_no_neg_4xx_5xx)
    exp_fail_tokens = set(_ALNUM_TOKEN_RE.findall(exp_no_neg_fail))
    exp_has_unneg_4xx_5xx = bool(
        _BARE_4XX_5XX_CLAUSE_RE.search(exp_no_neg_4xx_5xx)
        or _HTTP_4XX_5XX_RE.search(exp_no_neg_4xx_5xx)
        or _HTTP_5XX_SERVER_ERROR_RE.search(exp_no_neg_4xx_5xx)
        or _HTTP_401_UNAUTHORIZED_RE.search(exp_no_neg_4xx_5xx)
        or ("forbidden" in exp_fail_tokens)
    )

    exp_is_protective = (
        (
            bool(exp_tokens & _PROTECTIVE_TOKENS)
            and not bool(_NEGATED_PROTECTIVE_RE.search(exp_clean))
        )
        or bool(_NEGATED_PERMISSIVE_RE.search(exp_clean))
        or bool(_NEGATED_PERMISSIVE_CONFIRM_RE.search(exp_clean))
        or (
            exp_has_unneg_4xx_5xx
            and not exp_has_unneg_2xx
            and not bool(exp_tokens & _PERMISSIVE_EXPECT_TOKENS)
        )
    )
    exp_is_permissive = (
        bool(exp_tokens & _PERMISSIVE_EXPECT_TOKENS)
        and not exp_is_protective
        and not bool(_NEGATED_PERMISSIVE_RE.search(exp_clean))
    )
    exp_is_permissive_like = (
        exp_is_permissive
        or (
            not exp_is_protective
            and bool(exp_tokens & (_PERMISSIVE_CONFIRM_EXTRA | {"authorized"}))
            and not bool(_NEGATED_PERMISSIVE_CONFIRM_RE.search(exp_clean))
        )
        or (not exp_is_protective and exp_has_unneg_2xx)
    )

    obs_tokens = set(_ALNUM_TOKEN_RE.findall(obs_clean))
    obs_has_unneg_protective = bool(
        obs_tokens & _PROTECTIVE_TOKENS
    ) and not bool(_NEGATED_PROTECTIVE_RE.search(obs_clean))
    exp_expects_5xx = bool(_UNNEG_5XX_STATUS_RE.search(exp_no_neg_4xx_5xx))
    allow_obs_5xx = exp_expects_5xx or obs_has_unneg_protective
    obs_for_neg_markers = obs_clean
    if exp_is_permissive_like:
        obs_perm_stripped = _NEGATED_PERMISSIVE_CONFIRM_RE.sub(
            " ",
            _NEGATED_PERMISSIVE_RE.sub(" ", obs_clean),
        )
        obs_perm_tokens = set(_ALNUM_TOKEN_RE.findall(obs_perm_stripped))
        if obs_perm_tokens & (
            _PERMISSIVE_EXPECT_TOKENS | _PERMISSIVE_CONFIRM_EXTRA | {"authorized"}
        ):
            obs_for_neg_markers = _NOT_UNAUTHORIZED_RE.sub(" ", obs_clean)
        obs_for_neg_markers = _strip_negated_4xx_5xx(obs_for_neg_markers)
        obs_for_neg_markers = _NEGATED_PERMISSIVE_FAILURE_RE.sub(
            lambda m: (
                " "
                if (
                    m.group(0).startswith(("failed", "failing"))
                    or _FAILED_TO_RE.search(m.group(0))
                )
                else m.group(0)
            ),
            obs_for_neg_markers,
        )
    else:
        obs_for_neg_markers = _NEGATED_PERMISSIVE_TO_RE.sub(" not ", obs_for_neg_markers)
        if exp_is_protective:
            obs_for_neg_markers = _replace_unnegated_401_unauthorized(obs_for_neg_markers)
            obs_for_neg_markers = _replace_unnegated_5xx_server_error(
                obs_for_neg_markers, allow_5xx=allow_obs_5xx
            )
            obs_for_neg_markers = _PASSIVE_NEGATED_2XX_RE.sub(
                " ",
                _NEGATED_VERB_2XX_RE.sub(" ", obs_for_neg_markers),
            )
            obs_for_neg_markers = _NEGATED_PERMISSIVE_CONFIRM_RE.sub(
                " ",
                _NEGATED_PERMISSIVE_RE.sub(" ", obs_for_neg_markers),
            )
        obs_for_neg_markers = _NEGATED_PERMISSIVE_FAILURE_RE.sub(
            lambda m: (
                " "
                if (
                    _RATE_LIMIT_WORD_RE.search(m.group(0))
                    and _FAILED_TO_RE.search(m.group(0))
                )
                else m.group(0)
            ),
            obs_for_neg_markers,
        )

    exp_clean_for_neg = (
        _replace_unnegated_5xx_server_error(
            _replace_unnegated_401_unauthorized(exp_clean), allow_5xx=exp_expects_5xx
        )
        if exp_is_protective
        else exp_clean
    )
    exp_neg_tokens = _extract_unnegated_neg_markers(
        exp_clean_for_neg,
        ignore_failed_breach_infinitive=not exp_is_permissive_like,
    )
    obs_neg_tokens = _extract_unnegated_neg_markers(
        obs_for_neg_markers,
        ignore_failed_breach_infinitive=not exp_is_permissive_like,
    )
    if obs_neg_tokens and not exp_neg_tokens:
        return True
    if _NEGATED_CONFIRMATION_RE.search(obs_clean) and not _NEGATED_CONFIRMATION_RE.search(exp_clean):
        return True
    if exp_is_protective:
        if _NEGATED_PROTECTIVE_RE.search(obs_clean):
            return True
        if _DISCLOSURE_LOGGED_RE.search(_NEGATED_DISCLOSURE_LOGGED_RE.sub(" ", obs_clean)):
            return True
        obs_ct = _PROTECTIVE_CROSS_TENANT_RE.sub(" ", _NEGATED_CROSS_TENANT_RE.sub(" ", obs_clean))
        if _CROSS_TENANT_RE.search(obs_ct):
            return True
        obs_prot = _replace_unnegated_401_unauthorized(obs_clean)
        obs_no_neg_2xx = _strip_negated_2xx(obs_prot)
        obs_no_neg_perm = _NEGATED_PERMISSIVE_CONFIRM_RE.sub(
            " ",
            _NEGATED_PERMISSIVE_RE.sub(
                " ",
                _NEGATED_PERMISSIVE_TO_RE.sub(" not ", obs_no_neg_2xx),
            ),
        )
        for clause in _split_clauses(obs_no_neg_perm):
            clause_tokens = _ALNUM_TOKEN_RE.findall(clause)
            for idx, tok in enumerate(clause_tokens):
                if tok in _PERMISSIVE_BREACH_TOKENS or tok == "ok":
                    if _is_lookback_negated(
                        clause_tokens,
                        idx,
                        tok,
                        sharing_tokens=_OBJECT_SHARING_BREACH_TOKENS,
                        leakage_tokens=_LEAKAGE_BREACH_TOKENS,
                        allow_writes=True,
                    ):
                        continue
                    if tok in ("returned", "return"):
                        tail_toks = clause_tokens[idx + 1 : idx + 6]
                        if any(
                            len(tt) == 3 and tt.isdigit() and tt[0] in ("4", "5")
                            for tt in tail_toks
                        ):
                            continue
                    if tok == "ok":
                        j = idx - 1
                        while j >= 0 and clause_tokens[j] in {
                            "is",
                            "are",
                            "was",
                            "were",
                            "be",
                            "been",
                        }:
                            j -= 1
                        if j >= 0 and clause_tokens[j] in _BENIGN_OK_SUBJECT_NOUNS:
                            continue
                    return True
        if _BARE_2XX_CLAUSE_RE.search(obs_no_neg_2xx) or _HTTP_2XX_BREACH_RE.search(obs_no_neg_2xx):
            return True
    if exp_is_permissive_like:
        obs_without_neg_4xx_5xx = _strip_negated_4xx_5xx(obs_clean)
        if (
            _NEGATED_PERMISSIVE_RE.search(obs_without_neg_4xx_5xx)
            or _NEGATED_PERMISSIVE_CONFIRM_RE.search(obs_without_neg_4xx_5xx)
            or _PASSIVE_NEGATED_2XX_RE.search(obs_without_neg_4xx_5xx)
            or _NEGATED_VERB_2XX_RE.search(obs_without_neg_4xx_5xx)
            or _NEGATED_2XX_PERM_RE.search(_REF_NO_RE.sub(" ", obs_without_neg_4xx_5xx))
        ):
            return True
        obs_without_neg_fail = _NEGATED_PERMISSIVE_FAILURE_RE.sub(" ", obs_without_neg_4xx_5xx)
        if (
            set(_ALNUM_TOKEN_RE.findall(obs_without_neg_fail)) & _PERMISSIVE_FAILURE_WORDS
            or _TIMED_OUT_RE.search(obs_without_neg_fail)
            or _RATE_LIMITED_RE.search(obs_without_neg_fail)
        ):
            return True
        if _BARE_4XX_5XX_CLAUSE_RE.search(obs_without_neg_4xx_5xx) or _HTTP_4XX_5XX_RE.search(
            obs_without_neg_4xx_5xx
        ):
            return True
    return False


def evaluate_perturbation_matrix(raw_cases: Sequence[Any]) -> list[PerturbationCaseResult]:
    """Evaluate AC 3 single-variable perturbation cases & missing-receipt detector."""
    results: list[PerturbationCaseResult] = []
    for idx, item in enumerate(raw_cases):
        if not isinstance(item, Mapping):
            continue
        cid = _clean_opt_str(_pick_val(item, "case_id", "id")) or f"perturbation-{idx + 1}"
        label = str(_pick_val(item, "label", "title", default=cid))
        varied = str(_pick_val(item, "varied_factor", "varied", default="single_factor"))
        fixed = [
            str(f).strip()
            for f in (_pick_val(item, "held_fixed", "fixed_factors", default=[]) or [])
            if str(f).strip()
        ]
        expected = str(_pick_val(item, "expected_outcome", default=""))
        observed = str(_pick_val(item, "observed_outcome", default=""))

        rcpt_ref = _clean_opt_str(_pick_val(item, "decisive_receipt_ref", "receipt_ref"))
        missing_rcpt = _clean_opt_str(_pick_val(item, "missing_receipt_id", "removed_receipt_id"))
        receipt_present = _pick_val(item, "receipt_present")
        unver_conc = _clean_opt_str(_pick_val(item, "unverified_conclusion"))
        expects_unverified = _strict_bool(
            _pick_val(item, "expects_unverified_on_missing_receipt"), default=False
        )
        raw_passed = _pick_val(item, "passed")
        outcomes_differ = _perturbation_outcomes_contradict(expected, observed)
        receipt_present_ok = _strict_bool(receipt_present, default=True)
        raw_passed_ok = _strict_bool(raw_passed, default=False) if raw_passed is not None else True

        # Fail-closed receipt check: stripped/missing decisive receipt forces `unverified`
        if (
            not receipt_present_ok
            or missing_rcpt is not None
            or rcpt_ref is None
        ):
            conc_state: Literal["supported", "unverified", "failed_regression"] = "unverified"
            rcpt_ref = None
            if not unver_conc:
                unver_conc = (
                    f"Conclusion for '{cid}' is unverified because decisive receipt "
                    f"'{missing_rcpt or 'decisive_receipt'}' is missing."
                )
            passed = bool(expects_unverified and raw_passed_ok)
        elif (
            not raw_passed_ok
            or str(_pick_val(item, "conclusion_state", default="")).lower() == "failed_regression"
            or outcomes_differ
        ):
            conc_state = "failed_regression"
            passed = False
        else:
            conc_state = "supported"
            passed = True

        results.append(
            PerturbationCaseResult(
                case_id=cid,
                label=label,
                varied_factor=varied,
                held_fixed=fixed,
                expected_outcome=expected,
                observed_outcome=observed,
                conclusion_state=conc_state,
                passed=passed,
                decisive_receipt_ref=rcpt_ref,
                missing_receipt_id=missing_rcpt,
                unverified_conclusion=unver_conc if conc_state == "unverified" else None,
            )
        )
    return results


def evaluate_verdict_clauses(
    raw_clauses: Sequence[Any],
) -> tuple[list[VerdictClause], str, str, list[str]]:
    """Evaluate linked verdict clauses; any clause lacking evidence_ref becomes `unverified`."""
    clauses: list[VerdictClause] = []
    missing_joins: list[str] = []
    for idx, item in enumerate(raw_clauses):
        if not isinstance(item, Mapping):
            continue
        cid = _clean_opt_str(_pick_val(item, "clause_id", "id")) or f"clause-{idx + 1}"
        text = str(_pick_val(item, "text", "clause", default="")).strip()
        if not text:
            continue
        ev_ref = _sanitize_verdict_evidence_ref(
            _clean_opt_str(_pick_val(item, "evidence_ref", "receipt_ref"))
        )
        src_loc = _sanitize_verdict_source_location(
            _clean_opt_str(_pick_val(item, "source_location", "source_ref"))
        )
        miss_rcpt = _clean_opt_str(_pick_val(item, "missing_receipt", "missing_receipt_id"))
        raw_state = str(_pick_val(item, "state", default="supported")).strip().lower()

        if miss_rcpt is not None or (ev_ref is None and src_loc is None) or raw_state == "unverified":
            state: VerdictClauseState = "unverified"
            ev_ref = None
            src_loc = None
            join_key = f"missing_receipt:{miss_rcpt}" if miss_rcpt else f"missing_clause_evidence:{cid}"
            if join_key not in missing_joins:
                missing_joins.append(join_key)
        elif raw_state in ("degraded_or_drifted", "indeterminate"):
            state = raw_state  # type: ignore[assignment]
        else:
            state = "supported"

        clauses.append(
            VerdictClause(
                clause_id=cid,
                text=text,
                state=state,
                evidence_ref=ev_ref,
                source_location=src_loc,
                missing_receipt=miss_rcpt if state == "unverified" else None,
            )
        )

    sentence = " ".join(c.text for c in clauses)
    md_parts: list[str] = []
    for c in clauses:
        safe_text = (
            _VERDICT_TEXT_CTRL_RE.sub(" ", c.text)
            .replace("\\", "\\\\")
            .replace("[", "\\[")
            .replace("]", "\\]")
            .replace("<", "\\<")
            .replace(">", "\\>")
            .strip()
        )
        if c.state == "unverified":
            safe_target = _sanitize_markdown_target(
                None, c.missing_receipt or c.clause_id, verified=False
            )
        else:
            safe_target = _sanitize_markdown_target(
                c.source_location or c.evidence_ref, c.clause_id, verified=True
            )
        md_parts.append(f"[{safe_text}]({safe_target})")
    markdown = " ".join(md_parts)
    return clauses, sentence, markdown, missing_joins
