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
        requires_delivery = bool(_pick_val(item, "requires_device_delivery_receipt", default=False))
        if isinstance(raw_obs, Mapping):
            obs_src = _clean_opt_str(_pick_val(raw_obs, "source_ref", "source_location"))
            deliv_rcpt = _clean_opt_str(_pick_val(raw_obs, "delivery_receipt_ref", "delivery_receipt_id"))
            claimed_deliv = bool(_pick_val(raw_obs, "delivery_verified", default=False))
            # Enforce #104 positive delivery receipt rule on boundary notifications
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
    eligible_state = _norm_fact(_pick_val(raw_div, "eligible_for_actor", "eligible_for_koa"))
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
        expects_unverified = bool(_pick_val(item, "expects_unverified_on_missing_receipt", default=False))
        raw_passed = _pick_val(item, "passed")

        # Fail-closed receipt check: stripped/missing decisive receipt forces `unverified`
        if receipt_present is False or missing_rcpt is not None or rcpt_ref is None:
            conc_state: Literal["supported", "unverified", "failed_regression"] = "unverified"
            rcpt_ref = None
            if not unver_conc:
                unver_conc = (
                    f"Conclusion for '{cid}' is unverified because decisive receipt "
                    f"'{missing_rcpt or 'decisive_receipt'}' is missing."
                )
            passed = bool(expects_unverified and (raw_passed is not False))
        elif raw_passed is False or str(_pick_val(item, "conclusion_state", default="")).lower() == "failed_regression":
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
        ev_ref = _clean_opt_str(_pick_val(item, "evidence_ref", "receipt_ref"))
        src_loc = _clean_opt_str(_pick_val(item, "source_location", "source_ref"))
        miss_rcpt = _clean_opt_str(_pick_val(item, "missing_receipt", "missing_receipt_id"))
        raw_state = str(_pick_val(item, "state", default="supported")).strip().lower()

        if miss_rcpt is not None or (ev_ref is None and src_loc is None):
            state: VerdictClauseState = "unverified"
            ev_ref = None
            join_key = f"missing_receipt:{miss_rcpt}" if miss_rcpt else f"missing_clause_evidence:{cid}"
            if join_key not in missing_joins:
                missing_joins.append(join_key)
        elif raw_state in ("degraded_or_drifted", "indeterminate", "unverified"):
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
        target = c.source_location or c.evidence_ref or f"#unverified:{c.missing_receipt or c.clause_id}"
        md_parts.append(f"[{c.text}]({target})")
    markdown = " ".join(md_parts)
    return clauses, sentence, markdown, missing_joins
