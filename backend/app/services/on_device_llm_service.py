"""Multi-engine bare-minimum local LLM bridge (`apple` + `chrome` + `local` `/v1`)."""

from __future__ import annotations

import base64
import ipaddress
import json
import urllib.error
import urllib.parse
import urllib.request
from pathlib import Path
from typing import Any, Literal

from sqlalchemy.orm import Session

from app.core.clock import utc_now
from app.schemas.atlas import (
    AskChatTurn,
    AskEnginesRead,
    AskWytheRequest,
    AskWytheResponse,
    InvestigationCreateRequest,
    InvestigationTurnCreate,
    LlmNodePointer,
    OnDeviceEngineStatus,
)
from app.services.apple_fm_service import (
    check_apple_engine_status,
    run_apple_engine_ask,
)
from app.services.governance_service import get_target_by_slug
from app.services.investigation_service import (
    build_evidence_identity,
    create_or_reopen_investigation,
    get_active_session_ids_for_target,
    get_investigation_session,
    get_or_run_cached_scan,
    list_session_corrections,
    record_investigation_turn,
    validate_references_against_report,
)
from app.services.llm_context_service import (
    build_lineage_cone_slice,
    build_section_budgeted_ask_prompt,
)
from app.services.ui_focus_service import explain_ui_focus

_default_local_seats = (
    "http://127.0.0.1:8080/v1",
    "http://127.0.0.1:8084/v1",
    "http://127.0.0.1:8081/v1",
    "http://127.0.0.1:8083/v1",
    "http://127.0.0.1:8085/v1",
    "http://127.0.0.1:8093/v1",
    "http://127.0.0.1:1234/v1",
    "http://127.0.0.1:11434/v1",
)
_non_chat_tokens = ("whisper", "embed", "minilm", "bge-", "rerank", "tts", "piper", "kokoro", "ocr", "flux")
_vision_tokens = ("vl", "vision", "gemma-3", "gemma-4", "pixtral", "llava", "minicpm-v", "internvl")
_no_proxy_opener = urllib.request.build_opener(urllib.request.ProxyHandler({}))


def _normalize_private_v1_url(raw_url: str) -> str:
    parsed = urllib.parse.urlparse(raw_url.strip())
    if parsed.scheme not in ("http", "https") or not parsed.hostname:
        raise ValueError("Local model URL must start with http:// or https://.")
    host = parsed.hostname.lower()
    if host not in ("localhost", "127.0.0.1", "::1"):
        try:
            ip_obj = ipaddress.ip_address(host)
        except ValueError as exc:
            raise ValueError(
                "Local model URL must target loopback (127.0.0.1/localhost) or a private/Tailnet IP."
            ) from exc
        if not (ip_obj.is_loopback or ip_obj.is_private or ip_obj in ipaddress.ip_network("100.64.0.0/10")):
            raise ValueError("Refusing non-private model host; keep model traffic local/Tailnet.")
    path = parsed.path.rstrip("/")
    if not path.endswith("/v1"):
        path = f"{path}/v1" if path else "/v1"
    netloc = f"[{host}]" if ":" in host and not host.startswith("[") else host
    if parsed.port:
        netloc = f"{netloc}:{parsed.port}"
    return f"{parsed.scheme}://{netloc}{path}"


def _extract_snapshot_slug(model_id: str) -> str | None:
    marker = "models--"
    if marker in model_id and "/snapshots/" in model_id:
        tail = model_id.split(marker, 1)[1].split("/snapshots/", 1)[0]
        return tail.replace("--", "/")
    return None


def _select_safe_seat_model(
    raw_items: list[dict[str, Any]],
    preferred_model: str | None,
    server_header: str = "",
) -> tuple[str, str] | None:
    """Return `(request_model_id, display_label)` without triggering mlx_lm/mlx_vlm weight swaps."""
    raw_ids = [str(it.get("id")) for it in raw_items if it.get("id")]
    chat_ids = [m for m in raw_ids if not any(bad in m.lower() for bad in _non_chat_tokens)]
    if not chat_ids:
        return None
    if preferred_model and (preferred_model == "default_model" or preferred_model in raw_ids):
        return preferred_model, preferred_model

    if len(raw_items) == 1 or "pinned" in str(raw_items[0].get("owned_by") or "").lower():
        pinned = chat_ids[0]
        return pinned, (_extract_snapshot_slug(pinned) or pinned)

    is_mlx_multi_dir = any(
        m.startswith("mlx-community/") or "/models--" in m for m in raw_ids
    )
    if is_mlx_multi_dir:
        created_vals = {it.get("created") for it in raw_items if it.get("created") is not None}
        has_owner = any(it.get("owned_by") for it in raw_items)
        if "mlx_vlm" in server_header.lower() or (len(created_vals) > 1 and not has_owner):
            return None
        snap_slug = next((_extract_snapshot_slug(m) for m in raw_ids if _extract_snapshot_slug(m)), None)
        return "default_model", (snap_slug or "default_model (mlx_lm resident)")

    return chat_ids[0], chat_ids[0]


def _looks_vision_capable(model_id: str) -> bool:
    low = model_id.lower()
    return any(tok in low for tok in _vision_tokens)


def probe_local_openai_engine(
    custom_base_url: str | None = None,
    preferred_model: str | None = None,
    *,
    prefer_vision: bool = False,
) -> OnDeviceEngineStatus:
    """Probe loopback/Tailnet OpenAI-compatible `/v1/models` seats bypassing `HTTP_PROXY`."""
    candidates: list[str] = []
    explicit_custom_base: str | None = None
    if custom_base_url and custom_base_url.strip():
        try:
            explicit_custom_base = _normalize_private_v1_url(custom_base_url)
            candidates.append(explicit_custom_base)
        except ValueError as exc:
            return OnDeviceEngineStatus(
                engine="local",
                label="Local OpenAI /v1 Server",
                state="unavailable",
                note=str(exc),
            )
    else:
        for seat in _default_local_seats:
            if seat not in candidates:
                candidates.append(seat)

    last_note = "No loopback OpenAI-compatible /v1 seat detected (:8080, :8084, :8083, :8085, :8093, :8081, :1234, :11434)."
    fallback_text_seat: OnDeviceEngineStatus | None = None
    for base in candidates:
        req = urllib.request.Request(f"{base}/models", method="GET")
        try:
            with _no_proxy_opener.open(req, timeout=4.5) as resp:
                if resp.status != 200:
                    last_note = f"{base}/models answered HTTP {resp.status}."
                    continue
                srv_hdr = str(resp.headers.get("Server") or "")
                payload = json.loads(resp.read().decode("utf-8", errors="replace"))
        except (OSError, ValueError, urllib.error.URLError):
            last_note = f"Nothing answered at {base}."
            continue

        raw_items = [
            item for item in (payload.get("data") or []) if isinstance(item, dict) and item.get("id")
        ]
        selected = _select_safe_seat_model(raw_items, preferred_model, server_header=srv_hdr)
        if selected is None:
            last_note = f"{base} has no chat-capable `/v1/models` entries."
            continue
        req_model, display_model = selected
        has_vision = _looks_vision_capable(display_model) or _looks_vision_capable(req_model)
        seat_status = OnDeviceEngineStatus(
            engine="local",
            label="Local OpenAI /v1 Server",
            state="ready",
            model_id=req_model,
            base_url=base,
            supports_vision=has_vision,
            note=f"{display_model} ready at {base}",
        )
        explicit_model_match = bool(
            preferred_model
            and preferred_model.strip()
            and preferred_model.strip() in {str(item.get("id")) for item in raw_items}
        )
        if explicit_custom_base == base or explicit_model_match or has_vision or not prefer_vision:
            return seat_status
        if fallback_text_seat is None:
            fallback_text_seat = seat_status

    if fallback_text_seat is not None:
        return fallback_text_seat

    return OnDeviceEngineStatus(
        engine="local",
        label="Local OpenAI /v1 Server",
        state="unavailable",
        note=last_note,
    )


def resolve_auto_backend_cascade(
    *,
    backend: str = "auto",
    apple_status: OnDeviceEngineStatus | None,
    local_status: OnDeviceEngineStatus | None,
    image_data_url: str | None = None,
    has_screenshot: bool = False,
) -> list[Literal["apple", "local"]]:
    """Select backend engine priority; prefer ready local `/v1` VLMs when a viewport image is attached."""
    if backend == "apple":
        return ["apple"]
    if backend == "local":
        return ["local"]

    apple_ready = bool(apple_status and apple_status.state == "ready")
    local_ready = bool(
        local_status
        and local_status.state == "ready"
        and local_status.base_url
        and local_status.model_id
    )
    local_vlm_ready = bool(local_ready and local_status and local_status.supports_vision)
    multimodal_attached = bool((image_data_url and image_data_url.strip()) or has_screenshot)

    order: list[Literal["apple", "local"]] = []
    if multimodal_attached and local_vlm_ready:
        order.append("local")
        if apple_ready:
            order.append("apple")
        return order

    if apple_ready:
        order.append("apple")
    if local_ready:
        order.append("local")
    return order


def list_ask_engines(custom_base_url: str | None = None) -> AskEnginesRead:
    """Return unified zero-setup on-device engine inventory (`apple`, `chrome`, `local`)."""
    apple_st = check_apple_engine_status()
    chrome_st = OnDeviceEngineStatus(
        engine="chrome",
        label="Chrome Built-In (Gemini Nano)",
        state="client_probed",
        supports_vision=True,
        note="Probed directly inside Chrome via `LanguageModel.availability()` (zero backend required).",
    )
    local_st = probe_local_openai_engine(custom_base_url=custom_base_url)
    rec: str = "apple" if apple_st.state == "ready" else ("local" if local_st.state == "ready" else "none")
    return AskEnginesRead(
        auto_order=["apple", "chrome", "local"],
        recommended_backend_engine=rec,  # type: ignore[arg-type]
        engines=[apple_st, chrome_st, local_st],
    )


def _sniff_image_data_url(snap_path: Path | None, inline_data_url: str | None) -> str | None:
    if inline_data_url:
        low_inline = inline_data_url[:32].lower()
        if low_inline.startswith(("data:image/webp;base64,", "data:image/png;base64,", "data:image/jpeg;base64,")):
            return inline_data_url
        if low_inline.startswith("data:image/jpg;base64,"):
            return "data:image/jpeg;base64," + inline_data_url[len("data:image/jpg;base64,") :]
    if snap_path is not None and snap_path.is_file():
        raw = snap_path.read_bytes()
        if len(raw) >= 12 and raw[:4] == b"RIFF" and raw[8:12] == b"WEBP":
            mime = "image/webp"
        elif raw[:3] == b"\xff\xd8\xff":
            mime = "image/jpeg"
        else:
            mime = "image/png"
        b64 = base64.b64encode(raw).decode("ascii")
        return f"data:{mime};base64,{b64}"
    return None


def _run_local_chat_completion(
    base_url: str,
    model_id: str,
    instructions: str,
    user_text: str,
    snap_path: Path | None,
    *,
    inline_data_url: str | None = None,
    history: list[AskChatTurn] | None = None,
    supports_vision: bool | None = None,
) -> tuple[str, bool]:
    used_vision = False
    user_content: Any = user_text
    can_vision = supports_vision if supports_vision is not None else _looks_vision_capable(model_id)
    img_url = _sniff_image_data_url(snap_path, inline_data_url) if can_vision else None
    if img_url:
        user_content = [
            {"type": "text", "text": user_text},
            {"type": "image_url", "image_url": {"url": img_url}},
        ]
        used_vision = True

    prior_msgs = [
        {"role": turn.role, "content": turn.content[:2400]}
        for turn in (history or [])[-8:]
    ]

    def _post_chat(content_payload: Any) -> str:
        body: dict[str, Any] = {
            "model": model_id,
            "temperature": 0.2,
            "max_tokens": 900,
            "messages": [
                {"role": "system", "content": instructions},
                *prior_msgs,
                {"role": "user", "content": content_payload},
            ],
        }
        if "qwen" in model_id.lower() or model_id == "default_model":
            body["chat_template_kwargs"] = {"enable_thinking": False}
        req = urllib.request.Request(
            f"{base_url}/chat/completions",
            data=json.dumps(body).encode("utf-8"),
            headers={"Content-Type": "application/json"},
            method="POST",
        )
        with _no_proxy_opener.open(req, timeout=60.0) as resp:
            parsed = json.loads(resp.read().decode("utf-8", errors="replace"))
        choice = (parsed.get("choices") or [{}])[0]
        msg = choice.get("message") or {}
        text = str(msg.get("content") or "").strip()
        if not text:
            raise RuntimeError(f"Local model `{model_id}` returned an empty completion.")
        return text

    try:
        return _post_chat(user_content), used_vision
    except urllib.error.HTTPError as exc:
        if used_vision and exc.code in (400, 415, 422, 500):
            try:
                return _post_chat(user_text), False
            except (TimeoutError, OSError, ValueError) as inner_exc:
                raise RuntimeError(
                    f"Local model text fallback at {base_url} failed ({type(inner_exc).__name__}: {inner_exc})."
                ) from inner_exc
        raise RuntimeError(f"Local model server at {base_url} answered HTTP {exc.code}.") from exc
    except urllib.error.URLError as exc:
        raise RuntimeError(f"Could not reach local model server at {base_url} ({exc.reason}).") from exc
    except (TimeoutError, OSError, ValueError) as exc:
        raise RuntimeError(
            f"Local model server at {base_url} failed during completion ({type(exc).__name__}: {exc})."
        ) from exc


def ask_wythe_with_live_context(session: Session, payload: AskWytheRequest) -> AskWytheResponse:
    """Answer an architectural question grounded in live 3D X-Ray focus + lineage cone."""
    req_sid = (payload.session_id or "").strip() or None
    if (
        req_sid is not None
        and get_investigation_session(req_sid) is None
        and payload.target_slug
        and get_target_by_slug(session, payload.target_slug.strip()) is not None
    ):
        create_or_reopen_investigation(
            session,
            InvestigationCreateRequest(
                target_slug=payload.target_slug.strip(),
                session_id=req_sid,
                client_id=payload.client_id,
            ),
        )

    focus = explain_ui_focus(
        session,
        target_override=payload.target_slug,
        session_id=req_sid,
    )
    target = get_target_by_slug(session, focus.active_slug)
    report = get_or_run_cached_scan(session, target, strict_gate=True) if target else None
    ev_identity = focus.evidence_identity or (build_evidence_identity(report) if report else None)

    eff_sid = req_sid or focus.session_id
    if eff_sid is not None and get_investigation_session(eff_sid) is None and target is not None:
        create_or_reopen_investigation(
            session,
            InvestigationCreateRequest(
                target_slug=target.slug,
                session_id=eff_sid,
                client_id=payload.client_id,
            ),
            precomputed_report=report,
        )

    if report is not None and (
        payload.selected_node_id or payload.selected_finding_id or payload.selected_edge_id
    ):
        upd_focus: dict[str, Any] = {}
        if payload.selected_edge_id:
            upd_focus["selected_edge_id"] = payload.selected_edge_id
        if payload.selected_finding_id:
            upd_focus["selected_finding_id"] = payload.selected_finding_id
            f_match = next((f for f in report.findings if f.id == payload.selected_finding_id), None)
            if f_match is not None and f_match not in focus.active_findings:
                upd_focus["active_findings"] = [f_match, *focus.active_findings[:11]]
        if payload.selected_node_id:
            n_match = next((n for n in report.nodes if n.id == payload.selected_node_id), None)
            if n_match is not None:
                upd_focus["focused_node"] = LlmNodePointer(
                    id=n_match.id,
                    tier=n_match.tier,
                    subkind=n_match.subkind,
                    label=n_match.label,
                    pointer=f"{n_match.source_file}:{n_match.line}",
                    status=n_match.status,
                    columns=list(n_match.columns[:8]),
                    http_paths=list(n_match.http_paths[:6]),
                )
        if upd_focus:
            focus = focus.model_copy(update=upd_focus)

    cone_seed_id = (
        payload.selected_node_id
        or (focus.focused_node.id if focus.focused_node is not None else None)
    )
    cone = (
        build_lineage_cone_slice(report, cone_seed_id, max_nodes=18)
        if (report is not None and cone_seed_id)
        else None
    )

    corrections = list_session_corrections(eff_sid)
    eff_history: list[AskChatTurn] = list(payload.history)
    if not eff_history and eff_sid is not None:
        inv_hist = get_investigation_session(eff_sid)
        if inv_hist is not None:
            for prior_t in inv_hist.turns[-6:]:
                if prior_t.status == "answered" and prior_t.answer_markdown:
                    eff_history.append(AskChatTurn(role="user", content=prior_t.question[:2000]))
                    eff_history.append(
                        AskChatTurn(role="assistant", content=prior_t.answer_markdown[:4000])
                    )

    corr_sys_note = (
        " Respect active Human Investigation Corrections in Section 2 as authoritative working "
        "clarifications for this session, while noting they remain conversation context until "
        "deliberately promoted to a governance ruling."
        if corrections
        else ""
    )
    instructions = (
        "You are Wythe's embedded real-time 3-tier software architecture & lineage verifier assistant. "
        "Ground all repository, node, color, rule, and lineage statements strictly in the Live 3D Camera & X-Ray "
        "facts below (SQL Truth, Backend Manipulate, Frontend Display). Cite exact rule codes (e.g. TRUTH-002, "
        "MANIP-001, DISP-005), node names, on-screen colors, and `file:line` pointers, and never invent files or "
        "tables. Never treat a node's color or status (such as `gray_zone` or `duplicated_truth`) as standalone "
        "proof of duplicate contents, authoritative ownership, or safe deletion. Keep declared store purpose "
        "distinct from observed verification, distinguish a node's discovery coordinate from causal writer "
        "operation lines, preserve uncertainty when expiration or invalidation is unknown, and present "
        f"remediations as suggested changes rather than verified fixes.{corr_sys_note}"
    )

    full_prompt, apple_prompt, budget = build_section_budgeted_ask_prompt(
        question=payload.question,
        focus=focus,
        report=report,
        cone=cone,
        evidence_identity=ev_identity,
        corrections=corrections,
        live_viewport_brief=payload.live_viewport_brief,
        history=eff_history,
    )

    snap_path = (
        Path(focus.snapshot_path)
        if (payload.include_vision_snapshot and focus.snapshot_path and not focus.snapshot_stale)
        else None
    )
    inline_snap = payload.snapshot_data_url if payload.include_vision_snapshot else None
    attached_img_url = (
        _sniff_image_data_url(snap_path, inline_snap) if payload.include_vision_snapshot else None
    )
    has_multimodal_image = attached_img_url is not None

    explicit_local_url = (payload.local_base_url or "").strip() or None
    if explicit_local_url is not None:
        _normalize_private_v1_url(explicit_local_url)

    engine_choice: str = (
        "local"
        if (explicit_local_url is not None and payload.engine == "auto")
        else payload.engine
    )
    answer_md = ""
    engine_used: str = "local"
    model_used = ""
    used_vision = False
    fallback_reason: str | None = None
    hinted_refs: list[str] = []

    apple_status = check_apple_engine_status() if engine_choice in ("auto", "apple") else None
    local_status = probe_local_openai_engine(
        explicit_local_url,
        payload.local_model_id,
        prefer_vision=has_multimodal_image,
    )

    cascade = resolve_auto_backend_cascade(
        backend=engine_choice,
        apple_status=apple_status,
        local_status=local_status,
        image_data_url=inline_snap,
        has_screenshot=has_multimodal_image,
    )

    def _preserve_unresolved_question(reason: str) -> str | None:
        nonlocal eff_sid
        if eff_sid is None and target is not None:
            active_sids = get_active_session_ids_for_target(target.slug)
            if len(active_sids) == 1:
                eff_sid = active_sids[0]
            elif len(active_sids) == 0:
                created = create_or_reopen_investigation(
                    session,
                    InvestigationCreateRequest(
                        target_slug=target.slug,
                        client_id=payload.client_id,
                    ),
                    precomputed_report=report,
                )
                eff_sid = created.session_id
        if eff_sid is None:
            return None
        saved_unres = record_investigation_turn(
            session,
            eff_sid,
            InvestigationTurnCreate(
                client_id=payload.client_id,
                actor="human",
                question=payload.question,
                answer_markdown=None,
                authored_by="none",
                failure_reason=reason[:480],
                selected_node_id=cone_seed_id,
                selected_edge_id=payload.selected_edge_id or focus.selected_edge_id,
                selected_finding_id=payload.selected_finding_id or focus.selected_finding_id,
            ),
            report=report,
        )
        return saved_unres.turn_id

    prior_fail_note: str | None = None
    for idx, candidate_engine in enumerate(cascade):
        has_fallback = idx + 1 < len(cascade)
        if candidate_engine == "apple":
            try:
                answer_md, hinted_refs = run_apple_engine_ask(instructions, apple_prompt)
                engine_used = "apple"
                model_used = "apple-foundation-models-on-device"
                used_vision = False
                if prior_fail_note:
                    fallback_reason = f"{prior_fail_note}; answered via fallback `apple`."
                elif has_multimodal_image:
                    fallback_reason = "Viewport image available, but `apple` engine answered in text-only mode."
                break
            except (RuntimeError, TimeoutError, OSError, ValueError) as exc:
                prior_fail_note = f"Primary `apple` engine failed ({type(exc).__name__}: {exc})"
                if not has_fallback:
                    err_msg = (
                        str(exc)
                        if isinstance(exc, RuntimeError)
                        else f"Local model completion failed ({type(exc).__name__}: {exc})."
                    )
                    tid = _preserve_unresolved_question(err_msg)
                    suffix = f" [question preserved in session={eff_sid}, turn={tid}]" if tid else ""
                    raise RuntimeError(f"{err_msg}{suffix}") from exc
        else:
            if local_status.state != "ready" or not local_status.base_url or not local_status.model_id:
                prior_fail_note = f"Local `/v1` unavailable ({local_status.note})"
                if has_fallback:
                    continue
                break
            try:
                answer_md, used_vision = _run_local_chat_completion(
                    local_status.base_url,
                    local_status.model_id,
                    instructions,
                    full_prompt,
                    snap_path,
                    inline_data_url=inline_snap,
                    history=eff_history,
                    supports_vision=local_status.supports_vision,
                )
                engine_used = "local"
                if (
                    local_status.model_id == "default_model"
                    and local_status.note
                    and " ready at " in local_status.note
                ):
                    model_used = local_status.note.split(" ready at ", 1)[0]
                else:
                    model_used = local_status.model_id
                if prior_fail_note:
                    fallback_reason = f"{prior_fail_note}; answered via fallback `local` ({model_used})."
                elif has_multimodal_image and not used_vision:
                    fallback_reason = "Viewport image available, but selected local model ran in text-only mode."
                break
            except (RuntimeError, TimeoutError, OSError, ValueError) as exc:
                prior_fail_note = f"Primary `local` engine failed ({type(exc).__name__}: {exc})"
                if not has_fallback:
                    err_msg = (
                        str(exc)
                        if isinstance(exc, RuntimeError)
                        else f"Local model completion failed ({type(exc).__name__}: {exc})."
                    )
                    tid = _preserve_unresolved_question(err_msg)
                    suffix = f" [question preserved in session={eff_sid}, turn={tid}]" if tid else ""
                    raise RuntimeError(f"{err_msg}{suffix}") from exc

    if not answer_md:
        unavail_msg = (
            f"No ready backend LLM engine (Apple: {apple_status.note if apple_status else 'skipped'}; "
            f"Local: {local_status.note}). Try Chrome Built-In in the browser or start a local `/v1` model."
        )
        tid = _preserve_unresolved_question(unavail_msg)
        suffix = f" [question preserved in session={eff_sid}, turn={tid}]" if tid else ""
        raise RuntimeError(f"{unavail_msg}{suffix}")

    explicit_seed_refs = [
        r
        for r in (
            cone_seed_id,
            payload.selected_edge_id or focus.selected_edge_id,
            payload.selected_finding_id or focus.selected_finding_id,
            *(h.strip("` ") for h in hinted_refs if h.strip()),
        )
        if r
    ]
    ev_rev_id = ev_identity.evidence_revision_id if ev_identity else "ev_unknown"
    val_refs = validate_references_against_report(
        explicit_seed_refs,
        report,
        evidence_revision_id=ev_rev_id,
        answer_markdown=answer_md,
    )
    matched_node_ids: list[str] = []
    for vref in val_refs:
        if (
            vref.kind == "node"
            and vref.validation_state in ("validated", "text_convenience")
            and vref.ref_id not in matched_node_ids
        ):
            matched_node_ids.append(vref.ref_id)

    recorded_tid: str | None = None
    if eff_sid is not None:
        saved_turn = record_investigation_turn(
            session,
            eff_sid,
            InvestigationTurnCreate(
                client_id=payload.client_id,
                actor="human",
                question=payload.question,
                answer_markdown=answer_md,
                engine=engine_used,
                model_id=model_used,
                used_vision=used_vision,
                image_supplied=has_multimodal_image,
                authored_by="model",
                fallback_reason=fallback_reason,
                selected_node_id=cone_seed_id,
                selected_edge_id=payload.selected_edge_id or focus.selected_edge_id,
                selected_finding_id=payload.selected_finding_id or focus.selected_finding_id,
                referenced_ids=[r.ref_id for r in val_refs if r.validation_state == "validated"],
            ),
            report=report,
        )
        recorded_tid = saved_turn.turn_id
        val_refs = saved_turn.validated_references or val_refs

    return AskWytheResponse(
        session_id=eff_sid,
        turn_id=recorded_tid,
        authored_by="model",
        engine_used=engine_used,  # type: ignore[arg-type]
        model_id=model_used,
        used_vision_snapshot=used_vision,
        image_supplied=has_multimodal_image,
        fallback_reason=fallback_reason,
        context_headline=focus.headline,
        answer_markdown=answer_md,
        referenced_node_ids=matched_node_ids[:6],
        validated_references=val_refs,
        evidence_identity=ev_identity,
        context_budget=budget,
        observed_at=utc_now(),
    )
