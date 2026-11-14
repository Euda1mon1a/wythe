"""Multi-engine bare-minimum local LLM bridge (`apple` + `chrome` + `local` `/v1`)."""

from __future__ import annotations

import base64
import ipaddress
import json
import urllib.error
import urllib.parse
import urllib.request
from pathlib import Path
from typing import Any

from sqlalchemy.orm import Session

from app.core.clock import utc_now
from app.schemas.atlas import (
    AskChatTurn,
    AskEnginesRead,
    AskWytheRequest,
    AskWytheResponse,
    OnDeviceEngineStatus,
)
from app.services.apple_fm_service import (
    check_apple_engine_status,
    run_apple_engine_ask,
)
from app.services.governance_service import get_target_by_slug
from app.services.llm_context_service import build_lineage_cone_slice
from app.services.scanner_service import run_target_scan
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
) -> OnDeviceEngineStatus:
    """Probe loopback/Tailnet OpenAI-compatible `/v1/models` seats bypassing `HTTP_PROXY`."""
    candidates: list[str] = []
    if custom_base_url and custom_base_url.strip():
        try:
            candidates.append(_normalize_private_v1_url(custom_base_url))
        except ValueError as exc:
            return OnDeviceEngineStatus(
                engine="local",
                label="Local OpenAI /v1 Server",
                state="unavailable",
                note=str(exc),
            )
    for seat in _default_local_seats:
        if seat not in candidates:
            candidates.append(seat)

    last_note = "No loopback OpenAI-compatible /v1 seat detected (:8080, :8084, :8083, :8085, :8093, :8081, :1234, :11434)."
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
        has_vision = _looks_vision_capable(display_model)
        return OnDeviceEngineStatus(
            engine="local",
            label="Local OpenAI /v1 Server",
            state="ready",
            model_id=req_model,
            base_url=base,
            supports_vision=has_vision,
            note=f"{display_model} ready at {base}",
        )

    return OnDeviceEngineStatus(
        engine="local",
        label="Local OpenAI /v1 Server",
        state="unavailable",
        note=last_note,
    )


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
    if inline_data_url and inline_data_url.startswith(("data:image/webp;base64,", "data:image/png;base64,", "data:image/jpeg;base64,")):
        return inline_data_url
    if snap_path is not None and snap_path.is_file():
        raw = snap_path.read_bytes()
        mime = "image/webp" if raw[:4] == b"RIFF" and raw[8:12] == b"WEBP" else "image/png"
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
        if used_vision and exc.code in (400, 415, 422):
            return _post_chat(user_text), False
        raise RuntimeError(f"Local model server at {base_url} answered HTTP {exc.code}.") from exc
    except urllib.error.URLError as exc:
        raise RuntimeError(f"Could not reach local model server at {base_url} ({exc.reason}).") from exc


def ask_wythe_with_live_context(session: Session, payload: AskWytheRequest) -> AskWytheResponse:
    """Answer an architectural question grounded in live 3D X-Ray focus + lineage cone."""
    focus = explain_ui_focus(session, target_override=payload.target_slug)
    target = get_target_by_slug(session, focus.active_slug)
    report = run_target_scan(session, target, strict_gate=True, persist_snapshot=False) if target else None

    cone_md = ""
    if report is not None and focus.focused_node is not None:
        cone = build_lineage_cone_slice(report, focus.focused_node.id, max_nodes=18)
        cone_md = f"\n\n### Surgical 3-Tier Lineage Cone\n{cone.markdown[:1600]}"

    instructions = (
        "You are Wythe's embedded real-time 3-tier software architecture & lineage verifier assistant. "
        "Ground all repository, node, color, rule, and lineage statements strictly in the Live 3D Camera & X-Ray "
        "facts below (SQL Truth, Backend Manipulate, Frontend Display). Cite exact rule codes (e.g. TRUTH-002, "
        "MANIP-001, DISP-005), node names, on-screen colors, and `file:line` pointers, and never invent files or "
        "tables. Never treat a node's color or status (such as `gray_zone` or `duplicated_truth`) as standalone "
        "proof of duplicate contents, authoritative ownership, or safe deletion. Keep declared store purpose "
        "distinct from observed verification, distinguish a node's discovery coordinate from causal writer "
        "operation lines, preserve uncertainty when expiration or invalidation is unknown, and present "
        "remediations as suggested changes rather than verified fixes."
    )
    live_vp_override = (payload.live_viewport_brief or "").strip()
    vp_section = f"\n\n{live_vp_override[:2400]}" if live_vp_override and live_vp_override[:80] not in focus.markdown_brief else ""
    compact_context = f"{focus.markdown_brief[:2300]}{vp_section}{cone_md}"
    full_prompt = f"## Live 3D Wythe Viewport & X-Ray\n{compact_context}\n\n## User Question\n{payload.question.strip()}"

    snap_path = Path(focus.snapshot_path) if (payload.include_vision_snapshot and focus.snapshot_path) else None
    inline_snap = payload.snapshot_data_url if payload.include_vision_snapshot else None
    engine_choice = payload.engine
    answer_md = ""
    engine_used: str = "local"
    model_used = ""
    used_vision = False
    hinted_refs: list[str] = []

    apple_status = check_apple_engine_status() if engine_choice in ("auto", "apple") else None
    local_status = probe_local_openai_engine(payload.local_base_url, payload.local_model_id)

    if engine_choice == "apple" or (engine_choice == "auto" and apple_status and apple_status.state == "ready"):
        try:
            hist_tail = "\n".join(
                f"{'User' if t.role == 'user' else 'Assistant'}: {t.content[:360]}"
                for t in payload.history[-4:]
            )
            hist_block = f"\n\n## Recent Session Turns\n{hist_tail}" if hist_tail else ""
            apple_prompt = (
                f"## Live Wythe Viewport\n{focus.markdown_brief[:1600]}{vp_section[:900]}"
                f"{hist_block}\n\n## Question\n{payload.question.strip()}"
            )
            answer_md, hinted_refs = run_apple_engine_ask(instructions, apple_prompt)
            engine_used = "apple"
            model_used = "apple-foundation-models-on-device"
        except RuntimeError:
            if engine_choice == "apple" or local_status.state != "ready":
                raise

    if not answer_md:
        if local_status.state != "ready" or not local_status.base_url or not local_status.model_id:
            raise ValueError(
                f"No ready backend LLM engine (Apple: {apple_status.note if apple_status else 'skipped'}; "
                f"Local: {local_status.note}). Try Chrome Built-In in the browser or start a local `/v1` model."
            )
        answer_md, used_vision = _run_local_chat_completion(
            local_status.base_url,
            local_status.model_id,
            instructions,
            full_prompt,
            snap_path,
            inline_data_url=inline_snap,
            history=payload.history,
            supports_vision=local_status.supports_vision,
        )
        engine_used = "local"
        if local_status.model_id == "default_model" and local_status.note and " ready at " in local_status.note:
            model_used = local_status.note.split(" ready at ", 1)[0]
        else:
            model_used = local_status.model_id

    matched_ids: list[str] = []
    if focus.focused_node is not None:
        matched_ids.append(focus.focused_node.id)
    if report is not None:
        low_ans = answer_md.lower()
        hinted_low = {h.strip("` ").lower() for h in hinted_refs if h.strip()}
        for node in report.nodes:
            if len(matched_ids) >= 6:
                break
            if node.id in matched_ids:
                continue
            lbl_low = node.label.lower()
            is_code_identifier = "_" in lbl_low or "/" in lbl_low or ":" in lbl_low
            if (
                node.id.lower() in low_ans
                or node.id.lower() in hinted_low
                or lbl_low in hinted_low
                or f"`{lbl_low}`" in low_ans
                or (is_code_identifier and len(lbl_low) >= 5 and lbl_low in low_ans)
            ):
                matched_ids.append(node.id)

    return AskWytheResponse(
        engine_used=engine_used,  # type: ignore[arg-type]
        model_id=model_used,
        used_vision_snapshot=used_vision,
        context_headline=focus.headline,
        answer_markdown=answer_md,
        referenced_node_ids=matched_ids[:6],
        observed_at=utc_now(),
    )
