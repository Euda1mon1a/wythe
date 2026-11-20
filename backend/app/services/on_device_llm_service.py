"""Multi-engine bare-minimum local LLM bridge (`apple` + `chrome` + `local` `/v1`)."""

from __future__ import annotations

import base64
import copy
import ipaddress
import json
import re
import urllib.error
import urllib.parse
import urllib.request
from collections.abc import Sequence
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
from app.services.mcp_service import MCP_TOOLS, dispatch_mcp_request
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
_non_chat_tokens = (
    "ocr",
    "paddleocr",
    "whisper",
    "asr",
    "vad",
    "silero",
    "embed",
    "minilm",
    "bge-",
    "rerank",
    "tts",
    "piper",
    "kokoro",
    "flux",
)
_vision_tokens = (
    "qwen3.6",
    "qwen3.5",
    "qwen2.5-vl",
    "qwen2-vl",
    "gemma-4",
    "gemma-3",
    "vl",
    "vlm",
    "vision",
    "pixtral",
    "llava",
    "minicpm-v",
    "internvl",
)
_helper_model_re = re.compile(
    r"(?:router|classifier|guard|draft|speculative|\bd1-\d|\blfm2)",
    re.IGNORECASE,
)
_total_param_scale_re = re.compile(r"(?<![a-z])(\d+(?:\.\d+)?)b\b", re.IGNORECASE)
_any_param_scale_re = re.compile(r"(\d+(?:\.\d+)?)b\b", re.IGNORECASE)
_no_proxy_opener = urllib.request.build_opener(urllib.request.ProxyHandler({}))
_ask_mcp_tool_names = (
    "wythe_focus_camera",
    "wythe_camera_tour",
    "wythe_lineage_cone",
    "wythe_blast_radius",
    "wythe_findings",
    "wythe_what_is_this",
    "wythe_overview",
    "wythe_plugins",
    "wythe_investigation",
)
_session_scoped_mcp_tools = (
    "wythe_focus_camera",
    "wythe_camera_tour",
    "wythe_investigation",
    "wythe_what_is_this",
)
_ask_mcp_max_rounds = 3
_ask_mcp_max_calls_per_round = 4
_ask_mcp_max_tool_chars = 6000
_mcp_tool_intent_re = re.compile(
    r"\b(?:"
    r"mcp|wythe_[a-z0-9_]+|atlas_[a-z0-9_]+"
    r"|tools?|camera|viewport|focus|fly|move|steer|pan|orbit|tour|walkthrough|chronicle"
    r"|lens|layout|zoom|strat(?:um|a)|frustum|unshown|off[- ]?screen|outside"
    r"|filter(?:s|ed|ing)?|flagged(?:_?only)?|only[_ -]?flagged|cone|isolat(?:e|ed|ing|ion)"
    r"|tier(?:_filter)?|subkind(?:_filter)?|edge[_ -]?filter|salien(?:ce|t)|select(?:ed|ion)?"
    r"|working[_ -]?set|compact(?:_visible)?|flatten(?:_?2d)?|group[_ -]?by|reset[_ -]?filters"
    r"|blast(?:\s+|[-_])radius|lineage(?:\s+|[-_])cone|plugins?"
    r"|show\s+me|delet(?:e|ed|ing|ion)|remov(?:e|ed|ing)|affect(?:s|ed)?"
    r"|break(?:s|ing)?|broken|callers?|who\s+calls|used\s+by"
    r")\b",
    re.IGNORECASE,
)
_VIEWPORT_MUTATION_TOOLS = frozenset({"wythe_focus_camera", "wythe_camera_tour"})
_VIEWPORT_VERIFICATION_GATE_PROMPT = (
    "VERIFICATION GATE: No viewport tool (`wythe_focus_camera` or `wythe_camera_tour`) was called "
    "on this turn, so the user's 3D view/lens/filters have NOT changed. Call `wythe_focus_camera` "
    "now with the exact requested parameters, or state honestly that no view change was executed."
)
_VIEWPORT_TRUTH_BANNER = (
    "> **Viewport Notice:** No camera or filter command was executed on this turn; "
    "your 3D view remains unchanged.\n\n"
)
_SENTENCE_SPLIT_RE = re.compile(r"[.!?\n]+")
_CLAIM_NEGATION_RE = re.compile(
    r"\b(?:"
    r"not|no|never|cannot|can't|couldn't|didn't|did\s+not|haven't|have\s+not|has\s+not"
    r"|unavailable|unable|unchanged|without\s+changing|if\s+you|you\s+can|can\s+(?:control|steer|switch|focus|filter)"
    r"|to\s+(?:switch|change|filter|focus|isolate|reset)"
    r")\b",
    re.IGNORECASE,
)
_FIRST_PERSON_MUTATION_RE = re.compile(
    r"\b(?:"
    r"(?:i\s+(?:have\s+)?(?:just\s+)?|i've\s+(?:just\s+)?|we\s+(?:have\s+)?(?:just\s+)?)"
    r"(?:switched|changed|filtered|focused|applied|zoomed|isolated|steered|moved|panned|orbited|"
    r"enabled|disabled|toggled|set|selected|reset|updated|activated|framed|turned\s+(?:on|off))"
    r")\b",
    re.IGNORECASE,
)
_VIEWPORT_TARGET_NOUN_RE = re.compile(
    r"\b(?:"
    r"camera|3d\s+view|view(?:port)?|lens|layout(?:_mode)?|filter(?:s)?|flagged(?:_?only)?|"
    r"only[_ -]?flagged|cone|isolate[_ -]?cone|tier(?:_filter)?|subkind(?:_filter)?|edge[_ -]?filter|"
    r"stratum|z[_ -]?wythe|slice|working[_ -]?set|compact(?:_visible)?|flatten(?:_?2d)?|"
    r"group[_ -]?by|blast(?:_mode)?|hops?|tab|contention|gravity|containers"
    r")\b",
    re.IGNORECASE,
)
_PASSIVE_MUTATION_RE = re.compile(
    r"\b(?:the\s+)?(?:3d\s+)?(?:camera|view(?:port)?|lens|layout|filter(?:s)?|cone\s+isolation|flagged[- ]?only)"
    r"\s+(?:has\s+been|have\s+been|is\s+now|was\s+just)\s+"
    r"(?:switched|changed|filtered|focused|applied|zoomed|isolated|updated|enabled|disabled|reset|set)\b",
    re.IGNORECASE,
)
_PURE_CAPABILITY_QUESTION_RE = re.compile(
    r"^\s*(?:can\s+you|are\s+you\s+able|do\s+you\s+have|what\s+(?:is|are|does|happens|breaks|tools)|"
    r"why\s+(?:is|are|does)|how\s+(?:do|does|can)|explain\b|summarize\b|describe\b|tell\s+me\b)",
    re.IGNORECASE,
)
_IMPERATIVE_CLAUSE_AFTER_QUESTION_RE = re.compile(
    r"(?:[;,]|\band\s+(?:then\s+)?|\bplease\s+)"
    r"\s*(?:switch|change|focus|filter|isolate|zoom|fly|move|steer|set|turn\s+(?:on|off)|enable|disable|reset)\b",
    re.IGNORECASE,
)
_USER_VIEWPORT_MUTATION_RE = re.compile(
    r"(?:"
    r"\b(?:use|call|run|invoke)\s+`?(?:wythe_focus_camera|wythe_camera_tour)`?\b"
    r"|\b(?:switch|change|set|apply|update)\s+(?:the\s+)?(?:3d\s+)?(?:camera|view(?:port)?|lens|"
    r"layout(?:_mode)?|tier(?:_filter)?|subkind(?:_filter)?|edge[_ -]?filter|blast(?:_mode)?|"
    r"z[_ -]?wythe|slice|zoom(?:_stratum)?|group[_ -]?by|tab)\b"
    r"|\bfilter\s+(?:to|by|for|the\s+view|nodes)\b"
    r"|\bisolate\s+(?:the\s+)?(?:3-tier\s+|lineage\s+)?cone\b"
    r"|\b(?:turn\s+(?:on|off)|enable|disable)\s+(?:the\s+)?(?:cone|isolate[_ -]?cone|flagged(?:_?only)?|"
    r"only[_ -]?flagged|connected[_ -]?only|working[_ -]?set|compact(?:_visible)?|flatten(?:_?2d)?)\b"
    r"|\bfocus\s+(?:the\s+)?(?:3d\s+)?(?:camera|view(?:port)?|on)\b"
    r"|\b(?:fly|steer|pan|orbit|zoom)\s+(?:the\s+)?(?:3d\s+)?(?:camera|to|into|on)\b"
    r"|\breset\s+(?:all\s+|the\s+)?(?:3d\s+)?(?:filters|view(?:port)?|camera)\b"
    r"|\b(?:flagged_?only|only_?flagged|isolate_?cone|working_?set_?only|compact_?visible|flatten_?2d)\s*=\s*(?:true|false)\b"
    r")",
    re.IGNORECASE,
)


def _claims_unexecuted_viewport_mutation(
    text: str | None,
    executed_tools: Sequence[str] | None,
) -> bool:
    """Return True when prose claims a viewport/lens/filter mutation occurred without executing a viewport tool."""
    if not text or not text.strip():
        return False
    if executed_tools and any(t in _VIEWPORT_MUTATION_TOOLS for t in executed_tools):
        return False
    for raw_sentence in _SENTENCE_SPLIT_RE.split(text):
        sentence = raw_sentence.strip()
        if not sentence or "Viewport Notice:" in sentence:
            continue
        if _CLAIM_NEGATION_RE.search(sentence):
            continue
        if _FIRST_PERSON_MUTATION_RE.search(sentence) and _VIEWPORT_TARGET_NOUN_RE.search(sentence):
            return True
        if _PASSIVE_MUTATION_RE.search(sentence):
            return True
    return False


def _user_requested_viewport_mutation(question: str | None) -> bool:
    """Return True when `question` directly asks the assistant to mutate the 3D camera, lens, or filters."""
    if not question or not question.strip():
        return False
    cleaned = question.strip()
    if _PURE_CAPABILITY_QUESTION_RE.search(cleaned) and not _IMPERATIVE_CLAUSE_AFTER_QUESTION_RE.search(cleaned):
        return False
    return bool(_USER_VIEWPORT_MUTATION_RE.search(cleaned))


def _apply_viewport_truth_guardrail(
    text: str,
    executed_tools: Sequence[str] | None,
) -> str:
    """Deterministically prepend `_VIEWPORT_TRUTH_BANNER` if prose falsely claims an unexecuted view change."""
    if _claims_unexecuted_viewport_mutation(text, executed_tools) and not text.lstrip().startswith(
        "> **Viewport Notice:**"
    ):
        return f"{_VIEWPORT_TRUTH_BANNER}{text}"
    return text
_plain_english_intent_re = re.compile(
    r"(?:"
    r"\bplain[- ]english\b"
    r"|\blaym[ae]n(?:'?s)?\b"
    r"|\bsimple\s+terms\b"
    r"|\bsimply\b"
    r"|\beli5\b"
    r"|\bnon[- ]technical\b"
    r"|\bin\s+short\b"
    r"|\btl;?dr\b"
    r")",
    re.IGNORECASE,
)
_semantic_ref_re = re.compile(r"`((?:t|m|d|e|f):[A-Za-z0-9_.:/-]+)`")


def build_ask_openai_tools() -> list[dict[str, Any]]:
    """Build OpenAI `/v1/chat/completions` function definitions from Wythe's core `MCP_TOOLS`."""
    by_name = {str(spec["name"]): spec for spec in MCP_TOOLS if spec.get("name")}
    tools_out: list[dict[str, Any]] = []
    for tool_name in _ask_mcp_tool_names:
        spec = by_name.get(tool_name)
        if spec is None:
            continue
        params_schema = copy.deepcopy(
            spec.get("inputSchema") or {"type": "object", "properties": {}}
        )
        tools_out.append(
            {
                "type": "function",
                "function": {
                    "name": tool_name,
                    "description": str(spec.get("description") or ""),
                    "parameters": params_schema,
                },
            }
        )
    return tools_out


def _question_requests_mcp_or_camera(question: str | None) -> bool:
    if not question or not question.strip():
        return False
    return bool(_mcp_tool_intent_re.search(question))


def _question_requests_plain_english(question: str | None) -> bool:
    if not question or not question.strip():
        return False
    return bool(_plain_english_intent_re.search(question))


def _extract_param_billions(model_id: str) -> float:
    total_hits = [float(val) for val in _total_param_scale_re.findall(model_id)]
    if total_hits:
        return max(total_hits)
    any_hits = [float(val) for val in _any_param_scale_re.findall(model_id)]
    return max(any_hits) if any_hits else 0.0


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
    *,
    prefer_vision: bool = False,
) -> tuple[str, str] | None:
    """Return `(request_model_id, display_label)` without triggering mlx_lm/mlx_vlm weight swaps."""
    raw_ids = [str(it.get("id")) for it in raw_items if it.get("id")]
    chat_items = [
        it
        for it in raw_items
        if it.get("id") and not any(bad in str(it.get("id")).lower() for bad in _non_chat_tokens)
    ]
    chat_ids = [str(it.get("id")) for it in chat_items]
    if not chat_ids:
        return None
    if preferred_model and (preferred_model == "default_model" or preferred_model in raw_ids):
        return preferred_model, preferred_model

    loaded_chat_ids = [str(it.get("id")) for it in chat_items if it.get("loaded") is True]
    if loaded_chat_ids:
        def _loaded_rank(pair: tuple[int, str]) -> tuple[int, int, float, int, int]:
            idx, mid = pair
            slug = _extract_snapshot_slug(mid) or mid
            is_helper = bool(_helper_model_re.search(mid) or _helper_model_re.search(slug))
            is_vis = _looks_vision_capable(slug) or _looks_vision_capable(mid)
            scale_b = max(_extract_param_billions(slug), _extract_param_billions(mid))
            return (
                0 if is_helper else 1,
                1 if (prefer_vision and is_vis) else 0,
                scale_b,
                1 if is_vis else 0,
                -idx,
            )

        _, best_loaded_id = max(enumerate(loaded_chat_ids), key=_loaded_rank)
        return best_loaded_id, (_extract_snapshot_slug(best_loaded_id) or best_loaded_id)

    if any(isinstance(it.get("loaded"), bool) for it in raw_items):
        return None

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
    fallback_pinned_text_seat: OnDeviceEngineStatus | None = None
    fallback_default_vision_seat: OnDeviceEngineStatus | None = None
    fallback_default_seat: OnDeviceEngineStatus | None = None
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
        selected = _select_safe_seat_model(
            raw_items,
            preferred_model,
            server_header=srv_hdr,
            prefer_vision=prefer_vision,
        )
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
            and (
                preferred_model.strip() == "default_model"
                or preferred_model.strip() in {str(item.get("id")) for item in raw_items}
            )
        )
        if explicit_custom_base == base or explicit_model_match:
            return seat_status
        if req_model != "default_model":
            if has_vision or not prefer_vision:
                return seat_status
            if fallback_pinned_text_seat is None:
                fallback_pinned_text_seat = seat_status
            continue
        if has_vision and fallback_default_vision_seat is None:
            fallback_default_vision_seat = seat_status
        if fallback_default_seat is None:
            fallback_default_seat = seat_status

    if fallback_pinned_text_seat is not None:
        return fallback_pinned_text_seat
    if prefer_vision and fallback_default_vision_seat is not None:
        return fallback_default_vision_seat
    if fallback_default_seat is not None:
        return fallback_default_seat

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
    question: str | None = None,
    prefer_mcp_tools: bool = False,
) -> list[Literal["apple", "local"]]:
    """Select backend engine priority; prefer pinned/loaded local `/v1` or MCP/multimodal seats."""
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
    local_pinned_or_loaded = bool(
        local_ready and local_status and local_status.model_id != "default_model"
    )
    local_vlm_ready = bool(local_ready and local_status and local_status.supports_vision)
    multimodal_attached = bool((image_data_url and image_data_url.strip()) or has_screenshot)
    needs_mcp_tools = prefer_mcp_tools or _question_requests_mcp_or_camera(question)

    order: list[Literal["apple", "local"]] = []
    if (
        local_pinned_or_loaded
        or (multimodal_attached and local_vlm_ready)
        or (local_ready and needs_mcp_tools)
    ):
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


def _cap_tool_output(raw_text: str) -> str:
    if len(raw_text) <= _ask_mcp_max_tool_chars:
        return raw_text
    suffix = "\n...[truncated]"
    return raw_text[: _ask_mcp_max_tool_chars - len(suffix)] + suffix


def _collect_tool_refs(
    args_dict: dict[str, Any],
    raw_text: str,
    refs_out: list[str] | None,
) -> None:
    if refs_out is None:
        return
    candidates: list[str] = []
    raw_focus = args_dict.get("focus_node_ids")
    if isinstance(raw_focus, list):
        candidates.extend(str(item).strip() for item in raw_focus if isinstance(item, str) and item.strip())
    for fenced in re.findall(r"```json\s*(\{.*?\})\s*```", raw_text, re.DOTALL):
        try:
            parsed_block = json.loads(fenced)
        except ValueError:
            continue
        if isinstance(parsed_block, dict):
            blk_focus = parsed_block.get("focus_node_ids")
            if isinstance(blk_focus, list):
                candidates.extend(
                    str(item).strip() for item in blk_focus if isinstance(item, str) and item.strip()
                )
    candidates.extend(_semantic_ref_re.findall(raw_text)[:10])
    for ref_item in candidates:
        if ref_item and ref_item not in refs_out:
            refs_out.append(ref_item)


def _execute_inprocess_mcp_tool_call(
    db_session: Session,
    *,
    tc_id: str,
    fn_name: str,
    raw_arguments: Any,
    tool_schemas_by_name: dict[str, dict[str, Any]],
    all_known_tool_names: frozenset[str] = frozenset(),
    target_slug: str | None,
    session_id: str | None,
    executed_tools_out: list[str] | None,
    failed_tools_out: list[tuple[str, str]] | None = None,
    hinted_refs_out: list[str] | None,
) -> tuple[str, str]:
    err_tool_label = fn_name or "unknown"

    def _reject_call(serialized_args: str, error_text: str) -> tuple[str, str]:
        if failed_tools_out is not None:
            failed_tools_out.append((err_tool_label, error_text))
        err_payload = json.dumps(
            {
                "ok": False,
                "isError": True,
                "tool": err_tool_label,
                "error": error_text,
            }
        )
        return serialized_args, _cap_tool_output(err_payload)

    if raw_arguments is None or (isinstance(raw_arguments, str) and not raw_arguments.strip()):
        args_dict: dict[str, Any] = {}
    elif isinstance(raw_arguments, dict):
        args_dict = dict(raw_arguments)
    elif isinstance(raw_arguments, str):
        try:
            loaded = json.loads(raw_arguments)
        except ValueError as exc:
            return _reject_call("{}", f"Malformed JSON arguments: {exc}")
        if not isinstance(loaded, dict):
            return _reject_call("{}", "Tool arguments must be a JSON object.")
        args_dict = dict(loaded)
    else:
        return _reject_call("{}", "Tool arguments must be a JSON object string.")

    canonical_fn = (
        fn_name.replace("atlas_", "wythe_", 1) if fn_name.startswith("atlas_") else fn_name
    )
    spec = tool_schemas_by_name.get(fn_name) or tool_schemas_by_name.get(canonical_fn)
    if not fn_name or spec is None:
        offered_list = list(tool_schemas_by_name.keys())
        if fn_name in all_known_tool_names or canonical_fn in all_known_tool_names:
            return _reject_call(
                json.dumps(args_dict),
                f"Unoffered Wythe MCP tool `{fn_name}` is not enabled for this Ask round. "
                f"Offered tools: {offered_list}.",
            )
        return _reject_call(
            json.dumps(args_dict),
            f"Unknown Wythe MCP tool `{fn_name}`. Available tools: {offered_list}.",
        )

    props = (spec.get("inputSchema") or {}).get("properties") or {}
    bound_target = (target_slug or "").strip() or None
    bound_sid = (session_id or "").strip() or None

    if bound_target is not None:
        for t_key in ("target", "target_slug"):
            if t_key not in args_dict or args_dict[t_key] is None:
                continue
            raw_t_val = args_dict[t_key]
            if not isinstance(raw_t_val, str):
                return _reject_call(
                    json.dumps(args_dict),
                    f"Target scope violation: `{t_key}` must match active target `{bound_target}`.",
                )
            explicit_t = raw_t_val.strip()
            if explicit_t and explicit_t != bound_target:
                return _reject_call(
                    json.dumps(args_dict),
                    f"Target scope violation: `{t_key}={explicit_t}` does not match active Ask target `{bound_target}`.",
                )
        if "target_slug" in args_dict and "target_slug" not in props:
            args_dict.pop("target_slug", None)
        if "target" in props:
            args_dict["target"] = bound_target
        if "target_slug" in props:
            args_dict["target_slug"] = bound_target

    for s_key in ("session_id", "refresh_session_id"):
        if s_key not in args_dict or args_dict[s_key] is None:
            continue
        raw_s_val = args_dict[s_key]
        if not isinstance(raw_s_val, str):
            return _reject_call(
                json.dumps(args_dict),
                f"Session scope violation: `{s_key}` must be a string matching active session.",
            )
        raw_sid = raw_s_val.strip()
        if raw_sid and raw_sid != "default":
            if bound_sid is not None and raw_sid != bound_sid:
                return _reject_call(
                    json.dumps(args_dict),
                    f"Session scope violation: `{s_key}={raw_sid}` does not match active Ask session `{bound_sid}`.",
                )
            if bound_target is not None:
                existing_inv = get_investigation_session(raw_sid)
                if existing_inv is not None and existing_inv.target_slug != bound_target:
                    return _reject_call(
                        json.dumps(args_dict),
                        f"Session scope violation: session `{raw_sid}` belongs to target "
                        f"`{existing_inv.target_slug}`, not `{bound_target}`.",
                    )

    if canonical_fn in _session_scoped_mcp_tools and bound_sid is not None:
        args_dict["session_id"] = bound_sid

    rpc_msg = {
        "jsonrpc": "2.0",
        "id": tc_id,
        "method": "tools/call",
        "params": {"name": canonical_fn, "arguments": args_dict},
    }
    try:
        rpc_res = dispatch_mcp_request(
            db_session, rpc_msg, slice_mode="full", local_viewport_only=True
        )
    except TypeError:
        rpc_res = dispatch_mcp_request(db_session, rpc_msg, slice_mode="full")

    rpc_err = (rpc_res or {}).get("error")
    res_obj = (rpc_res or {}).get("result") or {}
    blocks = res_obj.get("content") if isinstance(res_obj.get("content"), list) else []
    joined_text = "\n\n".join(
        str(b.get("text") or "")
        for b in blocks
        if isinstance(b, dict) and b.get("type") == "text" and b.get("text")
    ).strip()
    if rpc_err:
        err_msg = str(rpc_err.get("message") if isinstance(rpc_err, dict) else rpc_err)
        if failed_tools_out is not None:
            failed_tools_out.append((err_tool_label, err_msg))
        out_str = json.dumps({"ok": False, "isError": True, "tool": canonical_fn, "error": err_msg})
    elif res_obj.get("isError"):
        err_msg = joined_text or "MCP tool returned an error."
        if failed_tools_out is not None:
            failed_tools_out.append((err_tool_label, err_msg))
        out_str = json.dumps(
            {
                "ok": False,
                "isError": True,
                "tool": canonical_fn,
                "error": err_msg,
            }
        )
    else:
        if executed_tools_out is not None and canonical_fn not in executed_tools_out:
            executed_tools_out.append(canonical_fn)
        _collect_tool_refs(args_dict, joined_text, hinted_refs_out)
        out_str = joined_text or json.dumps(res_obj)
    return json.dumps(args_dict), _cap_tool_output(out_str)


_TOOL_FALLBACK_REASON = (
    "Local endpoint rejected OpenAI tools payload; answered in text-only mode without live MCP tool execution."
)


def build_ask_instructions(
    tools_enabled: bool = True,
    *,
    plain_english: bool = False,
    has_corrections: bool = False,
) -> str:
    """Build capability-honest system instructions for Ask Wythe (`tools_enabled` & `plain_english`)."""
    corr_sys_note = (
        " Respect active Human Investigation Corrections in Section 2 as authoritative working "
        "clarifications for this session, while noting they remain conversation context until "
        "deliberately promoted to a governance ruling."
        if has_corrections
        else ""
    )
    direct_address = (
        "Speak directly to the user in second person ('you'); "
        "NEVER narrate about the user in third person (never write 'The user is...'). "
    )
    if tools_enabled:
        capability_block = (
            "Ground all repository, node, color, rule, and lineage statements strictly in the Live 3D Camera & X-Ray "
            "facts below and in any bound Wythe MCP tool outputs (SQL Truth, Backend Manipulate, Frontend Display). "
            "You have live Wythe MCP tools bound directly in this chat (`wythe_focus_camera`, `wythe_camera_tour`, "
            "`wythe_lineage_cone`, `wythe_blast_radius`, `wythe_findings`, `wythe_what_is_this`, `wythe_overview`, "
            "`wythe_plugins`, `wythe_investigation`), and external MCP clients can also connect via `/api/v1/mcp` "
            "or `wythe mcp`. Yes, you CAN directly control and steer the user's live 3D browser camera, lens, "
            "layout mode, Z-wythe slice, and zoom stratum via `wythe_focus_camera` and `wythe_camera_tour`, and you "
            "can inspect architecture evidence outside the current camera frustum via `wythe_lineage_cone`, "
            "`wythe_findings`, `wythe_what_is_this`, `wythe_blast_radius`, `wythe_overview`, `wythe_plugins`, and "
            "`wythe_investigation`. When asked whether you can control the camera or what MCP tools are exposed, "
            "confirm accurately that you can control the live 3D camera via `wythe_focus_camera` and "
            "`wythe_camera_tour` and name the exposed Wythe MCP tools rather than claiming you cannot control a "
            "camera. When asked to focus, move, fly, frame, or tour the 3D camera, switch lens/layout/zoom stratum, "
            "apply filters (`only_flagged`/`flagged_only`, `isolate_cone`, `tier_filter`, `subkind_filter`, "
            "`edge_filter`, `working_set_only`, `compact_visible`, `flatten_2d`, `group_by`, `reset_filters`), "
            "or inspect unshown nodes outside the current frustum, you MUST call `wythe_focus_camera` (or the "
            "corresponding MCP tool) BEFORE claiming any UI/view mutation, and ground your answer in the returned "
            "tool payload (including honest `delivery_state`). NEVER state in prose that you switched, filtered, "
            "focused, or isolated the view unless the viewport tool actually executed on this turn. "
        )
    else:
        capability_block = (
            "Ground all repository, node, color, rule, and lineage statements strictly in the supplied Live 3D Camera "
            "& X-Ray facts below (SQL Truth, Backend Manipulate, Frontend Display). "
            "Live MCP tool execution and direct 3D camera steering are NOT available on this text-only completion path "
            "(external MCP clients can connect separately via `/api/v1/mcp` or `wythe mcp`). "
            "Do NOT claim that you can steer or move the live 3D camera here, NEVER invent or hallucinate tool names "
            "(such as `wythe_backend_manipulate`), and if asked to move the camera or run a live MCP tool, state "
            "honestly that live MCP tool execution is unavailable on this text-only completion path while answering "
            "from the supplied X-Ray context. "
        )

    if plain_english:
        style_block = (
            "Plain-English mode: Explain clearly in 2 to 4 short everyday sentences without rigid section headers "
            "(do NOT output forced headings and do NOT dump raw internal severity/confidence/evidence tags). "
            "Explain plainly what this code or data store does, why it has a warning or color, and what happens in "
            "practice if you change or delete it (including any package `__init__.py` re-export import-crash trap), "
            "staying strictly grounded in the provided facts without inventing files, tables, or callers. "
            "Never treat a warning color alone as proof that a file or store is unused or safe to delete."
        )
    else:
        style_block = (
            "Cite exact rule codes (e.g. TRUTH-002, MANIP-001, DISP-005), node names, on-screen colors, and "
            "`file:line` pointers, and never invent files or tables. Never treat a node's color or status (such as "
            "`gray_zone` or `duplicated_truth`) as standalone proof of duplicate contents, authoritative ownership, "
            "or safe deletion. Keep declared store purpose distinct from observed verification, distinguish a node's "
            "discovery coordinate from causal writer operation lines, preserve uncertainty when expiration or "
            "invalidation is unknown, and present remediations as suggested changes rather than verified fixes."
        )

    return (
        "You are Wythe's embedded real-time 3-tier software architecture & lineage verifier assistant. "
        f"{direct_address}{capability_block}{style_block}{corr_sys_note}"
    )


def _run_local_chat_completion(
    base_url: str,
    model_id: str,
    instructions: str,
    user_text: str,
    snap_path: Path | None,
    *,
    question: str | None = None,
    toolless_instructions: str | None = None,
    inline_data_url: str | None = None,
    history: list[AskChatTurn] | None = None,
    supports_vision: bool | None = None,
    db_session: Session | None = None,
    target_slug: str | None = None,
    session_id: str | None = None,
    openai_tools: list[dict[str, Any]] | None = None,
    executed_tools_out: list[str] | None = None,
    hinted_refs_out: list[str] | None = None,
    max_rounds: int = _ask_mcp_max_rounds,
    max_calls_per_round: int = _ask_mcp_max_calls_per_round,
) -> tuple[str, bool, str | None]:
    used_vision = False
    tool_fallback_note: str | None = None
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
    messages: list[dict[str, Any]] = [
        {"role": "system", "content": instructions},
        *prior_msgs,
        {"role": "user", "content": user_content},
    ]
    active_tools: list[dict[str, Any]] | None = (
        openai_tools
        if openai_tools is not None
        else (build_ask_openai_tools() if db_session is not None else None)
    )
    all_mcp_schemas_by_name = {str(spec["name"]): spec for spec in MCP_TOOLS if spec.get("name")}
    all_known_mcp_names = frozenset(all_mcp_schemas_by_name.keys())

    def _schemas_for_offered_tools(
        offered: list[dict[str, Any]] | None,
    ) -> dict[str, dict[str, Any]]:
        allowed: dict[str, dict[str, Any]] = {}
        for item in offered or ():
            if not isinstance(item, dict):
                continue
            fn_def = item.get("function")
            offered_name = str(
                fn_def.get("name") if isinstance(fn_def, dict) else item.get("name") or ""
            ).strip()
            if not offered_name:
                continue
            canon_offered = (
                offered_name.replace("atlas_", "wythe_", 1)
                if offered_name.startswith("atlas_")
                else offered_name
            )
            matched_spec = all_mcp_schemas_by_name.get(offered_name) or all_mcp_schemas_by_name.get(
                canon_offered
            )
            if matched_spec is not None:
                allowed[offered_name] = matched_spec
        return allowed

    def _post_chat_message(
        req_messages: list[dict[str, Any]],
        req_tools: list[dict[str, Any]] | None,
    ) -> dict[str, Any]:
        body: dict[str, Any] = {
            "model": model_id,
            "temperature": 0.2,
            "max_tokens": 900,
            "messages": req_messages,
        }
        if req_tools:
            body["tools"] = req_tools
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
        msg = choice.get("message")
        return msg if isinstance(msg, dict) else {}

    def _send_round(
        round_idx: int,
        req_tools: list[dict[str, Any]] | None,
    ) -> tuple[dict[str, Any], list[dict[str, Any]] | None]:
        nonlocal used_vision, tool_fallback_note
        try:
            return _post_chat_message(messages, req_tools), req_tools
        except urllib.error.HTTPError as exc:
            # 1) Text-only servers (e.g. `mlx_lm.server`) serving VLM-named checkpoints reject
            # multimodal `image_url` list `content` with HTTP 400/404/415/422/500 while still
            # supporting native OpenAI `tools` on string `content`. Strip the image FIRST while
            # preserving `req_tools`, and only strip `req_tools` if text+tools also fails.
            if round_idx == 0 and used_vision and exc.code in (400, 404, 415, 422, 500):
                messages[len(prior_msgs) + 1] = {"role": "user", "content": user_text}
                used_vision = False
                try:
                    return _post_chat_message(messages, req_tools), req_tools
                except urllib.error.HTTPError as text_http:
                    if req_tools and text_http.code in (400, 404, 422, 501):
                        messages[0] = {
                            "role": "system",
                            "content": toolless_instructions or build_ask_instructions(tools_enabled=False),
                        }
                        tool_fallback_note = _TOOL_FALLBACK_REASON
                        try:
                            return _post_chat_message(messages, None), None
                        except urllib.error.HTTPError as final_http:
                            raise RuntimeError(
                                f"Local model server at {base_url} answered HTTP {final_http.code}."
                            ) from final_http
                    raise RuntimeError(
                        f"Local model server at {base_url} answered HTTP {text_http.code}."
                    ) from text_http
                except (TimeoutError, OSError, ValueError) as inner_exc:
                    raise RuntimeError(
                        f"Local model text fallback at {base_url} failed ({type(inner_exc).__name__}: {inner_exc})."
                    ) from inner_exc
            # 2) Already text-only request where server rejects `tools` parameter.
            if round_idx == 0 and req_tools and exc.code in (400, 404, 422, 501):
                messages[0] = {
                    "role": "system",
                    "content": toolless_instructions or build_ask_instructions(tools_enabled=False),
                }
                tool_fallback_note = _TOOL_FALLBACK_REASON
                try:
                    return _post_chat_message(messages, None), None
                except urllib.error.HTTPError as inner_http:
                    raise RuntimeError(
                        f"Local model server at {base_url} answered HTTP {inner_http.code}."
                    ) from inner_http
            raise RuntimeError(f"Local model server at {base_url} answered HTTP {exc.code}.") from exc
        except urllib.error.URLError as exc:
            raise RuntimeError(f"Could not reach local model server at {base_url} ({exc.reason}).") from exc
        except (TimeoutError, OSError, ValueError) as exc:
            raise RuntimeError(
                f"Local model server at {base_url} failed during completion ({type(exc).__name__}: {exc})."
            ) from exc

    seen_executed: list[str] = executed_tools_out if executed_tools_out is not None else []
    failed_tools: list[tuple[str, str]] = []
    ran_any_tools = False
    enforcement_retried = False
    effective_max_rounds = max(1, max_rounds)
    round_idx = 0
    while round_idx < effective_max_rounds:
        msg, active_tools = _send_round(round_idx, active_tools)
        round_tool_schemas = _schemas_for_offered_tools(active_tools)
        raw_calls = msg.get("tool_calls")
        valid_calls = (
            [tc for tc in raw_calls[:max_calls_per_round] if isinstance(tc, dict)]
            if isinstance(raw_calls, list) and db_session is not None and active_tools
            else []
        )
        if not valid_calls:
            text = str(msg.get("content") or "").strip()
            has_vp_tool = any(t in _VIEWPORT_MUTATION_TOOLS for t in seen_executed)
            if (
                db_session is not None
                and active_tools
                and not has_vp_tool
                and not enforcement_retried
                and (
                    _claims_unexecuted_viewport_mutation(text, seen_executed)
                    or _user_requested_viewport_mutation(question)
                )
            ):
                messages.append({"role": "assistant", "content": text})
                messages.append({"role": "user", "content": _VIEWPORT_VERIFICATION_GATE_PROMPT})
                enforcement_retried = True
                effective_max_rounds += 1
                round_idx += 1
                continue
            if text:
                return (
                    _apply_viewport_truth_guardrail(text, seen_executed),
                    used_vision,
                    tool_fallback_note,
                    "model",
                )
            if ran_any_tools:
                break
            raise RuntimeError(f"Local model `{model_id}` returned an empty completion.")

        ran_any_tools = True
        sanitized_calls: list[dict[str, Any]] = []
        tool_reply_msgs: list[dict[str, Any]] = []
        for call_idx, tc in enumerate(valid_calls):
            raw_id = tc.get("id")
            tc_id = (
                str(raw_id).strip()
                if isinstance(raw_id, str) and raw_id.strip()
                else f"call_{round_idx}_{call_idx}"
            )
            fn_obj = tc.get("function") if isinstance(tc.get("function"), dict) else {}
            fn_name = str(fn_obj.get("name") or "").strip()
            safe_fn_name = fn_name or "unknown_tool"
            args_json_str, tool_result_str = _execute_inprocess_mcp_tool_call(
                db_session,
                tc_id=tc_id,
                fn_name=fn_name,
                raw_arguments=fn_obj.get("arguments"),
                tool_schemas_by_name=round_tool_schemas,
                all_known_tool_names=all_known_mcp_names,
                target_slug=target_slug,
                session_id=session_id,
                executed_tools_out=seen_executed,
                failed_tools_out=failed_tools,
                hinted_refs_out=hinted_refs_out,
            )
            sanitized_calls.append(
                {
                    "id": tc_id,
                    "type": "function",
                    "function": {"name": safe_fn_name, "arguments": args_json_str},
                }
            )
            tool_reply_msgs.append(
                {
                    "role": "tool",
                    "tool_call_id": tc_id,
                    "name": safe_fn_name,
                    "content": tool_result_str,
                }
            )
        messages.append(
            {
                "role": "assistant",
                "content": str(msg.get("content") or ""),
                "tool_calls": sanitized_calls,
            }
        )
        messages.extend(tool_reply_msgs)
        round_idx += 1

    synth_msg, _ = _send_round(effective_max_rounds, None)
    synth_text = str(synth_msg.get("content") or "").strip()
    if synth_text:
        return (
            _apply_viewport_truth_guardrail(synth_text, seen_executed),
            used_vision,
            tool_fallback_note,
            "model",
        )
    if seen_executed or failed_tools:
        notice_lines = [
            (
                f"> **System / Tool Status Notice (non-model fallback):** Local model `{model_id}` "
                "returned empty synthesis after MCP tool dispatch; your question remains unanswered by the model."
            ),
        ]
        if seen_executed:
            succeeded_fmt = ", ".join(f"`{t}`" for t in seen_executed)
            notice_lines.append(f"- **Succeeded MCP tool call(s):** {succeeded_fmt}")
        if failed_tools:
            failed_fmt = "; ".join(
                f"`{t_name}` (`isError=true`: {t_err[:160]})" for t_name, t_err in failed_tools
            )
            notice_lines.append(f"- **Failed / rejected MCP tool call(s):** {failed_fmt}")
        empty_synth_reason = (
            f"Local model `{model_id}` returned empty synthesis after MCP tool dispatch; "
            "emitted system tool-execution status notice (question remains unanswered by model)."
        )
        eff_tool_fb = (
            f"{tool_fallback_note} {empty_synth_reason}".strip()
            if tool_fallback_note
            else empty_synth_reason
        )
        return (
            "\n".join(notice_lines),
            used_vision,
            eff_tool_fb,
            "scanner_brief",
        )
    raise RuntimeError(f"Local model `{model_id}` returned an empty completion.")


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
                if (
                    prior_t.status == "answered"
                    and prior_t.authored_by == "model"
                    and prior_t.answer_markdown
                ):
                    eff_history.append(AskChatTurn(role="user", content=prior_t.question[:2000]))
                    eff_history.append(
                        AskChatTurn(role="assistant", content=prior_t.answer_markdown[:4000])
                    )

    is_plain_english = _question_requests_plain_english(payload.question)
    instructions = build_ask_instructions(
        tools_enabled=True,
        plain_english=is_plain_english,
        has_corrections=bool(corrections),
    )
    toolless_instructions = build_ask_instructions(
        tools_enabled=False,
        plain_english=is_plain_english,
        has_corrections=bool(corrections),
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
        plain_english=is_plain_english,
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
    authored_by_source: Literal["model", "scanner_brief"] = "model"
    engine_used: str = "local"
    model_used = ""
    used_vision = False
    fallback_reason: str | None = None
    hinted_refs: list[str] = []
    executed_tools: list[str] = []

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
        question=payload.question,
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
                try:
                    answer_md, hinted_refs = run_apple_engine_ask(
                        toolless_instructions,
                        apple_prompt,
                        plain_english=is_plain_english,
                    )
                except TypeError:
                    answer_md, hinted_refs = run_apple_engine_ask(
                        toolless_instructions,
                        apple_prompt,
                    )
                engine_used = "apple"
                authored_by_source = "model"
                executed_tools = []
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
                local_executed: list[str] = []
                local_refs: list[str] = []
                chat_res = _run_local_chat_completion(
                    local_status.base_url,
                    local_status.model_id,
                    instructions,
                    full_prompt,
                    snap_path,
                    question=payload.question,
                    toolless_instructions=toolless_instructions,
                    inline_data_url=inline_snap,
                    history=eff_history,
                    supports_vision=local_status.supports_vision,
                    db_session=session,
                    target_slug=target.slug if target is not None else focus.active_slug,
                    session_id=eff_sid,
                    executed_tools_out=local_executed,
                    hinted_refs_out=local_refs,
                )
                if len(chat_res) == 4:
                    answer_md, used_vision, tool_fallback_note, authored_by_source = chat_res
                elif len(chat_res) == 3:
                    answer_md, used_vision, tool_fallback_note = chat_res  # type: ignore[misc]
                    authored_by_source = "model"
                else:
                    answer_md, used_vision = chat_res  # type: ignore[misc]
                    tool_fallback_note = None
                    authored_by_source = "model"
                executed_tools = local_executed
                hinted_refs = local_refs
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
                    base_fb = f"{prior_fail_note}; answered via fallback `local` ({model_used})."
                    fallback_reason = (
                        f"{base_fb} {tool_fallback_note}" if tool_fallback_note else base_fb
                    )
                elif tool_fallback_note:
                    fallback_reason = tool_fallback_note
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

    answer_md = _apply_viewport_truth_guardrail(answer_md, executed_tools)

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

    eff_authored_by: Literal["model", "scanner_brief"] = (
        "scanner_brief" if authored_by_source != "model" else "model"
    )
    if eff_authored_by != "model" and not fallback_reason:
        fallback_reason = (
            f"Local model `{model_used or 'local'}` returned empty synthesis after MCP tool dispatch; "
            "emitted system tool-execution status notice (question remains unanswered by model)."
        )
    eff_fallback_reason = fallback_reason[:480] if fallback_reason else None

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
                authored_by=eff_authored_by,
                fallback_reason=eff_fallback_reason,
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
        authored_by=eff_authored_by,
        engine_used=engine_used,  # type: ignore[arg-type]
        model_id=model_used,
        used_vision_snapshot=used_vision,
        image_supplied=has_multimodal_image,
        fallback_reason=eff_fallback_reason,
        context_headline=focus.headline,
        answer_markdown=answer_md,
        executed_tools=executed_tools,
        referenced_node_ids=matched_node_ids[:6],
        validated_references=val_refs,
        evidence_identity=ev_identity,
        context_budget=budget,
        observed_at=utc_now(),
    )


answer_ask_request = ask_wythe_with_live_context
