"""Pure lexical & structural TypeScript/JavaScript inspector for `wythe-plugin-agent-harness`.

Security boundary:
- Never invokes `node`, `tsc`, or target JavaScript/TypeScript code.
- Preserves exact 1-based line numbers via string-aware comment blanking and resilient
  brace/bracket balancing that tolerates malformed syntax with zero crashes.
"""

from __future__ import annotations

import re
from pathlib import PurePosixPath
from typing import TYPE_CHECKING

from wythe_plugin_agent_harness.python_inspector import (
    CANONICAL_CLIENT_STEM_RE,
    DISCOVERY_IDENTIFIERS,
    RAW_COMPLETION_PATH_RE,
    AgentLoopRecord,
    CanonicalClientRecord,
    HarnessInspectionBundle,
    HelperCallRecord,
    PromptSurface,
    RawHttpBypassRecord,
    RegistryLoadRecord,
    ToolManifestRecord,
    estimate_schema_budget,
    iter_safe_repo_files,
)

if TYPE_CHECKING:
    from pathlib import Path

_TS_DISCOVERY_NAMES = DISCOVERY_IDENTIFIERS | frozenset(
    {"searchTools", "discoverCapabilities", "discoverTools"}
)
_TS_SLICE_TOKENS = ("--slice", "slice_mode", "sliceMode", "toolSlice", "tool_slice")
_TS_VOLATILE_RE = re.compile(
    r"\b(?:new\s+Date\s*\(|Date\.now\s*\(|\.toISOString\s*\(|\.toLocaleString\s*\("
    r"|crypto\.randomUUID\s*\(|Math\.random\s*\()"
)
_TS_TEMPLATE_EXPR_RE = re.compile(r"\$\{([^}]{1,200})\}")
_TS_FN_DECL_RE = re.compile(
    r"(?:export\s+)?(?:async\s+)?function\s+(?P<fn>[A-Za-z_$][\w$]*)\s*(?:<[^>]{0,120}>)?\s*\([^)]*\)\s*(?::\s*[^{=]+)?\{"
    r"|(?:export\s+)?(?:const|let)\s+(?P<arrow>[A-Za-z_$][\w$]*)\s*(?::\s*[^=]+)?=\s*(?:async\s*)?(?:\([^)]*\)|[A-Za-z_$][\w$]*)\s*(?::\s*[^=]+)?=>\s*\{"
)
_TS_CONST_STR_RE = re.compile(
    r"(?:export\s+)?(?:const|let)\s+(?P<name>[A-Za-z_$][\w$]*)\s*(?::\s*[^=]+)?=\s*(?P<rhs>`(?:\\.|[^`\\])*`|'(?:\\.|[^'\\])*'|\"(?:\\.|[^\"\\])*\")"
)
_TS_CONST_INT_RE = re.compile(
    r"(?:export\s+)?const\s+(?P<name>[A-Za-z_$][\w$]*)\s*(?::\s*number\s*)?=\s*(?P<val>\d+)\b"
)
_TS_SERVER_TOOL_RE = re.compile(
    r"\b(?:server|mcp)\.tool\(\s*['\"](?P<name>[A-Za-z0-9_.:-]+)['\"]"
)
_TS_ARRAY_DECL_RE = re.compile(
    r"(?:export\s+)?const\s+(?P<name>[A-Za-z_$][\w$]*)\s*(?::\s*[^=]+)?=\s*\["
)
_TS_ARRAY_FROM_RE = re.compile(
    r"(?:export\s+)?const\s+(?P<name>[A-Za-z_$][\w$]*)\s*(?::\s*[^=]+)?=\s*Array\.from\(\s*\{\s*length\s*:\s*(?P<len>\d+)\s*\}"
)
_TS_RAW_FETCH_RE = re.compile(
    r"\b(?P<callee>fetch|axios\.post|axios\.request|undici\.request)\s*\(\s*(?P<arg>`(?:\\.|[^`\\])*`|'(?:\\.|[^'\\])*'|\"(?:\\.|[^\"\\])*\"|[A-Za-z_$][\w$]*)"
)


def blank_ts_comments(source: str) -> str:
    """Replace `//` and `/* ... */` comments with spaces while preserving strings and `\n`."""
    out = list(source)
    i = 0
    n = len(source)
    while i < n:
        ch = source[i]
        nxt = source[i + 1] if i + 1 < n else ""
        if ch in ("'", '"', "`"):
            quote = ch
            i += 1
            while i < n:
                if source[i] == "\\":
                    i += 2
                    continue
                if source[i] == quote:
                    i += 1
                    break
                i += 1
            continue
        if ch == "/" and nxt == "/":
            while i < n and source[i] != "\n":
                out[i] = " "
                i += 1
            continue
        if ch == "/" and nxt == "*":
            out[i] = " "
            out[i + 1] = " "
            i += 2
            while i < n:
                if source[i] == "*" and i + 1 < n and source[i + 1] == "/":
                    out[i] = " "
                    out[i + 1] = " "
                    i += 2
                    break
                if source[i] != "\n":
                    out[i] = " "
                i += 1
            continue
        i += 1
    return "".join(out)


def _line_at(text: str, offset: int) -> int:
    return text.count("\n", 0, max(0, offset)) + 1


def _find_balanced_end(text: str, open_idx: int, open_ch: str, close_ch: str) -> int:
    """Return index of matching `close_ch` (or `-1` if unbalanced), skipping string literals."""
    depth = 0
    i = open_idx
    n = len(text)
    while i < n:
        ch = text[i]
        if ch in ("'", '"', "`"):
            q = ch
            i += 1
            while i < n:
                if text[i] == "\\":
                    i += 2
                    continue
                if text[i] == q:
                    i += 1
                    break
                i += 1
            continue
        if ch == open_ch:
            depth += 1
        elif ch == close_ch:
            depth -= 1
            if depth == 0:
                return i
        i += 1
    return -1


def _ts_volatile_reasons(expr_src: str, str_bindings: dict[str, str], depth: int = 0) -> list[str]:
    if depth > 4:
        return []
    reasons: list[str] = []
    for m in _TS_VOLATILE_RE.finditer(expr_src):
        tok = re.sub(r"\s+", " ", m.group(0).rstrip("(")).strip()
        if tok not in reasons:
            reasons.append(tok)

    for tm in _TS_TEMPLATE_EXPR_RE.finditer(expr_src):
        inner = tm.group(1).strip()
        for sub_r in _ts_volatile_reasons(inner, str_bindings, depth + 1):
            if sub_r not in reasons:
                reasons.append(sub_r)
        if re.fullmatch(r"[A-Za-z_$][\w$]*", inner):
            if inner.isupper():
                continue
            if inner in str_bindings:
                for sub_r in _ts_volatile_reasons(str_bindings[inner], str_bindings, depth + 1):
                    if sub_r not in reasons:
                        reasons.append(sub_r)
                continue
            low = inner.lower()
            if inner not in reasons and any(
                k in low
                for k in (
                    "rag",
                    "memory",
                    "memor",
                    "retrieved",
                    "timestamp",
                    "session",
                    "turn",
                    "clock",
                    "now",
                    "uuid",
                    "nonce",
                )
            ):
                reasons.append(inner)

    ident = expr_src.strip()
    if re.fullmatch(r"[A-Za-z_$][\w$]*", ident) and not ident.isupper() and ident in str_bindings:
        for sub_r in _ts_volatile_reasons(str_bindings[ident], str_bindings, depth + 1):
            if sub_r not in reasons:
                reasons.append(sub_r)
    return reasons


_TS_ROLE_OBJ_RE = re.compile(
    r"\{\s*role\s*:\s*['\"](?P<role>system|developer|user)['\"]\s*,\s*content\s*:\s*(?P<content>`(?:\\.|[^`\\])*`|'(?:\\.|[^'\\])*'|\"(?:\\.|[^\"\\])*\"|[A-Za-z_$][\w$.()]*)"
)
_TS_SYS_PROP_RE = re.compile(
    r"(?:^|[,{\s])(?P<prop>system|systemPrompt)\s*:\s*(?P<val>`(?:\\.|[^`\\])*`|'(?:\\.|[^'\\])*'|\"(?:\\.|[^\"\\])*\"|[A-Za-z_$][\w$]*)",
    re.MULTILINE,
)
_TS_LLM_CONTEXT_RE = re.compile(
    r"\b(?:openai|anthropic|mcp|modelcontextprotocol|ollama|mlx|litellm|vllm|LanguageModel"
    r"|FoundationModels|systemPrompt|chat\.completions|messages\.create)\b"
    r"|sampling/createMessage|/v1/(?:chat/)?completions|/v1/messages"
)
_TS_TOOL_NAME_PROP_RE = re.compile(r"\bname\s*:\s*['\"](?P<name>[A-Za-z0-9_.:-]+)['\"]")
_TS_LOOP_HEAD_RE = re.compile(r"\b(?P<kw>while|for)\s*\((?P<cond>[^)]{0,180})\)\s*\{")
_TS_REG_PATH_RE = re.compile(
    r"['\"`](?P<path>(?:\.\.?/)*(?:config|configs)/[A-Za-z0-9_./-]+\.(?:json|ya?ml))['\"`]"
)


def _extract_ts_tool_manifests(
    rel_path: str,
    cleaned: str,
    has_discovery: bool,
    has_slice: bool,
) -> tuple[list[ToolManifestRecord], set[str]]:
    manifests: list[ToolManifestRecord] = []
    tool_const_names: set[str] = set()

    # 1. Static `const TOOLS = [ ... ]`
    for m in _TS_ARRAY_DECL_RE.finditer(cleaned):
        vname = m.group("name")
        open_br = m.end() - 1
        close_br = _find_balanced_end(cleaned, open_br, "[", "]")
        if close_br == -1:
            continue
        arr_body = cleaned[open_br : close_br + 1]
        if not any(
            k in arr_body for k in ("inputSchema", "input_schema", "parameters", "description", "function")
        ):
            continue
        tnames = tuple(dict.fromkeys(nm.group("name") for nm in _TS_TOOL_NAME_PROP_RE.finditer(arr_body)))
        if not tnames:
            continue
        tool_const_names.add(vname)
        normalized_bytes = len(re.sub(r"\s+", " ", arr_body).strip().encode("utf-8"))
        approx_tokens = max(1, (normalized_bytes + 3) // 4)
        manifests.append(
            ToolManifestRecord(
                rel_path=rel_path,
                line=_line_at(cleaned, m.start()),
                scope_name="*",
                manifest_name=vname,
                language="typescript",
                tool_names=tnames,
                tool_count=len(tnames),
                byte_len=normalized_bytes,
                approx_tokens=approx_tokens,
                has_progressive_discovery=has_discovery or bool(set(tnames) & _TS_DISCOVERY_NAMES),
                has_slice_selector=has_slice,
                is_explicit_slm_slice="SLM" in vname.upper(),
            )
        )

    # 2. `Array.from({ length: N }, ...)` tool schema generators
    for af in _TS_ARRAY_FROM_RE.finditer(cleaned):
        vname = af.group("name")
        count = int(af.group("len"))
        call_open = cleaned.find("(", af.start())
        call_close = _find_balanced_end(cleaned, call_open, "(", ")") if call_open != -1 else -1
        span_src = cleaned[af.start() : (call_close + 1 if call_close != -1 else min(len(cleaned), af.end() + 400))]
        if count <= 0 or count > 500 or not any(
            k in span_src for k in ("inputSchema", "input_schema", "parameters", "description")
        ):
            continue
        tool_const_names.add(vname)
        synth = [
            {
                "name": f"generated_tool_{idx}",
                "description": "Generated tool schema entry",
                "inputSchema": {"type": "object", "properties": {"query": {"type": "string"}}},
            }
            for idx in range(count)
        ]
        blen, atoks = estimate_schema_budget(synth)
        manifests.append(
            ToolManifestRecord(
                rel_path=rel_path,
                line=_line_at(cleaned, af.start()),
                scope_name="*",
                manifest_name=vname,
                language="typescript",
                tool_names=tuple(f"generated_tool_{idx}" for idx in range(count)),
                tool_count=count,
                byte_len=blen,
                approx_tokens=atoks,
                has_progressive_discovery=has_discovery,
                has_slice_selector=has_slice,
                is_explicit_slm_slice="SLM" in vname.upper(),
            )
        )

    # 3. `server.tool("...", ...)` / `mcp.tool("...", ...)` registrations
    srv_matches = list(_TS_SERVER_TOOL_RE.finditer(cleaned))
    if srv_matches:
        tnames = tuple(dict.fromkeys(sm.group("name") for sm in srv_matches))
        synth_srv = [
            {
                "name": nm,
                "description": "Registered MCP tool",
                "inputSchema": {"type": "object", "properties": {"input": {"type": "string"}}},
            }
            for nm in tnames
        ]
        blen, atoks = estimate_schema_budget(synth_srv)
        manifests.append(
            ToolManifestRecord(
                rel_path=rel_path,
                line=_line_at(cleaned, srv_matches[0].start()),
                scope_name="server.tool",
                manifest_name="server.tool",
                language="typescript",
                tool_names=tnames,
                tool_count=len(tnames),
                byte_len=blen,
                approx_tokens=atoks,
                has_progressive_discovery=has_discovery or bool(set(tnames) & _TS_DISCOVERY_NAMES),
                has_slice_selector=has_slice,
            )
        )

    return manifests, tool_const_names


def _inspect_ts_loop_span(
    rel_path: str,
    scope_name: str,
    scope_src: str,
    loop_kw: str,
    cond_src: str,
    body_src: str,
    line: int,
    int_env: dict[str, int],
) -> AgentLoopRecord | None:
    has_llm = bool(
        re.search(
            r"\b(?:completions\.create|messages\.create|responses\.create|complete|completeTurn|generate|callModel|callLlm|invokeModel)\s*\(",
            body_src,
        )
        or (RAW_COMPLETION_PATH_RE.search(body_src) and re.search(r"\b(?:fetch|axios)\b", body_src))
    )
    has_tool = bool(
        re.search(
            r"\b(?:tool_calls|toolCalls|tool_use|executeTool|dispatchTool|runTool|callTool|execute_tool|dispatch_tool|run_tool)\b|role\s*:\s*['\"]tool['\"]",
            body_src,
        )
    )
    if not (has_llm and has_tool):
        return None

    is_unbounded = False
    max_rounds: int | None = None
    cond_clean = cond_src.strip()
    if loop_kw == "while" and cond_clean in ("true", "1"):
        m_guard = re.search(
            r"if\s*\(\s*[A-Za-z_$][\w$]*\s*(?:>=|>|===)\s*(?P<bound>\d+|[A-Za-z_$][\w$]*)\s*\)\s*\{?\s*(?:break|return|throw)\b",
            body_src,
        )
        if m_guard:
            b_tok = m_guard.group("bound")
            max_rounds = int(b_tok) if b_tok.isdigit() else int_env.get(b_tok)
        else:
            is_unbounded = True
    else:
        m_lt = re.search(r"(?:<=|<)\s*(?P<bound>\d+|[A-Za-z_$][\w$]*)", cond_clean)
        if m_lt:
            b_tok = m_lt.group("bound")
            max_rounds = int(b_tok) if b_tok.isdigit() else int_env.get(b_tok)

    has_timeout = bool(
        re.search(r"\b(?:timeout|timeoutMs|AbortSignal\.timeout|AbortController|signal\s*:)\b", body_src)
    )
    has_dup_brake = bool(
        re.search(
            r"\b(?:seenCalls|seen_calls|callHistory|call_history|lastCall|prevCall|previousCall|callSignature|callSig|duplicateCalls|JSON\.stringify)\b",
            body_src,
        )
    )
    scope_verified = bool(
        re.search(
            r"\b(?:verify\w*|validate\w*|check\w*|emitReceipt\w*|buildReceipt\w*|receipt\w*|runTests|tsc|pytest)\s*\(",
            scope_src,
        )
    )
    premature: list[str] = []
    if re.search(
        r"if\s*\(\s*(?:filesModified|files_modified|edited|mutated|wroteFile|changesMade)\s*\)\s*\{?\s*(?:return|break)\b",
        body_src,
    ) and not scope_verified:
        premature.append("mutation flag stop without verification gate")
    if re.search(
        r"(?:\.includes\(\s*['\"]DONE['\"]\s*\)|===\s*['\"]DONE['\"])\s*\)?\s*\{?\s*(?:return|break)\b",
        body_src,
    ) and not scope_verified:
        premature.append("prose `'DONE'` check without verification gate")

    return AgentLoopRecord(
        rel_path=rel_path,
        line=line,
        scope_name=scope_name,
        language="typescript",
        is_unbounded=is_unbounded,
        max_rounds=max_rounds,
        has_step_timeout=has_timeout,
        has_duplicate_brake=has_dup_brake,
        premature_stop_reasons=tuple(premature),
        has_verification_gate=scope_verified,
    )


def inspect_ts_source(rel_path: str, source_text: str) -> HarnessInspectionBundle:
    """Statically inspect a single `.ts` / `.tsx` / `.js` / `.mjs` file."""
    bundle = HarnessInspectionBundle()
    cleaned = blank_ts_comments(source_text)

    stem = PurePosixPath(rel_path).name
    if CANONICAL_CLIENT_STEM_RE.search(stem):
        bundle.canonical_clients.append(
            CanonicalClientRecord(rel_path, 1, PurePosixPath(rel_path).stem, "typescript")
        )
    else:
        cls_m = re.search(
            r"\bclass\s+(?P<cls>[A-Za-z_$][\w$]*(?:LLMClient|ModelClient|LLMAdapter|ModelAdapter|ChatAdapter))\b",
            cleaned,
        )
        if cls_m:
            bundle.canonical_clients.append(
                CanonicalClientRecord(
                    rel_path, _line_at(cleaned, cls_m.start()), cls_m.group("cls"), "typescript"
                )
            )

    has_discovery = any(
        re.search(rf"\b{re.escape(nm)}\b", cleaned) for nm in _TS_DISCOVERY_NAMES
    )
    has_slice = any(tok in cleaned for tok in _TS_SLICE_TOKENS)

    manifests, tool_consts = _extract_ts_tool_manifests(
        rel_path, cleaned, has_discovery, has_slice
    )
    bundle.manifests.extend(manifests)

    mod_strs: dict[str, str] = {
        m.group("name"): m.group("rhs") for m in _TS_CONST_STR_RE.finditer(cleaned)
    }
    mod_ints: dict[str, int] = {
        m.group("name"): int(m.group("val")) for m in _TS_CONST_INT_RE.finditer(cleaned)
    }

    # Partition into named function scopes + remaining top-level spans
    fn_spans: list[tuple[str, int, int, int]] = []
    for fm in _TS_FN_DECL_RE.finditer(cleaned):
        fname = fm.group("fn") or fm.group("arrow") or "*"
        open_brace = fm.end() - 1
        close_brace = _find_balanced_end(cleaned, open_brace, "{", "}")
        if close_brace == -1:
            close_brace = len(cleaned) - 1
        if any(s <= fm.start() < e for _, _, s, e in fn_spans):
            continue
        fn_spans.append((fname, _line_at(cleaned, fm.start()), fm.start(), close_brace + 1))

    def _in_named_fn(offset: int) -> bool:
        return any(s <= offset < e for _, _, s, e in fn_spans)

    scopes_to_scan: list[tuple[str, int, str, int]] = [
        (fn_n, fn_ln, cleaned[s:e], s) for fn_n, fn_ln, s, e in fn_spans
    ]
    # Build masked top-level text so module-level statements outside functions are scanned once
    top_chars = list(cleaned)
    for _, _, s, e in fn_spans:
        for idx in range(s, min(e, len(top_chars))):
            if top_chars[idx] != "\n":
                top_chars[idx] = " "
    _ = _in_named_fn
    scopes_to_scan.insert(0, ("*", 1, "".join(top_chars), 0))

    file_has_llm_ctx = bool(bundle.manifests or _TS_LLM_CONTEXT_RE.search(cleaned))

    for sc_name, sc_ln, sc_text, base_off in scopes_to_scan:
        loc_strs = {
            **mod_strs,
            **{m.group("name"): m.group("rhs") for m in _TS_CONST_STR_RE.finditer(sc_text)},
        }
        loc_ints = {
            **mod_ints,
            **{m.group("name"): int(m.group("val")) for m in _TS_CONST_INT_RE.finditer(sc_text)},
        }

        role_objs = list(_TS_ROLE_OBJ_RE.finditer(sc_text))
        has_messages_ctx = bool(
            file_has_llm_ctx
            or re.search(r"\b(?:messages|chatMessages|promptMessages)\s*[:=]\s*\[", sc_text)
            or any(ro.group("role") == "user" for ro in role_objs)
        )
        tail_user_ctx = any(
            ro.group("role") == "user"
            and (
                "[TURN CONTEXT]" in ro.group("content")
                or bool(_ts_volatile_reasons(ro.group("content"), loc_strs))
            )
            for ro in role_objs
        )
        seen_lines: set[int] = set()
        if has_messages_ctx:
            for ro in role_objs:
                if ro.group("role") not in ("system", "developer"):
                    continue
                abs_ln = _line_at(cleaned, base_off + ro.start())
                if abs_ln in seen_lines:
                    continue
                seen_lines.add(abs_ln)
                reasons = _ts_volatile_reasons(ro.group("content"), loc_strs)
                bundle.prompts.append(
                    PromptSurface(
                        rel_path=rel_path,
                        line=abs_ln,
                        scope_name=sc_name,
                        language="typescript",
                        is_volatile=bool(reasons),
                        volatile_reasons=tuple(reasons),
                        has_tail_turn_context=tail_user_ctx,
                        mechanism="messages[0]",
                    )
                )

        for sp in _TS_SYS_PROP_RE.finditer(sc_text):
            if sp.group("prop") == "system" and not has_messages_ctx:
                continue
            abs_ln = _line_at(cleaned, base_off + sp.start("prop"))
            if abs_ln in seen_lines:
                continue
            seen_lines.add(abs_ln)
            reasons = _ts_volatile_reasons(sp.group("val"), loc_strs)
            mech = "mcp_sampling" if sp.group("prop") == "systemPrompt" else "anthropic_system"
            bundle.prompts.append(
                PromptSurface(
                    rel_path=rel_path,
                    line=abs_ln,
                    scope_name=sc_name,
                    language="typescript",
                    is_volatile=bool(reasons),
                    volatile_reasons=tuple(reasons),
                    has_tail_turn_context=tail_user_ctx,
                    mechanism=mech,
                )
            )

        # Raw HTTP completion calls (`AGENT-003`)
        for rf in _TS_RAW_FETCH_RE.finditer(sc_text):
            raw_arg = rf.group("arg").strip()
            resolved_url = loc_strs.get(raw_arg, raw_arg)
            if RAW_COMPLETION_PATH_RE.search(resolved_url):
                bundle.raw_http_calls.append(
                    RawHttpBypassRecord(
                        rel_path=rel_path,
                        line=_line_at(cleaned, base_off + rf.start()),
                        scope_name=sc_name,
                        language="typescript",
                        callee=rf.group("callee"),
                        endpoint=resolved_url.strip("`'\""),
                    )
                )

        # Loops (`AGENT-003`)
        for lm in _TS_LOOP_HEAD_RE.finditer(sc_text):
            open_b = lm.end() - 1
            close_b = _find_balanced_end(sc_text, open_b, "{", "}")
            if close_b == -1:
                continue
            body_s = sc_text[open_b : close_b + 1]
            loop_rec = _inspect_ts_loop_span(
                rel_path=rel_path,
                scope_name=sc_name,
                scope_src=sc_text,
                loop_kw=lm.group("kw"),
                cond_src=lm.group("cond"),
                body_src=body_s,
                line=_line_at(cleaned, base_off + lm.start()),
                int_env=loc_ints,
            )
            if loop_rec is not None:
                bundle.loops.append(loop_rec)

        # Registry loads (`AGENT-002`)
        reg_m = _TS_REG_PATH_RE.search(sc_text)
        if reg_m:
            accessed: set[str] = set()
            for key_cand in (
                "enabled",
                "disabled",
                "allowlist",
                "denylist",
                "tools",
                "capabilities",
                "slice",
                "scopes",
            ):
                if re.search(rf"(?:\.\s*{key_cand}\b|\[\s*['\"]{key_cand}['\"]\s*\])", sc_text):
                    accessed.add(key_cand)
            subst_hit = [
                tc for tc in sorted(tool_consts) if re.search(rf"\breturn\s+{re.escape(tc)}\b", sc_text)
            ]
            bundle.registry_loads.append(
                RegistryLoadRecord(
                    rel_path=rel_path,
                    line=_line_at(cleaned, base_off + reg_m.start()),
                    scope_name=sc_name,
                    language="typescript",
                    registry_hint=reg_m.group("path"),
                    accessed_keys=tuple(sorted(accessed)),
                    returns_hardcoded_tools=bool(subst_hit),
                    substituted_symbols=tuple(subst_hit),
                )
            )

        if sc_name != "*":
            for cm in re.finditer(r"\b([A-Za-z_$][\w$]*)\s*\(", sc_text):
                callee_nm = cm.group(1)
                if callee_nm not in {"if", "for", "while", "switch", "catch", "return", sc_name}:
                    bundle.helper_calls.append(
                        HelperCallRecord(
                            rel_path=rel_path,
                            line=_line_at(cleaned, base_off + cm.start()),
                            caller_scope=sc_name,
                            callee_symbol=callee_nm,
                        )
                    )

    return bundle


def inspect_ts_files(repo_root: Path) -> HarnessInspectionBundle:
    """Inspect all contained TypeScript/JavaScript source files under `repo_root`."""
    total = HarnessInspectionBundle()
    ts_files, skipped = iter_safe_repo_files(repo_root, {".ts", ".tsx", ".js", ".mjs"})
    total.skipped_files += skipped
    for fpath, rel_path in ts_files:
        try:
            text = fpath.read_text(encoding="utf-8")
        except (OSError, UnicodeError) as exc:
            total.parse_errors.append(f"{rel_path}: {type(exc).__name__}")
            continue
        total.merge(inspect_ts_source(rel_path, text))
    return total
