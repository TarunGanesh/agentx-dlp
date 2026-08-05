"""
AgentX DLP — LiteLLM CustomGuardrail

Enforces the same policy as the Claude Code plugin, but at the LLM-proxy boundary:

  • async_post_call_success_hook  → scans the MODEL RESPONSE and BLOCKS when it
        suggests a public/unapproved share (gist/pastebin/personal cloud), echoes
        secrets/PII, or emits a tool_call that would exfiltrate. This is the
        "block when we get the response back" behaviour.

  • async_pre_call_hook           → scans the OUTBOUND PROMPT and blocks secrets /
        CUSTOMER DATA / RESTRICTED content from being sent to the model vendor at
        all (the bigger prompt-layer DLP win; optional, controlled by `scan_prompt`).

Modes:
  • block  (default) — raise and reject the call
  • redact           — replace matched spans in the response with [REDACTED-DLP]

Register in config.yaml under `guardrails:` (see litellm/config.yaml).

Docs: https://docs.litellm.ai/docs/proxy/guardrails/custom_guardrail
"""

from typing import Any, Optional, Literal

from litellm.integrations.custom_guardrail import CustomGuardrail
from litellm.proxy._types import UserAPIKeyAuth
from litellm.caching.caching import DualCache
from litellm._logging import verbose_proxy_logger

try:
    # raising this returns a clean 400 to the caller
    from fastapi import HTTPException
except Exception:  # pragma: no cover
    HTTPException = RuntimeError  # fallback if fastapi import path changes

from dlp_patterns import (
    scan_content,
    scan_suggestions,
    scan_external_destinations,
    is_fail_closed_tier,
    tier_label,
    describe,
    TIER_RANK,
)


class AgentXDLPGuardrail(CustomGuardrail):
    def __init__(
        self,
        mode: Literal["block", "redact"] = "block",
        scan_prompt: bool = True,
        scan_response: bool = True,
        **kwargs,
    ):
        self.mode = mode
        self.scan_prompt = scan_prompt
        self.scan_response = scan_response
        super().__init__(**kwargs)

    # ── PROMPT layer (outbound to the model vendor) ─────────────────────────
    async def async_pre_call_hook(
        self,
        user_api_key_dict: UserAPIKeyAuth,
        cache: DualCache,
        data: dict,
        call_type: str,
    ) -> Optional[dict]:
        if not self.scan_prompt:
            return data

        text = self._messages_text(data.get("messages", []))
        tier, findings = scan_content(text)

        # Block only top-tier data from leaving in the prompt. Secrets/CUSTOMER
        # DATA/RESTRICTED should never be shipped to an external model vendor.
        if is_fail_closed_tier(tier) or tier == "restricted":
            self._violation(
                where="prompt",
                reason=f"{tier_label(tier)} content in prompt to external model",
                detail=describe(findings),
            )
        return data

    # ── RESPONSE layer (what the model sent back) ───────────────────────────
    async def async_post_call_success_hook(
        self,
        data: dict,
        user_api_key_dict: UserAPIKeyAuth,
        response: Any,
    ) -> Any:
        if not self.scan_response:
            return response

        text = self._response_text(response)
        violations = []

        # 1. Model suggesting a public/unapproved share (the gist case)
        suggestions = scan_suggestions(text)
        if suggestions:
            violations.append("suggests public sharing: " +
                              ", ".join(s["match"] for s in suggestions))

        # 2. Unapproved external destinations named in the response
        dests = scan_external_destinations(text)
        if dests:
            violations.append("unapproved destination(s): " + ", ".join(dests))

        # 3. Secrets / PII / classification content echoed in the response
        tier, findings = scan_content(text)
        if tier != "none":
            violations.append(f"{tier_label(tier)} content: {describe(findings)}")

        # 4. Tool calls in the response that would exfiltrate
        tool_text = self._response_tool_calls_text(response)
        if tool_text:
            t_dests = scan_external_destinations(tool_text)
            t_sugg = scan_suggestions(tool_text)
            if t_dests or t_sugg:
                violations.append("tool_call targets external destination")

        if not violations:
            return response

        if self.mode == "redact":
            return self._redact_response(response, suggestions, dests, findings)

        # block mode
        self._violation(
            where="response",
            reason="model response contains data-exfiltration content",
            detail="; ".join(violations),
        )

    # ── streaming note ──────────────────────────────────────────────────────
    # For streamed responses, override async_post_call_streaming_iterator_hook
    # to buffer + scan chunks. Omitted here for brevity; recommend running the
    # proxy with stream scanning enabled for full coverage.

    # ── helpers ─────────────────────────────────────────────────────────────
    def _violation(self, where: str, reason: str, detail: str):
        verbose_proxy_logger.warning(
            "[AgentX DLP] BLOCKED (%s): %s | %s", where, reason, detail
        )
        raise HTTPException(
            status_code=400,
            detail={
                "error": "Blocked by AgentX DLP policy",
                "where": where,
                "reason": reason,
                "detail": detail,
                "contact": "#security",
            },
        )

    @staticmethod
    def _messages_text(messages) -> str:
        out = []
        for m in messages or []:
            c = m.get("content")
            if isinstance(c, str):
                out.append(c)
            elif isinstance(c, list):
                out.extend(part.get("text", "") for part in c if isinstance(part, dict))
        return "\n".join(out)

    @staticmethod
    def _response_text(response) -> str:
        try:
            choices = response.choices if hasattr(response, "choices") else response.get("choices", [])
            out = []
            for ch in choices:
                msg = getattr(ch, "message", None) or (ch.get("message") if isinstance(ch, dict) else None)
                if not msg:
                    continue
                content = getattr(msg, "content", None) or (msg.get("content") if isinstance(msg, dict) else None)
                if isinstance(content, str):
                    out.append(content)
            return "\n".join(out)
        except Exception:
            return ""

    @staticmethod
    def _response_tool_calls_text(response) -> str:
        try:
            choices = response.choices if hasattr(response, "choices") else response.get("choices", [])
            out = []
            for ch in choices:
                msg = getattr(ch, "message", None) or (ch.get("message") if isinstance(ch, dict) else None)
                tcs = getattr(msg, "tool_calls", None) or (msg.get("tool_calls") if isinstance(msg, dict) else None)
                for tc in tcs or []:
                    fn = getattr(tc, "function", None) or (tc.get("function") if isinstance(tc, dict) else None)
                    if fn:
                        args = getattr(fn, "arguments", None) or (fn.get("arguments") if isinstance(fn, dict) else "")
                        out.append(str(args))
            return "\n".join(out)
        except Exception:
            return ""

    def _redact_response(self, response, suggestions, dests, findings):
        """Replace offending spans with a marker instead of blocking."""
        try:
            for ch in response.choices:
                msg = ch.message
                if getattr(msg, "content", None):
                    txt = msg.content
                    for s in suggestions:
                        txt = txt.replace(s["match"], "[REDACTED-DLP]")
                    for d in dests:
                        txt = txt.replace(d, "[REDACTED-DLP]")
                    msg.content = txt
        except Exception:
            pass
        return response
