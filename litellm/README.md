# AgentX DLP — LiteLLM Guardrail

The **proxy/response-layer** half of AgentX DLP. Where the Claude Code plugin
blocks at the *tool-execution* boundary, this blocks at the *LLM-API* boundary —
scanning the model's **response** (and optionally the **prompt**) and rejecting
the call when it matches the same policy.

```
            ┌──────────────── LiteLLM Proxy ────────────────┐
 client ───►│  pre_call hook        post_call hook            │───► provider
 (Cursor/   │  (scan PROMPT)        (scan RESPONSE)           │     (Anthropic/
  Claude    │   block secrets/      block: share-suggestions, │      OpenAI/…)
  Code)     │   PII leaving         secrets, PII, ext dests    │
            └────────────────────────────────────────────────┘
```

## What it catches that the hook can't
- The model **suggesting** a public share in prose (e.g. "paste it at a public
  gist / pastebin link") — blocked before it reaches the user. *(The original
  share-suggestion threat.)*
- Any model routed through the proxy (GPT, Gemini, etc.), centrally — not just Claude Code.
- Secrets / CUSTOMER DATA / RESTRICTED content in the **prompt** never reaching the vendor.

## What it can't do (use the plugin for this)
- It only sees traffic **routed through LiteLLM**. Direct provider calls bypass it.
- It can't see local tool execution (a publish/push command actually running) — that's the hook's job.

The two are complementary; deploy both behind the same policy (see `../POLICY.md`).

## Files
| File | Purpose |
|------|---------|
| `dlp_patterns.py`          | Python port of the detectors (secrets, PII, tiers, suggestions, allowlist) |
| `agentx_dlp_guardrail.py` | `CustomGuardrail` — pre_call (prompt) + post_call (response) hooks |
| `config.yaml`              | LiteLLM proxy config wiring the guardrail |
| `test_patterns.py`         | Standalone unit test (no litellm needed): `python3 test_patterns.py` |

## Run
```
pip install 'litellm[proxy]'
export ANTHROPIC_API_KEY=...            # + any other provider keys
export PYTHONPATH="$PWD"                 # so the guardrail module imports
litellm --config config.yaml            # serves on http://localhost:4000
```
Point your client's base URL at `http://localhost:4000`. Responses that violate
policy return HTTP 400 with a `Blocked by AgentX DLP policy` detail.

## Modes
- `mode: "block"` (default) — reject the call.
- `mode: "redact"` — let the response through but replace offending spans with `[REDACTED-DLP]`.
- `scan_prompt` / `scan_response` — toggle each layer per guardrail entry.

## Notes
- **Streaming:** for streamed responses, also implement
  `async_post_call_streaming_iterator_hook` to buffer + scan chunks (stubbed in the
  guardrail with a comment).
- **Policy parity:** `dlp_patterns.py` mirrors the JS detectors in `../dlp/`. Keep
  them in sync, or (future) generate both from one source.
- **Rollout:** start with `mode: "redact"` or response-scan-only + log, measure
  false positives, then switch to `block` — same shadow-to-enforce path as the hook.
```
