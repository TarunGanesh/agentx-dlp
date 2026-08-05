# Contributing

Audience: engineers and security engineers changing DLP **policy** or **code**.

`POLICY.md` is the rule source of truth — what gets blocked, why, and where each rule
came from ([Policy] / [Threat] / [Allowlist] / [Engine]). Read it before you touch a
detector. If a code change alters enforcement behaviour, `POLICY.md` must change in the
same commit.

---

## 1. Repo layout

| Path | What lives here |
|------|-----------------|
| `dlp/` | Claude Code plugin: the `PreToolUse` hook and all Layer 1 detectors (Node, no runtime deps). |
| `src/` | VS Code / Cursor extension source (TypeScript → `out/`). |
| `litellm/` | Python LiteLLM proxy guardrail — prompt/response scanning at the LLM-API boundary. |
| `hooks/` | `hooks.json` — the plugin's `PreToolUse` registration (matcher `.*`, `timeout: 15`). |
| `.claude-plugin/` | `plugin.json` + `marketplace.json` — plugin identity and the `agentx-local` marketplace entry. |
| `test/` | Test runner and fixtures (`bash test/run-tests.sh`, `test/cases.jsonl`). |
| `.github/workflows/` | `ci.yml` — the three CI jobs (`hook`, `python`, `manifests`). |
| `out/` | `tsc` build output. Generated, git-ignored. |

Root files: `POLICY.md` (rules), `README.md` (front door), `ARCHITECTURE.md` (where
enforcement sits), this file, `LICENSE`, and `package.json` / `tsconfig.json`
(extension build).

### Module map (`dlp/`)

| File | Role |
|------|------|
| `exfil-hook.js` | Router / orchestrator. Reads the hook event, dispatches Bash / Write+Edit / everything-else, formats blocks, writes advisories. |
| `semantic-analyzer.js` | Layer 1 structural data-flow (`SOURCE → TRANSFORM → DESTINATION`) + obfuscation/pipeline detection. |
| `content-scanner.js` | "What is this data?" — secrets, PII, classification markers, tier ranking. |
| `allowlist.js` | Approved destinations: hosts, GitHub orgs, bucket prefixes. (Also declares `APPROVED_NPM_REGISTRIES`, which is dead — see §3.1.) |
| `patterns.js` | Sensitive file types/names (`isSensitiveFile`). Also holds two legacy lists the hook does **not** consult — see §4. |
| `mcp-handler.js` | Generic + MCP tool DLP: tool read/write classification, primary-destination extractors, recursive input inspection. |
| `intent-classifier.js` | Layer 2 Haiku intent check. Lazy SDK load, 3 s timeout, **fails open**. |
| `bench-layer2.js` | Layer 2 latency benchmark. Not part of CI. |
| `setup.sh` | **Legacy** standalone installer, superseded by the plugin. See §6. |

---

## 2. Local setup

```
npm install          # devDeps (typescript, eslint) + @anthropic-ai/sdk for Layer 2
npx tsc -p ./        # builds src/*.ts → out/
```

| Surface | Needs |
|---------|-------|
| `dlp/` (Layer 1) | Node ≥ 18 only. No install step, no runtime dependencies. |
| `dlp/` Layer 2 | `@anthropic-ai/sdk` + credentials (`ANTHROPIC_API_KEY`, `ANTHROPIC_AUTH_TOKEN`, or `~/.claude/.credentials.json`). Absent → Layer 2 is skipped, Layer 1 still enforces. |
| `src/` extension | `npm install`, then `npx tsc -p ./`. |
| `litellm/` detector test | **Nothing.** `dlp_patterns.py` is pure stdlib; `test_patterns.py` imports it directly. |
| `litellm/` proxy | `litellm` is required only to actually *run* the proxy. **Do not install it to test** — nothing in CI may import or require it. |

The `claude` CLI must never be a CI dependency either.

---

## 3. How to add or change a policy rule

Every recipe below ends the same way: **update `POLICY.md`, and add both a BLOCK case
and an ALLOW case** (§5).

### 3.1 Approved destination — host, GitHub org, or bucket prefix

Primary file: **`dlp/allowlist.js`**

| Change | Constant |
|--------|----------|
| Hostname / domain suffix | `APPROVED_HOSTS` (leading `.` = suffix match, e.g. `.your-company.com`) |
| GitHub org | `APPROVED_GITHUB_ORGS` |
| S3 / GCS bucket prefix | `APPROVED_BUCKET_PREFIXES` |

> **`APPROVED_NPM_REGISTRIES` is dead — do not edit it.** It is declared in
> `dlp/allowlist.js` but is neither exported nor read by anything. The live npm
> registry decision is a substring test inside `dlp/semantic-analyzer.js`
> `analyzeFlow()`: `const isApprovedRegistry = registry.includes('your-company.com')`,
> where `registry` is whatever followed `--registry`. To change which registries
> are acceptable, change that branch (§3.4), not the constant.

Then update every mirror. Adding a destination is the **highest-blast-radius change in
the repo**: it does not map to one tier, it removes the block for *all* tiers —
CONFIDENTIAL, CUSTOMER DATA and RESTRICTED all become free to leave to that host.
Treat it as a security review, not a config tweak.

| Mirror | What to edit |
|--------|--------------|
| `litellm/dlp_patterns.py` | `APPROVED_HOST_SUFFIXES`, `APPROVED_GITHUB_ORGS` |
| `src/intentAnalyzer.ts` | `APPROVED_HOSTS`, `APPROVED_GITHUB_ORGS` |
| `dlp/mcp-handler.js` | `APPROVED_GITHUB_ORGS` (a genuine duplicate of `allowlist.js`'s), plus `COMPANY_EMAIL_DOMAINS` and `PASTE_SERVICE_HOSTS`, which exist **only** here. It *does* `require('./allowlist.js')` — but only for `isApprovedHost` (host approval is shared) and `classifyDestinations` (imported, currently unused). The three constants above are not imported. |
| `dlp/intent-classifier.js` | `SYSTEM_PROMPT` lists the approved destinations in prose; a stale list makes Layer 2 contradict Layer 1 |
| `POLICY.md` §4 | The approved-destinations table |

Approved **email** recipients are a separate axis: `COMPANY_EMAIL_DOMAINS` in
`dlp/mcp-handler.js` (primary-destination path) *and* the inline `your-company.com` check in
`inspectString()`.

### 3.2 Sensitive file type

File: **`dlp/patterns.js`**

- Extension → `SENSITIVE_FILE_EXTENSIONS` (a `Set`, values include the leading dot).
- Filename shape → `SENSITIVE_FILE_NAME_PATTERNS` (array of `RegExp`, tested against the
  basename only, lowercased).

**Tier:** a sensitive-file hit assigns **no tier**. It is a *severity* signal, and it
does two distinct things in `analyzeFlow()`:

1. When the destination *was* resolved and is unapproved, `sensitiveFiles.length > 0`
   lifts `risk: 'medium'` to `risk: 'high'` — both verdicts already carry
   `is_exfil: true`, so what changes is only the severity, and with it the fact that
   the hook blocks in Layer 1 instead of deferring.
2. When the destination could **not** be resolved (a shell variable), it lifts the
   verdict from `none` — a silent allow — to `risk: 'medium', is_exfil: true`. That is
   *not* a Layer 1 block: medium escalates to Layer 2, which fails open when the SDK
   or credentials are missing. A sensitive filename alone therefore buys an intent
   check, not a block.

Tiers come only from `content-scanner.js`.

Mirrors — there are **two** TypeScript copies, and they disagree with each other:

| Copy | Constants | Consumed by |
|------|-----------|-------------|
| `src/intentAnalyzer.ts` | `SENSITIVE_EXTENSIONS` / `SENSITIVE_NAME_PATTERNS` | `IntentAnalyzer.isSensitivePath()` — the Layer 1 port |
| `src/dlpEngine.ts` | `SENSITIVE_EXTENSIONS` / `SENSITIVE_NAME_PATTERNS` (same names, different contents) | `DLPEngine.isSensitiveFile()`, which is what `ResponseScanner.trackOpenFiles()` calls |

All three lists have already drifted (see §4). There is no Python mirror — the LiteLLM
guardrail scans text, not file paths.

### 3.3 Secret or PII detector

File: **`dlp/content-scanner.js`**

Three lists, three shapes:

```js
// SECRET_DETECTORS
{ id: 'databricks-token', tier: 'restricted', label: 'Databricks token', pattern: /\bdapi[0-9a-f]{32}\b/ }

// PII_DETECTORS — same shape plus an explicit luhn flag
{ id: 'credit-card', tier: 'customer', label: 'Credit card number', pattern: /…/, luhn: true }

// CLASSIFICATION_MARKERS — no id
{ tier: 'restricted', pattern: /\bdo\s+not\s+share\b/i, label: 'Do Not Share marker' }
```

Field contract:

| Field | Rule |
|-------|------|
| `id` | kebab-case, unique. Not shown to users; used in tests and logs. |
| `tier` | One of `public` \| `confidential` \| `customer` \| `restricted`. Ranked by `TIER_RANK`; a scan's tier is the **max** across all findings. |
| `label` | Human-readable; appears verbatim in the block message via `describeContent()`. |
| `pattern` | A `RegExp`. Anchor with `\b` and bound every quantifier. Do **not** use the `g` flag — these are reused across calls and `lastIndex` will make `.test()` non-deterministic. |
| `luhn` | PII only. `true` → `scanText()` runs `luhnValid(match[0])` and **drops the finding** if it fails. `luhnValid` also requires ≥ 13 digits. Use it for any card-like numeric to cut false positives. |

**Tier mapping, per `POLICY.md` §3.4:**

| Detector kind | Tier | Effect when leaving to an unapproved destination |
|---|---|---|
| Cloud/API/VCS credentials, private keys | `restricted` | Hard block, **fail-closed** (`isFailClosedTier`), cannot be overridden inline |
| SSN, credit card, IBAN, passport | `customer` | Hard block, **fail-closed** |
| JWT, hardcoded `password=…` | `confidential` | Hard block (not fail-closed) |
| `Classification: Public` marker | `public` | Allowed |

Python mirror: **`litellm/dlp_patterns.py`**. Same detectors, tuple form — note the
positional layouts differ from each other:

```python
SECRET_DETECTORS       = [(id, tier, label, compiled_pattern), …]
PII_DETECTORS          = [(id, tier, label, compiled_pattern, luhn_bool), …]
CLASSIFICATION_MARKERS = [(tier, compiled_pattern, label), …]   # label LAST here
```

Getting the tuple order wrong fails silently — the label ends up in the tier slot and
`TIER_RANK.get()` returns `0`, so the detector matches and blocks nothing. Always run
`python3 test_patterns.py` after editing.

### 3.4 A new outbound CLI

File: **`dlp/semantic-analyzer.js`**

1. `ALWAYS_OUTBOUND` — add the invocation if it is unconditionally an upload
   (`gh gist create`, `npm publish`, `docker push`, …). If direction depends on argument
   order (`scp`, `rsync`) or flags (`curl`, `wget`), add a branch to
   `isOutboundTransfer()` instead.
2. `analyzeFlow()` — if the destination is **not** a URL in the command text, add an
   explicit branch. There are five today, checked in this order: `gh gist create`,
   `gh repo create`, `git push`, `docker push`, `npm publish` — because
   `classifyDestinations()` cannot see an implicit default registry or a public-by-default
   flag. Return `{risk, is_exfil, reason, unapprovedDests, sensitiveFiles, technique}`.
3. `detectDataSource()` — add the tool's file/stdin flags so a payload is recognised.
4. `buildTechnique()` — add a label so the block message names the channel.

Also update:

| File | Why |
|------|-----|
| `dlp/mcp-handler.js` `COMMAND_HEAD` | Decides what counts as command-shaped text inside an MCP tool input. A CLI missing here is never analysed when embedded in a tool argument. |
| `dlp/mcp-handler.js` `MENTIONS_TOOLING` | Advisory-only prose mentions. |
| `dlp/exfil-hook.js` `handleFileWrite()` | The per-line prefilter `\b(?:curl\|wget\|scp\|rsync\|gh\|git\|nc\|aws\|gsutil\|docker\|npm)\b` gates the Write/Edit advisory. A new CLI not listed there produces no advisory. |
| `src/intentAnalyzer.ts` | `isOutbound()` and `describeTechnique()`. |
| `dlp/intent-classifier.js` `SYSTEM_PROMPT` | So Layer 2 recognises the channel. |

**Tier:** an outbound CLI carries no tier of its own. It supplies the *direction* half of
the rule; the tier comes from `content-scanner.js` and the block decision is
`outbound AND destination-not-approved`. A public-by-default publish target
(Docker Hub, `registry.npmjs.org`, public gist) is blocked on destination alone,
independent of content — that is `POLICY.md` §3.2.

> **Warning — pipeline and obfuscation patterns.**
> Any new pattern in `OBFUSCATION_PATTERNS` (or anything joining two pipeline stages)
> **must be same-line and length-bounded**. Use the existing
> `const GAP = '[^\\n]{0,200}?'` between stages. Never write an unbounded cross-line
> matcher (`[\s\S]*?`, `.*` with `s`, or an unbounded negative lookahead). Backslash
> line-continuations are already handled — `normalizeCommand()` collapses them before
> matching, so a genuinely multi-line command still reads as one logical line. See §7
> for the bug this rule exists to prevent.

### 3.5 A new MCP tool whose primary parameter IS the destination

File: **`dlp/mcp-handler.js`** → `PRIMARY_DEST_EXTRACTORS`

Use this only when one specific parameter *is* the destination (a GitHub `owner`, an
email `to`, a browser `url`) — not merely a field that might contain a URL. Those are
already covered by the recursive `inspectInput()` walk.

```js
{ pattern: /^(?:navigate|file_upload|upload_image)$/,
  extract: inp => ({ kind: 'url', value: inp.url ?? inp.target_url }) },
```

Contract:

- `pattern` is matched against the **last `__` segment** of the tool name
  (`mcp__server__create_draft` → `create_draft`). Anchor it `^…$`.
- `extract` returns `{ kind, value }`. Supported `kind` values are `github_org`,
  `emails` (array), and `url`. Anything else falls through `checkPrimaryDestination()`'s
  `switch` and returns `null` — i.e. **silently allows**. A new kind needs a new `case`.
- `github_org` also accepts `forced: true`, meaning "no org and not private" → treated as
  a personal/public account.

Two gotchas:

1. `classifyTool()` runs **first** and `READ_PATTERNS` take precedence over
   `WRITE_PATTERNS`. A tool is `read` — and returns `allow` before the extractor is ever
   reached — if its last `__` segment contains `get`, `list`, `search`, `read`, `query`,
   `fetch`, `find`, `describe` or `inspect` as an **underscore-delimited token**
   (`(?:^|_)…(?:_|$)`, so `get_page` and `page_get` match but `getter` does not), or ends
   in `_grouped`, `_status`, `_metadata` or `_count`. It is also `read` if the full tool
   name is in `READ_ONLY_TOOL_WHITELIST` (`WebFetch`, `Read`, `Glob`, `Grep`, …), which is
   checked before any pattern. Adding to `WRITE_PATTERNS` does **not** override any of
   this — the read check wins — so such a tool needs the read match removed or the name
   changed.
2. Extractors are evaluated in array order, first match wins.

**Tier:** an unapproved primary destination is sufficient to block **on its own**,
regardless of content tier — this is the high-confidence path. The content tier only
escalates the message: `failClosed` is set when `inspectInput()` finds `customer` or
`restricted` content in the same call.

---

## 4. Detector parity — known debt

**The same policy is implemented three times.** This is deliberate (three enforcement
surfaces, three languages, no shared runtime) and it is **known debt**. The long-term fix
is to generate all three from one source; until then parity is a manual checklist.

| Concern | `dlp/*.js` (hook) | `src/intentAnalyzer.ts` (extension) | `litellm/dlp_patterns.py` (proxy) |
|---|---|---|---|
| Approved hosts | `allowlist.js` `APPROVED_HOSTS` | `APPROVED_HOSTS` | `APPROVED_HOST_SUFFIXES` |
| Approved GitHub orgs | `allowlist.js` + `mcp-handler.js` (local copy) | `APPROVED_GITHUB_ORGS` | `APPROVED_GITHUB_ORGS` |
| Sensitive file types | `patterns.js` | `SENSITIVE_EXTENSIONS` / `SENSITIVE_NAME_PATTERNS` — **twice**, in `intentAnalyzer.ts` *and* `dlpEngine.ts` | — (no file-path scanning) |
| Secrets / PII / markers | `content-scanner.js` | — (no content scanning) | `SECRET_DETECTORS` / `PII_DETECTORS` / `CLASSIFICATION_MARKERS` |
| Tier ranking | `content-scanner.js` `TIER_RANK` | — | `TIER_RANK` |
| Outbound direction | `semantic-analyzer.js` `isOutboundTransfer()` | `isOutbound()` | — (no command analysis) |
| Obfuscation pipelines | `semantic-analyzer.js` `OBFUSCATION_PATTERNS` | `OBFUSCATION_PATTERNS` | — |
| Share-suggestion prose | `patterns.js` `EXFIL_SUGGESTION_PATTERNS` (**unused by the hook**) | `src/dlpEngine.ts` `EXFIL_SUGGESTION_PATTERNS` | `SUGGESTION_PATTERNS` |
| Layer 2 prompt copy of the allowlist | `intent-classifier.js` `SYSTEM_PROMPT` | — | — |

### Checklist for any policy change

- [ ] `dlp/` primary file edited (§3 tells you which).
- [ ] `dlp/mcp-handler.js` local constants checked — it imports `isApprovedHost` from the allowlist, but keeps its own org / email-domain / paste-host lists.
- [ ] `dlp/intent-classifier.js` `SYSTEM_PROMPT` checked, so Layer 2 agrees with Layer 1.
- [ ] `src/intentAnalyzer.ts` **and** `src/dlpEngine.ts` updated — `dlpEngine.ts` owns the command/suggestion patterns *and* a second sensitive-file list (§3.2).
- [ ] `litellm/dlp_patterns.py` updated — correct tuple arity and field order.
- [ ] `POLICY.md` updated, with the provenance tag ([Policy] / [Threat] / [Allowlist] / [Engine]).
- [ ] BLOCK case added to `test/`.
- [ ] ALLOW case added to `test/` proving no over-block.
- [ ] `python3 test_patterns.py` added case, if the change touched detectors.
- [ ] `npx tsc -p ./` clean.
- [ ] All three surfaces reported in the PR description, even the ones you decided not to change — with the reason.

### Live drift to be aware of

These are real divergences in the tree today. Do not "fix" one surface without checking
whether you have widened the gap:

| Drift | Detail |
|---|---|
| Sensitive extensions | Three-way split. `src/intentAnalyzer.ts` is the only list with `.pem` and `.env`, and the only one **missing** `.dot`, `.gv`, `.iuml`, `.wsd`. `dlp/patterns.js` and `src/dlpEngine.ts` have those four and lack `.pem` / `.env`. |
| Sensitive name patterns | Only `src/intentAnalyzer.ts` has `credentials?`, `secret`, `private`, and the bare `security` (the other two require a suffix: `security[-_]?(design\|arch\|model)`). Only `dlp/patterns.js` has `incident[-_]?response`, `vpn`, `firewall`, `pipeline`. `runbook`, `threat[-_]?model`, `data[-_]?flow`, `deployment` and `system[-_]?design` are **not** JS-only — `src/dlpEngine.ts` carries them, so check it before assuming a gap. `arch`, `infra`, `topology` and `network` are in all three (`dlp/patterns.js`'s `network[-_]?(diagram\|topology\|map)?` has an optional tail, so it matches bare `network` too). |
| Obfuscation bound | `dlp/semantic-analyzer.js` uses the bounded `GAP`. **`src/intentAnalyzer.ts` `OBFUSCATION_PATTERNS` still uses unbounded `[\s\S]*?`** — the §7 bug, unfixed on the extension surface. |
| Classification markers | `dlp/content-scanner.js` has a `RESTRICTED — Do Not Share/Distribute` marker that `litellm/dlp_patterns.py` lacks. |
| `openssl-pipe` | Present in `dlp/semantic-analyzer.js`, absent from `src/intentAnalyzer.ts`. |
| Legacy lists | `dlp/patterns.js` `EXFIL_COMMANDS` and `EXFIL_SUGGESTION_PATTERNS` are exported but **never consulted by the hook** — only `isSensitiveFile` is on the hook's live path. The extension keeps its own **narrower** copies in `src/dlpEngine.ts`: the 9 suggestion patterns match one-for-one (only the `suggest-public-gist` → `suggest-public-share` id differs), but of the 15 `EXFIL_COMMANDS` the extension carries only 9 — it lacks `curl-dpaste`, `curl-ix-io`, `curl-sprunge`, `curl-rentry`, `curl-telegra` and `gsutil-public`. Editing `dlp/patterns.js`'s command list changes nothing at runtime on either surface. |

---

## 5. Testing

```
bash test/run-tests.sh          # hook / Layer 1 / MCP cases (needs node + jq, no npm deps)
npx tsc -p ./                   # extension must compile clean
```

```
# from litellm/
python3 test_patterns.py        # Python detector parity, no dependencies
```

Invoke the runner as `bash test/run-tests.sh` — see §8.

### Every policy change needs a BLOCK case *and* an ALLOW case

A one-sided test is not a test. Each new or narrowed rule gets a matched pair:

| Case | Proves |
|------|--------|
| **BLOCK** | The rule fires on the thing it was written for. |
| **ALLOW** | The nearest legitimate neighbour is *not* caught — no over-block. |

Pick the ALLOW case adversarially: the closest thing a real engineer does every day.

| Change | BLOCK case | ALLOW case |
|---|---|---|
| New approved host | Same payload to a *neighbouring unapproved* host | The payload to the newly approved host |
| New sensitive extension | That file uploaded to an unapproved destination | The same file uploaded to `*.your-company.com`, and `git clone` of a repo containing it |
| New secret detector | The literal secret in an outbound payload | A same-shaped non-secret (a test fixture, a placeholder, documentation prose describing the format) |
| New outbound CLI | The upload form to an unapproved destination | The tool's read/inbound form (`install`, `pull`, `clone`, `fetch`, `GET`) |
| New MCP extractor | Unapproved `owner` / external recipient / paste-service URL | Approved org, `@your-company.com` recipient, internal URL — and the tool's read-only sibling |
| Any regex narrowing | The original true positive still blocks | The false positive that motivated the change now allows |

Fixture hygiene: build trigger strings by concatenation rather than writing them
literally, as `litellm/test_patterns.py` does (`_AWSKEY = "AKIA" + "1234567890" + "ABCDEF"`).
Test files otherwise trip the tooling they are testing — including this repo's own hook
while you edit them.

---

## 6. Releasing a plugin change

**Bump the version in two places, and they must match:**

1. `.claude-plugin/plugin.json` → `"version"`
2. `.claude-plugin/marketplace.json` → the `agentx-dlp` entry's `"version"`

CI enforces equality. Both are `0.1.2` today. `package.json`'s version is the **VS Code
extension** version and is independent — do not conflate them.

### Why the bump is mandatory

The plugin runs from a **cached copy** of the source, not from your working tree.
`claude plugin update` compares versions; if the version string is unchanged it is a
**no-op** and your edited hook is never copied. Symptom: your fix works when you pipe an
event into `node dlp/exfil-hook.js` by hand, but the live hook keeps the old behaviour.

Release sequence:

1. Edit code, update `POLICY.md`, add tests.
2. `bash test/run-tests.sh`, `python3 test_patterns.py`, `npx tsc -p ./` — all green.
3. Bump both version strings identically.
4. Commit.
5. `claude plugin update agentx-dlp` (or reinstall from the marketplace).
6. **Restart Claude Code.** The hook command is resolved at session start; a running
   session keeps the previously loaded hook.

### `dlp/setup.sh` is legacy — do not combine it with the plugin

`setup.sh` is the original standalone installer. It merges a `PreToolUse` entry pointing
at an absolute `dlp/exfil-hook.js` path into `~/.claude/settings.json`.

The plugin registers its own `PreToolUse` entry via `hooks/hooks.json` using
`${CLAUDE_PLUGIN_ROOT}`. **Running both means the hook fires twice** — duplicate block
banners, duplicate advisory log lines, and two Layer 2 Haiku calls per tool call. Pick
one. If you previously ran `setup.sh`, remove its entry from
`~/.claude/settings.json` (`.hooks.PreToolUse`, the one whose command contains an
absolute path to `dlp/exfil-hook.js`) before installing the plugin.

---

## 7. Triaging a false positive

### Reproduce

The hook is a plain stdin→exit-code program, so a false positive is reproducible without
Claude Code. Write the event to a fixture file and pipe it in:

```
# /tmp/event.json
{ "session_id": "fp-repro",
  "transcript_path": "",
  "tool_name": "Bash",
  "tool_input": { "command": "<the command that was wrongly blocked>" } }
```

```
node dlp/exfil-hook.js < /tmp/event.json ; echo "exit=$?"
```

`exit=0` allow, `exit=2` block (the banner on stdout names the rule and the destination).
`exit=1` is the hook protocol's non-blocking-error code, but `exfil-hook.js` never emits
it — it converts its own failures into `exit 0` (see `ARCHITECTURE.md` §3.4/§3.5), so
anything other than 0 or 2 means the process died before the handler ran. For an MCP false
positive, set `tool_name` to the full `mcp__server__tool` name and `tool_input` to the real
argument object.

Keep repro fixtures under `test/` so a fix arrives with its regression case.

### Check the advisory log

```
~/.claude/agentx-dlp.log
```

Advisories are **never** written to stderr — they go only to this file. Write/Edit are
advisory-only, so anything the hook noticed about a local file write is here, not in the
transcript. Use it to distinguish "the hook saw this and let it through" from "the hook
never saw it".

If a Layer 2 decision is suspected, `intent-classifier.js` prints its fail-open reason to
stderr (`[DLP Layer 2] … — failing open`) and the block banner says
`(Decision by LLM intent classifier with conversation context)`. Layer 2 blocks are
non-deterministic; if the same command sometimes blocks and sometimes does not, it is
Layer 2, and the fix belongs in Layer 1 or in `SYSTEM_PROMPT`, not in a retry.

### Fix

Two options, in order of preference:

1. **Narrow the rule** — bound the regex, anchor it, restrict it to the syntactic
   position where the thing actually occurs. Preferred: it fixes the class, not the case.
2. **Extend the allowlist** — only when the destination genuinely should be approved.
   This is a policy change with the blast radius described in §3.1; it needs security
   sign-off, not just a green test run.

Never fix a false positive by weakening the *direction* or *tier* logic — that converts
one false positive into a whole class of false negatives.

### Guiding principle

> **Prefer a false positive over a false negative for top-tier data — but never
> over-block a read-only operation.**

CUSTOMER DATA and RESTRICTED leaving to an unapproved destination is fail-closed by
design (`POLICY.md` §2): blocked on uncertainty, not overridable inline. That tolerance
for false positives does **not** extend to reads. `curl` GET, `git clone/pull/fetch`,
`npm`/`pip`/`go install`, and every `search`/`list`/`get` MCP tool must stay allowed
(`POLICY.md` §5). Blocking those is how a DLP tool gets uninstalled, after which it
catches nothing at all.

### Two real bugs — cautionary examples

**1. Unbounded pipeline regex** (`dlp/semantic-analyzer.js`, `OBFUSCATION_PATTERNS`).

The pipeline detectors originally joined stages with `[\s\S]*?`:

```js
/\b(?:gzip|bzip2|xz|zip|tar)\b[\s\S]*?\|[\s\S]*?\b(?:curl|nc|wget|ssh)\b/
```

Across any long document the tokens `gzip`, `|`, and `curl` each appear *somewhere* — a
README, a Jira ticket, a markdown table (`|` is a table delimiter). The unbounded matcher
happily spanned hundreds of characters and multiple lines to join them, so **prose that
merely discussed these tools was reported as an active exfil pipeline.**

Fix: `GAP = '[^\\n]{0,200}?'` — newline-free and length-bounded — plus
`normalizeCommand()` collapsing backslash continuations so real multi-line commands still
match. **Still unfixed in `src/intentAnalyzer.ts`** (§4).

Lesson: a pipeline is a *local* syntactic structure. Bound the gap and forbid newlines.

**2. Unanchored repo pattern** (`dlp/mcp-handler.js`, `REPO_RE`).

The repo detector matched any bare `word/word` token whenever the surrounding string
mentioned "github" anywhere. Ordinary file paths — `dlp/allowlist.js`,
`test/run-tests.sh`, `.github/workflows/ci.yml` — were **all reported as unapproved
repositories**, so any tool call whose input mentioned GitHub and contained a file path
was blocked.

Fix: anchor to a real reference.

```js
const REPO_RE = /github\.com[/:]([\w.-]+)\/([\w.-]+?)(?:\.git)?(?=[\s"'),;:]|$)/gi;
```

Lesson: match the *identifier that establishes the context* (`github.com/`), not a shape
that happens to be common (`a/b`). A nearby keyword is not an anchor.

Both bugs share one root cause: a pattern that worked on the short strings it was written
against, applied to long free text. Every new pattern gets an ALLOW case built from a
long, prose-heavy document that discusses the very thing being detected.

---

## 8. Gotcha — using Claude Code on this repo

**This repo's own hook screens the agent's Bash calls.** You are editing a DLP tool with
a tool the DLP tool guards. Consequences:

| Do | Don't |
|----|-------|
| Put example commands in **file content** via Write/Edit — Write/Edit are advisory-only and never blocked. | Paste a real upload/publish/pipe command into a Bash call to "see what happens". |
| Invoke scripts as `bash test/run-tests.sh` so the hook sees only the outer command. | Inline a fixture pipeline in a shell call; the hook analyses the whole command string. |
| Build fixture secrets by concatenation in the test file. | Write a live-looking key literal into a command argument. |

Why prose is generally safe: `mcp-handler.js` treats a segment as a command only when it
is **command-shaped** — `COMMAND_HEAD` requires the segment to *begin* with a
transfer/network/encoding tool (optionally via `sudo`/`env`). Documentation that
discusses `curl` or `gh gist create` mid-sentence is recorded as a non-blocking
`advisoryMentions` entry instead. That guarantee holds for MCP tool inputs; a `Bash`
`command` string is always analysed in full.

If the hook blocks you while working here, that is a live repro — capture it as a
`test/` fixture (§7) rather than working around it.
