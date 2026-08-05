# AgentX DLP — Policy Reference

The source of truth for **what gets blocked and why**. Read this before changing a rule.

The shipped policy is a *worked example* using placeholder identifiers
(`your-company.com`, `your-org`). It is meant to be adapted, not adopted verbatim —
see [§8](#8-adapting-this-to-your-organization).

Each rule carries a provenance tag so you can tell a policy decision from a
mechanism:

| Tag | Meaning |
|-----|---------|
| **[Policy]** | Comes from an organization's data-classification policy. You will want to re-derive these from your own. |
| **[Threat]** | Comes from known exfiltration techniques and channel taxonomies — largely organization-independent. |
| **[Allowlist]** | The approved-destination list. Entirely organization-specific; see [§4](#4-approved-destinations-the-allowlist). |
| **[Engine]** | Structural data-flow logic. A mechanism, not a policy input. |

---

## 1. How enforcement works

A **PreToolUse hook** runs before every tool call (Bash, file edits, and all MCP
tools). It is **allowlist-based**: for anything *leaving* the machine the default is
**deny unless the destination is approved**, layered with explicit deny rules and
content-based escalation.

```
Tool call
   │
   ▼
Layer 1 — deterministic rules (~0 ms)                    [Engine]
   • direction:   is data going OUT?                     [Engine]
   • destination: is it on the approved list?            [Allowlist]
   • content:     secrets / PII / classification tier?   [Threat]+[Policy]
   │
   ├─ clear violation ─────────────► BLOCK (exit 2)
   │
   ▼
Layer 2 — LLM intent, only when ambiguous                [Engine]
   • reads the conversation transcript for intent
   • fails open if unavailable
```

A violation requires **both** a sensitive subject *and* an unapproved destination.
That is what keeps read-only work and internal transfers untouched.

---

## 2. Data classification tiers  [Policy]

A four-tier scheme with the machine tag set `public | confidential | customer |
restricted`. Most corporate classification policies map onto this shape; if yours
uses different names, change the labels in `dlp/content-scanner.js` and keep the
ordering.

| Tier | Typical definition | Enforcement when leaving to an unapproved destination |
|------|--------------------|--------------------------------------------------------|
| **PUBLIC** | Already public, or published by the organization | Allowed |
| **CONFIDENTIAL** | Internal business information, not for public sharing. **Default for unlabeled internal data** | **Block** |
| **CUSTOMER DATA** | Anything submitted by, captured from, or derived about customers | **Block — fail-closed** |
| **RESTRICTED** | Highly sensitive; secrecy-critical | **Block — fail-closed** |

> **Fail-closed** = blocked even under uncertainty, and not overridable inline.
> The principle: a single top-tier factor, or a single public-internet factor, sets
> the severity floor on its own — it cannot be averaged away by surrounding context.

---

## 3. Explicit deny rules

### 3.1 Evasion / obfuscation — always blocked  [Threat]
Encoding or compressing data immediately before pushing it over the network.

- `base64 … | curl/nc/wget`
- `gzip/bzip2/xz/zip/tar … | curl/nc/wget/ssh`
- `xxd … | curl/nc`
- `openssl enc … | curl/nc`
- `nslookup/dig/host … $(…)` — DNS exfiltration
- `curl … | bash/sh/zsh/python/node` — remote code execution

> These patterns are **same-line and length-bounded** by construction. An unbounded
> cross-line matcher joins unrelated tokens across a long document and blocks
> ordinary prose. See [CONTRIBUTING.md](CONTRIBUTING.md) §7.

### 3.2 Public publishing of code or data — blocked  [Allowlist]+[Engine]
- `gh gist create` without `--secret`
- `gh repo create` without `--private` / `--internal`
- `git push` to a GitHub org outside the approved list
- `docker push` to a registry outside the approved list (Docker Hub default denied)
- `npm publish` without `--access restricted`, or to a non-approved registry
- `aws s3 … --acl public-read`, `gsutil acl set public`

> This class is the reason the project exists. Publishing internal material to a
> personal or public repository is a recurring, well-documented incident pattern —
> an engineer moves work somewhere convenient and the destination happens to be
> world-readable.

### 3.3 Outbound transfers to non-approved destinations — deny by default  [Allowlist]
Any `curl`/`wget` POST/PUT/`--data`/`-F`/`-T`, `scp`, `rsync`, `sftp`, or `| nc`
targeting a host **not** on the approved list ([§4](#4-approved-destinations-the-allowlist)).

The channels below are therefore blocked **by default-deny**, not by per-name rules —
so a new paste site or file-drop service needs no rule change  [Threat]:

| Channel | Examples |
|---|---|
| Public paste / code sites | pastebin, hastebin, paste.ee, dpaste, ix.io, sprunge, rentry, telegra.ph, CodePen, CodeSandbox, Diffchecker, JWT.io |
| Personal cloud storage | Dropbox, Google Drive, iCloud, OneDrive, Box, Mega, WeTransfer, pCloud |
| Personal email providers | Gmail, Yahoo, Proton, Outlook, GMX, … |
| Messaging / webhooks | Discord, Telegram, WhatsApp, external Teams |
| Other dev forges | GitLab, Bitbucket, Azure Repos, SourceForge |
| Transactional email APIs | SendGrid, Mailgun, Postmark |
| Anything unrecognized | any host not on the allowlist |

### 3.4 Content leaving to an external destination — blocked by detector  [Threat]
These escalate an outbound-to-unapproved action to a hard block. Implemented in
`dlp/content-scanner.js` (and mirrored in `litellm/dlp_patterns.py`).

| Detector | Tier |
|----------|------|
| AWS Access Key ID / Secret Access Key | RESTRICTED |
| Private key (PEM) / certificates | RESTRICTED |
| GitHub token, Slack token, Google API key, Databricks token | RESTRICTED |
| Company API key *(placeholder — see [§8](#8-adapting-this-to-your-organization))* | RESTRICTED |
| JWT, hardcoded `password/secret/token=…` | CONFIDENTIAL |
| US SSN, credit card (Luhn-validated), IBAN, passport number | CUSTOMER DATA |
| Classification markers: `Restricted`, `Do Not Share`, `Customer`, `Confidential`, `Privileged and Confidential` | per label  [Policy] |

> Detectors must be **specific enough not to fire on prose**. Two real bugs here:
> a passport pattern with a case-insensitive flag matched "passport photos", and a
> bare `do not share` marker matched "do not share your MFA codes" — both at
> fail-closed tiers. Both are now regression-tested.

### 3.5 MCP tool calls — blocked  [Engine]+[Allowlist]
The hook covers every MCP tool, not just shell commands.

- **Git forge writes** to an owner outside the approved orgs; public or personal repo creation
- **Email** send / draft / reply to any recipient outside the approved domains
- **Browser** navigate or upload to a paste service or unapproved host
- Any write tool whose input **embeds a command-shaped exfil command**, or routes
  **CONFIDENTIAL / CUSTOMER DATA / RESTRICTED** content to an external target

---

## 4. Approved destinations (the allowlist)  [Allowlist]

Everything outbound that is **not** matched here is denied. Defined in
`dlp/allowlist.js`; **this is the first thing you should replace.**

| Category | Shipped placeholder |
|----------|---------------------|
| Internal | `*.your-company.com` |
| Source control | `github.com/your-org`, `github.com/your-org-dev` |
| Wiki / tickets | `your-company.atlassian.net` |
| Chat | `your-company.slack.com`, `files.slack.com` |
| Cloud storage | S3 / GCS **only** with bucket prefix `your-org-` |
| CI/CD | `circleci.com`, `buildkite.com` |
| Monitoring | `datadoghq.com`, `sentry.io` |
| Email recipients | `@your-company.com` only |

---

## 5. Explicitly allowed — not exfiltration

- **Reads and inbound transfers:** `curl` GET, `git clone/pull/fetch`,
  `npm`/`pip`/`go` install
- **Internal transfers:** sensitive content sent to an approved host or an internal
  recipient. Moving sensitive data *within* the perimeter is not exfiltration
- **Local file writes:** `Write`, `Edit`, `MultiEdit`, `NotebookEdit` are advisory
  only. Writing a file locally does not move data anywhere; the egress is caught
  later, when something tries to send it

---

## 6. Out of scope — by design

**OS and physical channels** the hook cannot observe: AirDrop, USB / removable
media, printing, screen capture. These belong to endpoint DLP; this tool is
deliberately not a second, worse implementation of it.

**Shadow-AI governance** (which AI services staff may use) is descoped. This tool
answers "is data leaving to an unapproved destination", not "is this vendor
sanctioned."

**A determined insider.** Anyone who can disable the plugin can bypass it. See
[ARCHITECTURE.md](ARCHITECTURE.md) §1 for the honest threat model.

---

## 7. Rule-to-code map

| Policy section | Enforcing code |
|---|---|
| §3.1 obfuscation | `dlp/semantic-analyzer.js` → `OBFUSCATION_PATTERNS` |
| §3.2 public publishing | `dlp/semantic-analyzer.js` → per-tool branches in `analyzeFlow()` |
| §3.3 default-deny egress | `dlp/allowlist.js` + `classifyDestinations()` |
| §3.4 content detectors | `dlp/content-scanner.js`, `litellm/dlp_patterns.py` |
| §3.5 MCP coverage | `dlp/mcp-handler.js` → `PRIMARY_DEST_EXTRACTORS`, `evaluateMcpCall()` |
| §4 allowlist | `dlp/allowlist.js` |
| tier → enforcement | `dlp/content-scanner.js` → `isFailClosedTier()` |

---

## 8. Adapting this to your organization

The engine is generic; the policy is not. Work through these in order:

1. **Replace the allowlist** — `dlp/allowlist.js`: `APPROVED_HOSTS`,
   `APPROVED_GITHUB_ORGS`, `APPROVED_BUCKET_PREFIXES`, and the email domains in
   `dlp/mcp-handler.js` (`COMPANY_EMAIL_DOMAINS`). Nothing else matters until this
   reflects reality.
2. **Map your classification scheme** onto the four tiers in
   `dlp/content-scanner.js` → `CLASSIFICATION_MARKERS`. If your documents carry
   labels, match the literal strings you actually use.
3. **Add your own secret formats.** The `company-api-key` detector is a
   placeholder pattern; replace it with the real shape of your internal API keys.
4. **Decide your fail-closed tiers.** Shipped default is CUSTOMER DATA and
   RESTRICTED. This is the single most consequential knob: fail-closed tiers block
   on uncertainty and cannot be overridden inline.
5. **Mine your existing DLP tooling.** If you run endpoint DLP, its risk-indicator
   taxonomy is the fastest source of a realistic channel list and detector set —
   you are re-encoding decisions your security team already made.
6. **Add a test case for every change.** Both a BLOCK case and the matching ALLOW
   case that proves you did not over-block. See [CONTRIBUTING.md](CONTRIBUTING.md) §5.

> **Roll out in monitor mode first.** There is no shadow mode yet
> ([ARCHITECTURE.md](ARCHITECTURE.md) §7) — a rule that over-blocks will be routed
> around, and a control everyone routes around is worse than no control.
