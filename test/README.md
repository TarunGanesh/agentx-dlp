# DLP hook test harness

End-to-end tests for the `agentx-dlp` PreToolUse hook. Each case is a real hook
event fed to `dlp/exfil-hook.js` on **stdin**, exactly as Claude Code delivers it.
Nothing is stubbed and no internal function is called directly — the harness only
observes the hook's exit code, which is the whole of its contract.

```
bash test/run-tests.sh              # all cases
bash test/run-tests.sh bash/        # only labels containing "bash/"
bash test/run-tests.sh git-push     # substring match anywhere in the label
```

Exit `0` if every case matched its expectation, `1` otherwise (also `1` if a
filter matched nothing, `127` if `node`/`jq`/the hook is missing).

## Contract under test

| Hook exit | Meaning | Harness verdict |
|-----------|---------|-----------------|
| `2` | block — stdout is shown to the user and fed back to the model | `BLOCK` |
| `0` | allow | `ALLOW` |
| anything else | non-blocking error (`1`) or crash | `ERROR` — always fails the case |

## Files

| File | Role |
|------|------|
| `cases.jsonl` | one case per line; `.event` is piped to the hook verbatim |
| `run-tests.sh` | runner; resolves the repo root from its own location, so any cwd works |

Case shape — `section` groups the output, `label` is what the filter matches:

```json
{"section":"must-BLOCK (Bash)","label":"bash/npm-publish-public","expect":"BLOCK",
 "event":{"tool_name":"Bash","tool_input":{"command":"npm publish"}}}
```

## Hermetic by construction

No network, no `ANTHROPIC_API_KEY`, no `claude` CLI, no dependency on the
developer's working tree. Two sandbox moves in `run-tests.sh` buy that:

| Move | Why |
|------|-----|
| `HOME` → empty temp dir | `intent-classifier.js` discovers credentials from `ANTHROPIC_API_KEY`, `ANTHROPIC_AUTH_TOKEN`, then `~/.claude/.credentials.json`. With all three absent, Layer 2 **fails open on every case**, so every expectation below is decided by deterministic Layer 1 logic alone. (Node's `os.homedir()` honours `$HOME` on POSIX; the two env vars are `unset`.) |
| cwd → empty temp dir | `content-scanner.scanCommandReferencedFiles()` does bounded reads of files a command references. In an empty cwd those reads always miss, so no verdict can drift with the contents of the repo. |

Consequence worth knowing: cases that *would* reach Layer 2 (`bash/git-push-your-org`,
`bash/read-only-fetch`, `bash/docker-push-internal-registry`, …) exercise the
**fail-open** path. That is the intended CI behaviour — Layer 2 is an escalation
for ambiguity, never a load-bearing control.

## Expectations, and where each one comes from

Every expectation below was derived by reading the module named in the last
column, not by recording observed behaviour.

### must-BLOCK (Bash) — all Layer 1, `risk: high`

| Case | Deciding rule |
|------|---------------|
| `bash/gist-public-no-secret` | `analyzeFlow` gist branch: `gh gist create` with no `--secret`/`-s` → `gist.github.com (public)` |
| `bash/repo-create-not-private` | repo branch: `gh repo create` with neither `--private` nor `--internal` (the public-repo incident class shape) |
| `bash/sensitive-file-to-paste-host` | unapproved host + `detectDataSource` file ref whose extension is in `patterns.SENSITIVE_FILE_EXTENSIONS` (`.drawio`) |
| `bash/local-file-to-external-webhook` | unapproved host + `hasAnyData` (`-d @file`), no sensitive extension needed |
| `bash/git-push-unapproved-org` | git-push branch + `allowlist.extractGitHubOrg` → org not in `APPROVED_GITHUB_ORGS` |
| `bash/scp-terraform-to-external-host` | `isOutboundTransfer` scp heuristic (local src, remote dst) + `.tf` sensitive + unapproved host |
| `bash/compress-then-listener` | `OBFUSCATION_PATTERNS.compress-pipe` (`tar … \| nc`) |
| `bash/encode-then-upload` | `OBFUSCATION_PATTERNS.base64-pipe` (`base64 … \| curl`) |
| `bash/docker-push-public-registry` | docker branch: registry prefix does not end in `.your-company.com` (bare `user/image` ⇒ Docker Hub) |
| `bash/npm-publish-public` | npm branch: no `--access restricted`, no `--registry …your-company.com` |
| `bash/aws-key-in-body-to-external-host` | flow alone is only **medium** (no `@file` payload); `analyze()` escalates to high + `failClosed` because `content-scanner` finds an `AKIA…` key (RESTRICTED) and the destination is unapproved |

The last row is the one case where the content layer, not the flow layer, is
what blocks. Removing the AWS key from that command would turn it into an ALLOW.

### must-ALLOW (Bash)

| Case | Deciding rule |
|------|---------------|
| `bash/gist-with-secret-flag` | `--secret` skips the gist branch; no resolvable destination and no data payload |
| `bash/git-push-your-org` | org on `APPROVED_GITHUB_ORGS` → `git push to approved destination` |
| `bash/read-only-fetch` | `curl` with no write method, payload flag, or JSON header ⇒ inbound |
| `bash/git-clone` | `clone` is not a transfer verb (`ALWAYS_OUTBOUND` covers `push` only) |
| `bash/dependency-install` | `npm install` is not `npm publish` |
| `bash/docker-push-internal-registry` | `registry.your-company.com/…` matches the approved-registry suffix test |
| `bash/npm-publish-access-restricted` | `--access restricted` |
| `bash/read-only-fetch-key-in-query` | **direction beats content**: an `AKIA…` key in the query string is RESTRICTED, but the request is a GET, so `analyze()` computes `leaving === false` and never escalates |
| `bash/secret-body-to-approved-host` | **destination beats content**: same RESTRICTED key, POSTed, but `api.your-company.com` is on the allowlist so `toApproved` short-circuits `leaving` |

### must-BLOCK (MCP) — `mcp-handler.evaluateMcpCall`

| Case | Deciding rule |
|------|---------------|
| `mcp/github-write-personal-owner` | `PRIMARY_DEST_EXTRACTORS` maps `create_or_update_file` → `owner`; unapproved org blocks on its own |
| `mcp/github-push-files-unapproved-owner` | same extractor family via `push_files` |
| `mcp/email-draft-external-recipient` | `create_draft` → `to/cc/bcc`; any domain outside `your-company.com` |
| `mcp/chat-send-sensitive-file-plus-paste-host` | secondary signals: `unapprovedHosts` (pastebin) **and** `sensitiveFiles` (`.drawio`) in the message text |
| `mcp/browser-navigate-paste-host` | `navigate` → `url` host in `PASTE_SERVICE_HOSTS` |
| `mcp/browser-file-upload-sensitive` | `file_upload` → `url` host fails `isApprovedHost` |
| `mcp/tool-input-embeds-exfil-command` | `extractCommandCandidates` finds a `COMMAND_HEAD`-shaped segment; `semanticAnalyze` rates it high |
| `mcp/email-external-with-ssn` | external recipient + SSN ⇒ CUSTOMER DATA, `failClosed: true` |
| `mcp/email-external-with-restricted-marker` | external recipient + `Data Classification: Restricted` ⇒ RESTRICTED, `failClosed: true` |

### must-ALLOW (MCP)

| Case | Deciding rule |
|------|---------------|
| `mcp/github-write-your-org` | `owner: your-org` is on `APPROVED_GITHUB_ORGS` |
| `mcp/email-internal-with-ssn` | recipient is `@your-company.com`, so there is no external target; **a tier alone never blocks** — every content escalation is gated on `hasExternalTarget` (POLICY.md §5: internal movement is not exfil) |
| `mcp/chat-send-benign-internal` | no destination, file, command, or content signal |
| `mcp/read-only-code-search` | `classifyTool` → `read` via `READ_PATTERNS`; note the query text itself contains `aws_secret_access_key` and is still allowed, because reads cannot exfiltrate |
| `mcp/read-only-thread-search` | `read`; the external address in the query is inert |
| `mcp/read-only-wiki-search` | `read`; the RESTRICTED marker in the query is inert |
| `mcp/webfetch-external-docs` | `READ_ONLY_TOOL_WHITELIST` — `WebFetch` is an HTTP GET |

### false-positive guards (must ALLOW)

Each of these encodes a bug that actually shipped. They are **verified
non-vacuous** — the input really does reach the detector that used to misfire.

| Case | Regression it pins |
|------|--------------------|
| `fp/doc-prose-with-markdown-table` | The pipeline patterns once used an unbounded `[\s\S]*?` gap, so `gzip` on one line, a `\|` in a table border, and `curl` on another line were joined into a fake "compressed data piped to network tool". Fixed by the newline-free `GAP` bound in `semantic-analyzer.js` plus per-segment `COMMAND_HEAD` filtering in `mcp-handler.js`. The document yields **5** command-shaped segments that do reach `semanticAnalyze` (three table rows and two prose clauses) and none flags; the pre-fix regex matches this exact body, the current one does not. |
| `fp/ordinary-paths-with-word-github` | `REPO_RE` once matched any bare `word/word` token whenever the string mentioned "github", so `.github/workflows/ci.yml`, `dlp/allowlist.js` and `test/run-tests.sh` were all reported as unapproved repositories. The pre-fix pattern reports 3 phantom repos on this comment; the current `github.com`-anchored one reports 0. |
| `fp/write-with-example-exfil-commands` | `Write`/`Edit` are **advisory only** — writing a file locally is not exfiltration. The content here contains three commands that would each be blocked at execution; the hook appends an advisory to `~/.claude/agentx-dlp.log` and exits 0. |

## Adding a case

1. Append one JSON object per line to `cases.jsonl` (`section`, `label`, `expect`, `event`).
2. Derive `expect` by reading the module that would decide it — do not run it first
   and copy the answer, or the suite documents bugs instead of policy.
3. `bash test/run-tests.sh <your-label-substring>`.

Keep new commands pointed at reserved example hosts (`example.com`, `webhook.site`,
RFC 5737 addresses) and at files that do not exist. Nothing in `cases.jsonl` is
ever executed — it is parsed as text — but the fixtures should stay obviously inert.
