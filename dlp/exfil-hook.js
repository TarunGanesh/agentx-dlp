#!/usr/bin/env node
/**
 * Claude Code PreToolUse DLP Hook
 *
 * Two-layer pipeline:
 *
 *   Layer 1 — Semantic rules      (semantic-analyzer.js, ~0ms, no API)
 *             Structural data-flow analysis: direction + destination + data source.
 *             Catches everything that can be determined from command syntax alone.
 *
 *   Layer 2 — LLM intent decision (intent-classifier.js, ~500ms, Haiku API)
 *             Runs only when Layer 1 does not produce a clear block.
 *             Uses the live conversation transcript as context so Haiku understands
 *             WHY the user asked for the command, not just what the command is.
 *
 * Claude Code hook protocol:
 *   stdin  → JSON: { session_id, transcript_path, tool_name, tool_input, ... }
 *   exit 0 → allow the tool call
 *   exit 2 → block; stdout is shown to the user and fed back to Claude as context
 */

'use strict';

const path = require('path');
const fs   = require('fs');
const os   = require('os');
const { analyze: layer1 }                       = require(path.join(__dirname, 'semantic-analyzer.js'));
const { classifyIntent }                        = require(path.join(__dirname, 'intent-classifier.js'));
const { evaluateMcpCall, describeFindings }     = require(path.join(__dirname, 'mcp-handler.js'));
const { scanText, describeContent, tierLabel }  = require(path.join(__dirname, 'content-scanner.js'));

// Non-blocking advisory log. Advisories (e.g. secrets written to a local file)
// are recorded here rather than emitted to stderr, so they never interfere with
// the tool call. This is also the natural feed for SOC/Splunk forwarding.
const ADVISORY_LOG = path.join(os.homedir(), '.claude', 'agentx-dlp.log');
function advise(line) {
  try {
    fs.appendFileSync(ADVISORY_LOG, `${new Date().toISOString()} ${line}\n`);
  } catch { /* never let logging break the hook */ }
}

// ── Read stdin ────────────────────────────────────────────────────────────────
let raw = '';
process.stdin.setEncoding('utf8');
process.stdin.on('data', chunk => { raw += chunk; });
process.stdin.on('end', async () => {
  let event;
  try {
    event = JSON.parse(raw);
  } catch (e) {
    process.stderr.write(`DLP hook: JSON parse error: ${e.message}\n`);
    process.exit(0);
  }

  try {
    await run(event);
  } catch (err) {
    process.stderr.write(`DLP hook: unexpected error: ${err.message}\n`);
    process.exit(0);   // fail open
  }
});

// ── Router ────────────────────────────────────────────────────────────────────
async function run(event) {
  const { tool_name, tool_input, transcript_path } = event;

  switch (tool_name) {
    case 'Bash':
      return handleBash(tool_input, transcript_path);
    // All local file-mutating tools take the ADVISORY path. Listing only
    // Write/Edit meant MultiEdit and NotebookEdit fell through to the generic
    // handler, where a local edit could be hard-blocked — inconsistent with the
    // rule that writing a file locally is not exfiltration.
    case 'Write':
    case 'Edit':
    case 'MultiEdit':
    case 'NotebookEdit':
      return handleFileWrite(tool_input, transcript_path);
    default:
      // Everything else routes through the generic handler:
      //   • mcp__* tools (Slack, Gmail, GitHub, Atlassian, browser, etc.)
      //   • Agent / Task sub-agent invocations
      //   • WebFetch, and any custom tool we don't explicitly route
      return handleGeneric(tool_name, tool_input, transcript_path);
  }
}

// ── Generic / MCP handler ─────────────────────────────────────────────────────
async function handleGeneric(toolName, toolInput, transcriptPath) {
  if (!toolName || !toolInput) process.exit(0);

  const { verdict, severity, reason, findings, failClosed } = evaluateMcpCall(toolName, toolInput);

  if (verdict === 'allow') process.exit(0);

  if (verdict === 'block') {
    block(severity, reason, [
      describeFindings(toolName, findings),
      '',
      approvedAlternatives(),
    ], failClosed);
  }

  // verdict === 'defer' → escalate to Layer 2 with conversation context
  const l2 = await classifyIntent({
    toolName,
    command: JSON.stringify(toolInput).slice(0, 1500),
    transcriptPath,
  });

  if (!l2.skipped && l2.is_exfil && (l2.risk === 'high' || l2.risk === 'medium')) {
    block(l2.risk, l2.reason, [
      describeFindings(toolName, findings),
      l2.destination ? `Destination: ${l2.destination}` : '',
      l2.technique   ? `Technique:   ${l2.technique}`   : '',
      `(Decision by LLM intent classifier with conversation context)`,
      '',
      approvedAlternatives(),
    ].filter(Boolean));
  }

  process.exit(0);
}

// ── Bash handler ──────────────────────────────────────────────────────────────
async function handleBash(input, transcriptPath) {
  const command = (input.command || '').trim();
  if (!command) process.exit(0);

  // ── Layer 1: semantic rules + content tier ────────────────────────────────
  const l1 = layer1(command);

  if (l1.is_exfil && l1.risk === 'high') {
    block('high', l1.reason, [
      `Command:  ${firstLine(command)}`,
      l1.technique    ? `Technique:    ${l1.technique}`                  : '',
      l1.unapprovedDests?.length ? `Destination:  ${l1.unapprovedDests[0]}` : '',
      l1.sensitiveFiles?.length  ? `Sensitive files: ${l1.sensitiveFiles.join(', ')}` : '',
      l1.contentTier && l1.contentTier !== 'none'
        ? `Data tier:    ${tierLabel(l1.contentTier)}${l1.contentFindings?.length ? ` — ${describeContent(l1.contentFindings)}` : ''}`
        : '',
      '',
      approvedAlternatives(),
    ], l1.failClosed);
  }

  // ── Layer 2: LLM intent decision ─────────────────────────────────────────
  // Runs when Layer 1 is inconclusive (medium risk, or no risk but command
  // touches external destinations). Haiku gets the command + conversation
  // transcript so it understands the user's actual intent.
  const needsLLMCheck = l1.is_exfil && l1.risk === 'medium'
    || (!l1.is_exfil && looksExternal(command));

  if (needsLLMCheck) {
    const l2 = await classifyIntent({
      toolName:       'Bash',
      command,
      transcriptPath,
    });

    if (!l2.skipped && l2.is_exfil && (l2.risk === 'high' || l2.risk === 'medium')) {
      block(l2.risk, l2.reason, [
        `Command:     ${firstLine(command)}`,
        l2.destination ? `Destination: ${l2.destination}` : '',
        l2.technique   ? `Technique:   ${l2.technique}`   : '',
        `(Decision by LLM intent classifier with conversation context)`,
        '',
        approvedAlternatives(),
      ].filter(Boolean));
    }
  }

  process.exit(0);
}

// ── Write / Edit handler ──────────────────────────────────────────────────────
async function handleFileWrite(input, transcriptPath) {
  const content  = (input.content || input.new_string || '').trim();
  const filePath = (input.file_path || '');

  // Non-blocking advisory: writing secrets/credentials into a file isn't exfil
  // by itself (it stays local), but it's worth flagging to the log/SOC. We warn
  // rather than block to avoid breaking legitimate config work.
  const contentScan = scanText(content);
  if (contentScan.tier === 'restricted') {
    advise(
      `Write to ${filePath || '(unknown)'} contains ${describeContent(contentScan.findings)} ` +
      `— ensure this file is not later pushed to an external destination.`
    );
  }

  // Embedded shell commands inside a file being written are flagged as a
  // NON-BLOCKING advisory only. Writing a file locally is not exfiltration —
  // the exfil happens when the script is executed (caught by the Bash handler)
  // or pushed (caught by git/MCP handlers). Blocking here produces false
  // positives on docs, READMEs, and test fixtures that merely *mention* these
  // commands, so we advise instead of block.
  const flagged = [];
  for (const line of content.split('\n')) {
    if (!/\b(?:curl|wget|scp|rsync|gh|git|nc|aws|gsutil|docker|npm)\b/.test(line)) continue;
    const l1 = layer1(line);
    if (l1.is_exfil && l1.risk === 'high') flagged.push(l1.reason);
  }
  if (flagged.length) {
    advise(
      `Write to ${filePath || '(unknown)'} embeds command(s) that would be blocked ` +
      `at execution: ${[...new Set(flagged)].join('; ')}`
    );
  }

  process.exit(0);
}

// ── Output helpers ────────────────────────────────────────────────────────────

function block(severity, title, lines, failClosed = false) {
  const border = '─'.repeat(60);
  const output = [
    '',
    `┌${border}┐`,
    `│ DLP POLICY VIOLATION — ${severity.toUpperCase().padEnd(34)}│`,
    `└${border}┘`,
    '',
    title,
    '',
    ...lines,
    failClosed
      ? `Tier policy: top-tier data (CUSTOMER DATA / RESTRICTED) is blocked on\nuncertainty (fail-closed) and cannot be overridden inline.`
      : '',
    `This action has been blocked by your organization's DLP policy.`,
    `Contact #security if you believe this is a false positive.`,
    '',
  ].filter(l => l !== '' || true).join('\n');

  process.stdout.write(output);
  process.exit(2);
}

function approvedAlternatives() {
  return [
    `Approved sharing options:`,
    `  • gh gist create --secret <file>   (secret gist)`,
    `  • gh repo create --private <name>  (private repo)`,
    `  • Confluence  — your-company.atlassian.net`,
    `  • Slack DM    — your-company.slack.com`,
  ].join('\n');
}

function firstLine(cmd) {
  const line = cmd.split('\n')[0];
  return line.length > 120 ? line.slice(0, 120) + ' …' : line;
}

/**
 * Heuristic gate before calling Layer 2:
 * Only worth asking the LLM if the command references an external host/service.
 */
function looksExternal(cmd) {
  return /https?:\/\/|@[\w.-]+\.[\w]{2,}:|github\.com|s3\.|storage\.google|npm\s+publish|docker\s+push/.test(cmd);
}
