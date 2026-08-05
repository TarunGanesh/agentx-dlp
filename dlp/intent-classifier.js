/**
 * Layer 2 — LLM Intent Classifier  (~100ms target)
 *
 * Three latency optimizations stacked:
 *   1. Prompt caching      — system prompt is marked ephemeral and cached
 *                            across calls (5-min TTL). Cuts ~250-400ms after
 *                            the first call.
 *   2. Trimmed prompt      — system prompt is ~250 tokens, not 700.
 *   3. Output constraint   — max_tokens=60 + prefilled "{\"is_exfil\":" so
 *                            Haiku only generates ~15 tokens of JSON, not 200.
 *
 * Credential discovery — auto-detects the user's Claude credentials from:
 *   • ANTHROPIC_API_KEY      env var (most common)
 *   • ANTHROPIC_AUTH_TOKEN   env var (Bedrock / proxy setups)
 *   • ~/.claude/.credentials.json   (Claude Code OAuth users)
 *
 * Result: zero additional config required when Claude Code itself is working.
 */

'use strict';

const fs        = require('fs');
const os        = require('os');
const path      = require('path');

// Lazy, defensive load of the Anthropic SDK. When this hook runs from a plugin
// location, @anthropic-ai/sdk may not be resolvable on the module path. We must
// never let that crash the hook — Layer 2 simply becomes unavailable (fail-open)
// and Layer 1 (deterministic) still does its full job.
let _Anthropic;
function loadAnthropic() {
  if (_Anthropic !== undefined) return _Anthropic;
  try { _Anthropic = require('@anthropic-ai/sdk'); }
  catch { _Anthropic = null; }
  return _Anthropic;
}

const MODEL              = 'claude-haiku-4-5-20251001';
const TIMEOUT_MS         = 3000;
const TRANSCRIPT_TURNS   = 4;     // tighter window than before, less context = faster

// ---------------------------------------------------------------------------
// System prompt — trimmed to essentials, marked cacheable
// ---------------------------------------------------------------------------
const SYSTEM_PROMPT = [
  {
    type: 'text',
    text:
`Classify shell commands for AgentX DLP exfiltration intent.

APPROVED destinations:
- *.your-company.com, your-company.atlassian.net, your-company.slack.com, files.slack.com
- github.com/your-org, github.com/your-org-dev (only these orgs)
- circleci.com, buildkite.com, datadoghq.com, sentry.io
- approved-prefixed cloud buckets, private only

UNAUTHORIZED if data flows to:
- Public paste/share (gist.github.com public, pastebin, hastebin, ix.io, rentry, dpaste)
- Personal cloud (Dropbox/Google Drive/OneDrive personal)
- Webhooks (Discord, personal Slack, external Teams)
- Email APIs to non-approved addresses (SendGrid, Mailgun, Postmark)
- Any GitHub org NOT in approved list
- Public npm publish, Docker Hub push
- Unknown external URLs receiving file uploads
- DNS/base64/compress-piped exfil

NOT exfil: GETs, git clone/pull, npm/pip/go install, internal-only ops.

Use conversation context to resolve intent: "share with team" (internal) vs "share publicly" (external).

Output ONLY this JSON shape, no other text:
{"is_exfil":bool,"risk":"high"|"medium"|"low"|"none","reason":"<≤12 words>","destination":"<host or null>","technique":"<method or null>"}`,
    cache_control: { type: 'ephemeral' },
  },
];

// ---------------------------------------------------------------------------
// Credential discovery
// ---------------------------------------------------------------------------

let cachedClient = null;     // module-level so we keep the HTTP keep-alive pool

function getClient() {
  if (cachedClient) return cachedClient;

  const Anthropic = loadAnthropic();
  if (!Anthropic) return null;          // SDK not resolvable → Layer 2 unavailable

  const credentials = discoverCredentials();
  if (!credentials) return null;

  // Anthropic SDK accepts apiKey OR authToken. authToken is sent as Authorization: Bearer
  cachedClient = new Anthropic(
    credentials.kind === 'oauth'
      ? { authToken: credentials.value }
      : { apiKey:    credentials.value }
  );
  return cachedClient;
}

function discoverCredentials() {
  if (process.env.ANTHROPIC_API_KEY)    return { kind: 'apiKey',  value: process.env.ANTHROPIC_API_KEY };
  if (process.env.ANTHROPIC_AUTH_TOKEN) return { kind: 'oauth',   value: process.env.ANTHROPIC_AUTH_TOKEN };

  // Claude Code OAuth — credentials file
  const credPath = path.join(os.homedir(), '.claude', '.credentials.json');
  try {
    const data = JSON.parse(fs.readFileSync(credPath, 'utf8'));
    const token = data?.claudeAiOauth?.accessToken
               ?? data?.access_token
               ?? data?.api_key
               ?? null;
    if (token) {
      const isOauth = !!(data?.claudeAiOauth?.accessToken || data?.access_token);
      return { kind: isOauth ? 'oauth' : 'apiKey', value: token };
    }
  } catch { /* file absent or unparseable */ }

  return null;
}

// ---------------------------------------------------------------------------
// Transcript reader (unchanged interface, smaller window)
// ---------------------------------------------------------------------------
function readTranscriptContext(transcriptPath) {
  if (!transcriptPath) return '';
  try {
    const raw = fs.readFileSync(transcriptPath, 'utf8');
    const lines = raw.trim().split('\n').filter(Boolean);
    const messages = [];
    for (const line of lines) {
      try {
        const event = JSON.parse(line);
        if (event.type === 'user' || event.type === 'assistant') {
          const content = extractText(event.message?.content ?? event.content ?? '');
          if (content) messages.push({ role: event.type, content });
        }
      } catch { /* skip */ }
    }
    return messages.slice(-TRANSCRIPT_TURNS)
      .map(m => `${m.role.toUpperCase()}: ${m.content.slice(0, 250)}`)
      .join('\n');
  } catch {
    return '';
  }
}

function extractText(content) {
  if (typeof content === 'string') return content;
  if (Array.isArray(content)) {
    return content.filter(b => b.type === 'text').map(b => b.text).join(' ');
  }
  return '';
}

// ---------------------------------------------------------------------------
// Classifier
// ---------------------------------------------------------------------------

/**
 * @param {object} params
 * @param {string} params.toolName
 * @param {string} params.command
 * @param {string} [params.transcriptPath]
 * @returns {Promise<{is_exfil:boolean,risk:string,reason:string,destination:string|null,technique:string|null,skipped:boolean,latencyMs:number}>}
 */
async function classifyIntent({ toolName, command, transcriptPath }) {
  const t0 = Date.now();

  const client = getClient();
  if (!client) return failOpen('No Claude credentials found (env or ~/.claude/.credentials.json)', t0);

  const ctx = readTranscriptContext(transcriptPath);
  const userMsg =
    `Tool: ${toolName}\n` +
    `Command: ${command.slice(0, 800)}\n` +
    (ctx ? `\nRecent conversation:\n${ctx}` : '');

  try {
    const response = await Promise.race([
      client.messages.create({
        model: MODEL,
        max_tokens: 60,
        system: SYSTEM_PROMPT,
        messages: [
          { role: 'user',      content: userMsg },
          { role: 'assistant', content: '{"is_exfil":' },   // ← prefill
        ],
      }),
      new Promise((_, rej) => setTimeout(() => rej(new Error('timeout')), TIMEOUT_MS)),
    ]);

    const generated = response.content[0]?.text ?? '';
    return parseResponse('{"is_exfil":' + generated, Date.now() - t0);

  } catch (err) {
    return failOpen(`Haiku call failed: ${err.message}`, t0);
  }
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

function parseResponse(raw, latencyMs) {
  try {
    // Trim anything past the closing brace (model may continue beyond JSON)
    const match = raw.match(/^\{[^{}]*\}/);
    const json  = match ? match[0] : raw;
    const p     = JSON.parse(json);
    return {
      is_exfil:    Boolean(p.is_exfil),
      risk:        ['high','medium','low','none'].includes(p.risk) ? p.risk : 'low',
      reason:      String(p.reason ?? ''),
      destination: p.destination ?? null,
      technique:   p.technique   ?? null,
      skipped:     false,
      latencyMs,
    };
  } catch {
    return failOpen(`Could not parse: ${raw.slice(0, 80)}`, Date.now() - latencyMs);
  }
}

function failOpen(reason, t0) {
  process.stderr.write(`[DLP Layer 2] ${reason} — failing open\n`);
  return {
    is_exfil: false, risk: 'none', reason,
    destination: null, technique: null,
    skipped: true, latencyMs: typeof t0 === 'number' ? Date.now() - t0 : 0,
  };
}

module.exports = { classifyIntent, discoverCredentials };
