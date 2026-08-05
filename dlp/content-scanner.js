/**
 * Content Scanner
 *
 * Answers "WHAT is this data?" — the complement to the semantic analyzer's
 * "WHERE is it going?". Together they decide whether a data transfer is exfil.
 *
 * Policy sources:
 *   • Classification tiers + definitions — an organization data-classification policy
 *       PUBLIC < CONFIDENTIAL < CUSTOMER DATA < RESTRICTED
 *       canonical tag set: public | confidential | customer | restricted
 *   • Detectors (secrets, API keys, PII) — endpoint-DLP risk-indicator taxonomy
 *
 * Pure functions, no I/O except the optional scanFile/scanCommandReferencedFiles
 * helpers (bounded local reads). No network, no API.
 */

'use strict';

const fs = require('fs');

// ---------------------------------------------------------------------------
// Tier ranking — higher = more sensitive
// ---------------------------------------------------------------------------
const TIER_RANK = { none: 0, public: 0, confidential: 1, customer: 2, restricted: 3 };

function maxTier(a, b) {
  return (TIER_RANK[a] ?? 0) >= (TIER_RANK[b] ?? 0) ? (a || 'none') : (b || 'none');
}

function tierLabel(tier) {
  return ({ confidential: 'CONFIDENTIAL', customer: 'CUSTOMER DATA', restricted: 'RESTRICTED' })[tier] || tier;
}

// A tier triggers a hard fail-closed block when it leaves the organization perimeter.
function isFailClosedTier(tier) {
  return tier === 'customer' || tier === 'restricted';
}

// ---------------------------------------------------------------------------
// 1. Classification markers — canonical classification tags appearing in content
//    (Confluence: AWS Resource Tagging Policy + Google Drive labeling RFC use
//     exactly public/confidential/customer/restricted)
// ---------------------------------------------------------------------------
const CLASSIFICATION_MARKERS = [
  { tier: 'restricted',   pattern: /\b(?:data\s+)?classification\s*[:=\-]\s*restricted\b/i,           label: 'Classification: RESTRICTED' },
  { tier: 'restricted',   pattern: /\brestricted\s*[-–—:]\s*do\s+not\s+(?:share|distribute)\b/i,      label: 'RESTRICTED — Do Not Share' },
  // "Do Not Share" only counts as a CLASSIFICATION LABEL, not as advice.
  // The bare phrase put routine security guidance ("do not share your MFA
  // codes") at the top fail-closed tier. Require label-like usage: a document
  // marker, a colon/parenthetical, or the standalone all-caps form.
  { tier: 'restricted',   pattern: /\b(?:classification|marking|label|sensitivity)\s*[:=\-]\s*do\s+not\s+share\b/i, label: 'Classification: Do Not Share' },
  { tier: 'restricted',   pattern: /(?:^|[\n(\[|])\s*DO\s+NOT\s+SHARE\s*(?=$|[\n)\]|.,;])/,           label: 'DO NOT SHARE marker' },
  { tier: 'customer',     pattern: /\b(?:data\s+)?classification\s*[:=\-]\s*customer(?:\s+data)?\b/i,  label: 'Classification: CUSTOMER DATA' },
  { tier: 'confidential', pattern: /\b(?:data\s+)?classification\s*[:=\-]\s*confidential\b/i,          label: 'Classification: CONFIDENTIAL' },
  { tier: 'confidential', pattern: /\bprivileged\s+and\s+confidential\b/i,                             label: 'Privileged and Confidential' },
  { tier: 'public',       pattern: /\b(?:data\s+)?classification\s*[:=\-]\s*public\b/i,                label: 'Classification: PUBLIC' },
];

// ---------------------------------------------------------------------------
// 2. Secret / credential detectors — from endpoint DLP taxonomy
//    ([API Key] internal cloud platform / Databricks / GitHub, AWS keys, SAML, certs)
// ---------------------------------------------------------------------------
const SECRET_DETECTORS = [
  { id: 'aws-access-key-id', tier: 'restricted',   label: 'AWS Access Key ID',     pattern: /\b(?:AKIA|ASIA)[0-9A-Z]{16}\b/ },
  { id: 'aws-secret-key',    tier: 'restricted',   label: 'AWS Secret Access Key', pattern: /aws_secret_access_key["'\s]*[=:]\s*["']?[A-Za-z0-9/+]{40}\b/i },
  { id: 'private-key',       tier: 'restricted',   label: 'Private key (PEM)',     pattern: /-----BEGIN (?:RSA |EC |OPENSSH |PGP |DSA )?PRIVATE KEY-----/ },
  { id: 'github-token',      tier: 'restricted',   label: 'GitHub token',          pattern: /\b(?:ghp|gho|ghu|ghs|ghr)_[A-Za-z0-9]{36}\b|\bgithub_pat_[A-Za-z0-9_]{22,}\b/ },
  { id: 'slack-token',       tier: 'restricted',   label: 'Slack token',           pattern: /\bxox[baprs]-[A-Za-z0-9-]{10,}\b/ },
  { id: 'google-api-key',    tier: 'restricted',   label: 'Google API key',        pattern: /\bAIza[0-9A-Za-z_\-]{35}\b/ },
  { id: 'databricks-token',  tier: 'restricted',   label: 'Databricks token',      pattern: /\bdapi[0-9a-f]{32}\b/ },
  { id: 'company-api-key',   tier: 'restricted',   label: 'Company API key', pattern: /\bcompany_api_[A-Za-z0-9]{20,}\b/i }, // TODO: confirm exact format with security
  { id: 'jwt',               tier: 'confidential', label: 'JWT',                   pattern: /\beyJ[A-Za-z0-9_-]{8,}\.eyJ[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\b/ },
  { id: 'generic-credential',tier: 'confidential', label: 'Hardcoded credential',  pattern: /\b(?:api[_-]?key|secret|passwd|password|access[_-]?token|auth[_-]?token)\b["'\s]*[=:]\s*["'][^"'\s]{8,}["']/i },
];

// ---------------------------------------------------------------------------
// 3. PII detectors — from endpoint DLP built-in indicators
//    SSN / credit card / IBAN / passport map to CUSTOMER DATA tier (regulated)
// ---------------------------------------------------------------------------
const PII_DETECTORS = [
  { id: 'us-ssn',      tier: 'customer', label: 'US SSN',             pattern: /\b\d{3}-\d{2}-\d{4}\b/,        luhn: false },
  { id: 'credit-card', tier: 'customer', label: 'Credit card number', pattern: /\b(?:4[0-9]{12}(?:[0-9]{3})?|5[1-5][0-9]{14}|3[47][0-9]{13}|6(?:011|5[0-9]{2})[0-9]{12})\b/, luhn: true },
  { id: 'iban',        tier: 'customer', label: 'IBAN',               pattern: /\b[A-Z]{2}\d{2}[A-Z0-9]{11,30}\b/, luhn: false },
  // NOTE: deliberately NOT /i. With the case-insensitive flag the [A-Z0-9]
  // class also matched lowercase, so any 6-9 letter word after "passport"
  // ("passport photos", "passport numbers") was read as a passport number and
  // escalated to the fail-closed CUSTOMER DATA tier. Require an identifier
  // that actually looks like one: uppercase/digits, and at least one digit.
  { id: 'passport',    tier: 'customer', label: 'Passport number',    pattern: /\bpassport\s*(?:no\.?|number|#)?\s*[:=]?\s*(?=[A-Z0-9]{6,9}\b)(?=[^\s]*\d)[A-Z0-9]{6,9}\b/, luhn: false },
];

// ---------------------------------------------------------------------------
// Core: scan a block of text
// ---------------------------------------------------------------------------

/**
 * @param {string} text
 * @returns {{ tier: string, findings: Array<{type:string,label:string,tier:string}> }}
 */
function scanText(text) {
  const findings = [];
  let tier = 'none';

  if (!text || typeof text !== 'string') return { tier, findings };

  // Classification markers
  for (const m of CLASSIFICATION_MARKERS) {
    if (m.pattern.test(text)) {
      findings.push({ type: 'classification', label: m.label, tier: m.tier });
      tier = maxTier(tier, m.tier);
    }
  }

  // Secrets / credentials
  for (const d of SECRET_DETECTORS) {
    if (d.pattern.test(text)) {
      findings.push({ type: 'secret', label: d.label, tier: d.tier });
      tier = maxTier(tier, d.tier);
    }
  }

  // PII (with optional Luhn validation to cut false positives)
  for (const d of PII_DETECTORS) {
    const match = text.match(d.pattern);
    if (match) {
      if (d.luhn && !luhnValid(match[0])) continue;
      findings.push({ type: 'pii', label: d.label, tier: d.tier });
      tier = maxTier(tier, d.tier);
    }
  }

  return { tier, findings };
}

// ---------------------------------------------------------------------------
// Bounded local file scan
// ---------------------------------------------------------------------------

const MAX_SCAN_BYTES = 512 * 1024;   // don't read huge files in a hook

/**
 * Read a local file (bounded) and scan its content.
 * Returns {tier:'none', findings:[]} on any error or if the file is absent.
 */
function scanFile(filePath) {
  try {
    if (!filePath || filePath === '@-' || filePath.startsWith('-')) return { tier: 'none', findings: [] };
    const resolved = filePath.replace(/^~(?=\/)/, process.env.HOME || '');
    const stat = fs.statSync(resolved);
    if (!stat.isFile() || stat.size > MAX_SCAN_BYTES) return { tier: 'none', findings: [] };
    const content = fs.readFileSync(resolved, 'utf8');
    return scanText(content);
  } catch {
    return { tier: 'none', findings: [] };
  }
}

/**
 * Extract local file references from a shell command and scan their content.
 * Catches: curl -F file=@infra.drawio, gh gist create arch.tf, cat secrets.env | …
 *
 * @returns {{ tier:string, findings:Array, files:string[] }}
 */
function scanCommandReferencedFiles(command) {
  const candidates = new Set();

  // @file upload references (curl -d @f, -F x=@f, --upload-file handled below)
  for (const m of command.matchAll(/@([\w./~-]+)/g)) candidates.add(m[1]);

  // gh gist create <file>
  const gist = command.match(/gh\s+gist\s+create\s+(?:--\S+\s+)*([\w./~-]+)/);
  if (gist) candidates.add(gist[1]);

  // cat/scp/rsync/--upload-file/-T file-like tokens with an extension
  for (const m of command.matchAll(/\b(?:cat|scp|rsync|--upload-file|-T)\s+(?:-\w+\s+)*([\w./~-]+\.[\w]{1,8})\b/g)) {
    candidates.add(m[1]);
  }

  let tier = 'none';
  const findings = [];
  const files = [];
  for (const f of candidates) {
    const res = scanFile(f);
    if (res.tier !== 'none') {
      tier = maxTier(tier, res.tier);
      findings.push(...res.findings.map(x => ({ ...x, file: f })));
      files.push(f);
    }
  }
  return { tier, findings, files };
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

function luhnValid(numStr) {
  const digits = numStr.replace(/\D/g, '');
  if (digits.length < 13) return false;
  let sum = 0, alt = false;
  for (let i = digits.length - 1; i >= 0; i--) {
    let d = parseInt(digits[i], 10);
    if (alt) { d *= 2; if (d > 9) d -= 9; }
    sum += d; alt = !alt;
  }
  return sum % 10 === 0;
}

/** Summarise findings for a block message. */
function describeContent(findings) {
  if (!findings || findings.length === 0) return '';
  const byTier = {};
  for (const f of findings) (byTier[f.tier] ??= []).push(f.label + (f.file ? ` (in ${f.file})` : ''));
  return Object.entries(byTier)
    .sort((a, b) => TIER_RANK[b[0]] - TIER_RANK[a[0]])
    .map(([t, labels]) => `${tierLabel(t)}: ${[...new Set(labels)].join(', ')}`)
    .join(' | ');
}

module.exports = {
  scanText,
  scanFile,
  scanCommandReferencedFiles,
  maxTier,
  tierLabel,
  isFailClosedTier,
  describeContent,
  TIER_RANK,
};
