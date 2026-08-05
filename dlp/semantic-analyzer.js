/**
 * Semantic DataFlow Analyzer
 *
 * Replaces the AI intent classifier. Decomposes a shell command into:
 *
 *   SOURCE  →  TRANSFORM  →  DESTINATION
 *
 * Then applies one rule:
 *   IF data is being actively sent outward
 *   AND destination is not on the approved list
 *   THEN this is an unauthorized exfiltration attempt.
 *
 * Zero latency. Zero API cost. Covers ~95% of practical exfil patterns.
 *
 * The AI was essentially doing these two checks (destination approval + outbound
 * direction) in natural language. This does them structurally.
 */

'use strict';

const { classifyDestinations, extractHost, isApprovedHost } = require('./allowlist.js');
const { isSensitiveFile }      = require('./patterns.js');
const {
  scanText,
  scanCommandReferencedFiles,
  maxTier,
  tierLabel,
  isFailClosedTier,
} = require('./content-scanner.js');

// ---------------------------------------------------------------------------
// 1. Transfer verbs — commands that WRITE data to a destination
//    (as opposed to reading/fetching)
// ---------------------------------------------------------------------------

// These commands can go either direction. We need to determine if they're
// sending (outbound) or receiving (inbound).
const BIDIRECTIONAL_COMMANDS = new Set(['curl', 'wget', 'scp', 'rsync', 'sftp', 'ftp']);

// These are always outbound transfers of local data.
const ALWAYS_OUTBOUND = [
  /\bgh\s+gist\s+create\b/,
  /\bgh\s+repo\s+create\b/,
  /\bnpm\s+publish\b/,
  /\bdocker\s+push\b/,
  /\bgit\s+push\b/,
  /\bgsutil\s+(?:cp|rsync|mv)\b[\s\S]*?gs:\/\//,   // gsutil writing to GCS
  /\baws\s+s3\s+(?:cp|sync|mv|put-object)\b/,       // S3 write operations
  /\|\s*nc\b/,                                       // pipe into netcat
  /\bncat\b[\s\S]*?--send-only\b/,
];

// ---------------------------------------------------------------------------
// 2. Data source detectors
//    What data is being transferred?
// ---------------------------------------------------------------------------

/**
 * Returns information about the data source in a command.
 *
 * @param {string} cmd
 * @returns {{ hasLocalFile: boolean, hasPipeInput: boolean,
 *             hasStdin: boolean, sensitiveFiles: string[], hasAnyData: boolean }}
 */
function detectDataSource(cmd) {
  const sensitiveFiles = [];

  // Explicit file references: -d @file, --data-binary @file, -F field=@file,
  // --upload-file file, --data-urlencode @file, -T file (curl PUT)
  const fileRefs = [
    ...([...cmd.matchAll(/(?:--data(?:-binary|-urlencode)?|-d|-F|--form|--upload-file|-T)\s+["']?(?:\w+=)?@([\w./~-]+)/g)].map(m => m[1])),
    // scp source: accepts both `scp file user@host:path` and `scp file host:path`
    ...([...cmd.matchAll(/\bscp\b\s+(?:-\w+\s+)*([^\s@:]+)\s+(?:[\w.-]+@)?[\w.-]+:/g)].map(m => m[1])),
    // rsync source: rsync src dest  (where dest has a colon)
    ...([...cmd.matchAll(/\brsync\b\s+\S+\s+([\w./~-]+)\s+\S+:/g)].map(m => m[1])),
  ];

  for (const f of fileRefs) {
    if (isSensitiveFile(f)) sensitiveFiles.push(f);
  }

  // Pipe input: cat file | curl ...  /  command | nc ...  /  tar | ssh ...
  const hasPipeInput = /\|\s*(?:curl|wget|nc\b|ncat\b|ssh\b)/.test(cmd) ||
                       /(?:cat|tar|zip|gzip)\s+\S+[\s\S]*?\|/.test(cmd);

  // stdin: curl -d @- (dash means stdin)
  const hasStdin = /(?:-d|-F|--data)\s+@-\b/.test(cmd);

  // Heredoc / process substitution: curl ... < <(command)
  const hasProcessSub = /<\s*<\(/.test(cmd) || /<<</.test(cmd);

  const hasLocalFile = fileRefs.length > 0;
  const hasAnyData   = hasLocalFile || hasPipeInput || hasStdin || hasProcessSub;

  return { hasLocalFile, hasPipeInput, hasStdin, sensitiveFiles, hasAnyData };
}

// ---------------------------------------------------------------------------
// 3. Transfer direction detector
//    Is this command sending data OUT or pulling data IN?
// ---------------------------------------------------------------------------

/**
 * Returns true if the command is actively writing/uploading data externally.
 *
 * @param {string} cmd
 * @returns {boolean}
 */
function isOutboundTransfer(cmd) {
  // Always-outbound patterns
  if (ALWAYS_OUTBOUND.some(p => p.test(cmd))) return true;

  // curl: outbound when it uses a write method or has a data payload
  if (/\bcurl\b/.test(cmd)) {
    const hasMethod = /-X\s+(?:POST|PUT|PATCH|DELETE)/i.test(cmd);
    const hasData   = /(?:--data(?:-binary|-urlencode|-ascii)?|-d|-F|--form|--upload-file|-T)\s/.test(cmd);
    const hasJson   = /(?:--json|-H\s+["']?Content-Type:\s*application\/json)/.test(cmd);
    if (hasMethod || hasData || hasJson) return true;
    // curl with just a URL and no flags = GET = inbound, not exfil
    return false;
  }

  // wget: outbound only with --post-data or --post-file
  if (/\bwget\b/.test(cmd)) {
    return /--post-(?:data|file)/.test(cmd);
  }

  // scp: outbound when the source is local (no colon in first arg before the space+remote)
  // heuristic: if "scp localpath user@host:path" the local file is the source
  if (/\bscp\b/.test(cmd)) {
    const scpArgs = cmd.match(/\bscp\b\s+(?:-\w+\s+)*(\S+)\s+(\S+)/);
    if (scpArgs) {
      const src = scpArgs[1];
      const dst = scpArgs[2];
      // src is local if it has no colon; dst has colon = remote
      return !src.includes(':') && dst.includes(':');
    }
  }

  // rsync: outbound when src is local and dst has a colon (remote)
  if (/\brsync\b/.test(cmd)) {
    return /\brsync\b[\s\S]*?\s[\w./~-]+\s+[\w.-]+@[\w.-]+:/.test(cmd) ||
           /\brsync\b[\s\S]*?--(?:push|upload)/.test(cmd);
  }

  // git push: always outbound
  if (/\bgit\s+push\b/.test(cmd)) return true;

  // pipe into network tool
  if (/\|\s*(?:nc|ncat|ssh)\b/.test(cmd)) return true;

  return false;
}

// ---------------------------------------------------------------------------
// 4. Obfuscation detector
//    Catches commands that encode/compress data before sending, which
//    pattern matching alone misses.
// ---------------------------------------------------------------------------

// These patterns describe a PIPELINE, so the stages must be near each other on
// one logical command line. The gap matcher is deliberately bounded and
// newline-free: `[^\n]{0,200}?`.
//
// Using an unbounded `[\s\S]*?` here was a false-positive generator — across a
// long document (a README, a Jira ticket, a markdown table) the tokens `gzip`,
// `|` and `curl` will each appear *somewhere*, and an unbounded matcher happily
// spans hundreds of characters and multiple lines to join them. Any prose that
// merely discusses these tools was being reported as an active exfil pipeline.
const GAP = '[^\\n]{0,200}?';

const OBFUSCATION_PATTERNS = [
  // base64 encode then pipe out
  { id: 'base64-pipe',   pattern: new RegExp(`\\bbase64\\b${GAP}\\|${GAP}\\b(?:curl|nc|wget)\\b`),                       description: 'base64-encoded data piped to network tool' },
  // compress then pipe out
  { id: 'compress-pipe', pattern: new RegExp(`\\b(?:gzip|bzip2|xz|zip|tar)\\b${GAP}\\|${GAP}\\b(?:curl|nc|wget|ssh)\\b`), description: 'compressed data piped to network tool' },
  // hex encode then send
  { id: 'xxd-pipe',      pattern: new RegExp(`\\bxxd\\b${GAP}\\|${GAP}\\b(?:curl|nc)\\b`),                                description: 'hex-encoded data piped to network tool' },
  // openssl encrypt then send
  { id: 'openssl-pipe',  pattern: new RegExp(`\\bopenssl\\b${GAP}enc${GAP}\\|${GAP}\\b(?:curl|nc)\\b`),                   description: 'openssl-encrypted data piped to network tool' },
  // DNS exfil: nslookup / dig with data-containing subdomain
  { id: 'dns-exfil',     pattern: new RegExp(`\\b(?:nslookup|dig|host)\\b${GAP}\\$\\([^\\n]*\\)`),                        description: 'potential DNS exfiltration via dynamic subdomain' },
  // Eval of downloaded content (reverse exfil setup)
  { id: 'eval-download', pattern: new RegExp(`\\bcurl\\b${GAP}\\|\\s*(?:bash|sh|zsh|python|node)\\b`),                    description: 'curl output piped directly into a shell (remote code execution setup)' },
];

/**
 * Collapse backslash line-continuations so a genuinely multi-line shell command
 * still reads as one logical line for the same-line patterns above.
 */
function normalizeCommand(cmd) {
  return String(cmd).replace(/\\\r?\n[ \t]*/g, ' ');
}

function detectObfuscation(cmd) {
  const normalized = normalizeCommand(cmd);
  return OBFUSCATION_PATTERNS.filter(({ pattern }) => pattern.test(normalized));
}

// ---------------------------------------------------------------------------
// 5. Main analysis entry point
// ---------------------------------------------------------------------------

/**
 * @typedef {Object} SemanticResult
 * @property {"high"|"medium"|"low"|"none"} risk
 * @property {boolean} is_exfil
 * @property {string} reason
 * @property {string[]} unapprovedDests
 * @property {string[]} sensitiveFiles
 * @property {string|null} technique
 */

/**
 * Public entry point. Runs the destination/direction flow analysis, then
 * augments it with CONTENT analysis (what data is involved) and escalates
 * when sensitive content is leaving the organization perimeter.
 *
 * @param {string} command
 * @returns {SemanticResult & {contentTier:string, contentFindings:Array, failClosed:boolean}}
 */
function analyze(command) {
  const base = analyzeFlow(command);

  // ── Content analysis: inline command text + referenced local files ───────
  const inline = scanText(command);
  const refs   = scanCommandReferencedFiles(command);
  const contentTier     = maxTier(inline.tier, refs.tier);
  const contentFindings = [...inline.findings, ...refs.findings];

  base.contentTier     = contentTier;
  base.contentFindings = contentFindings;
  base.failClosed      = false;

  if (contentTier === 'none' || contentTier === 'public') return base;

  // Is the sensitive content actually leaving the organization perimeter?
  // Leaving = base already flagged it, OR it's an outbound transfer not
  // explicitly addressed to an approved destination.
  const outbound   = isOutboundTransfer(command);
  const toApproved = /approved (?:destination|registry|list)/i.test(base.reason);
  const leaving    = base.is_exfil || (outbound && !toApproved);

  if (!leaving) return base;   // sensitive, but staying internal / not a transfer

  // Sensitive content is leaving to an unapproved/unknown destination.
  const dest = base.unapprovedDests?.[0] || '(unresolved external destination)';
  if (isFailClosedTier(contentTier)) {
    base.risk       = 'high';
    base.is_exfil   = true;
    base.failClosed = true;
    base.reason     = `${tierLabel(contentTier)} content leaving to unapproved destination: ${dest}`;
    if (!base.unapprovedDests.length) base.unapprovedDests = [dest];
  } else if (contentTier === 'confidential') {
    base.risk     = 'high';
    base.is_exfil = true;
    base.reason   = `CONFIDENTIAL content leaving to unapproved destination: ${dest}`;
    if (!base.unapprovedDests.length) base.unapprovedDests = [dest];
  }

  return base;
}

/**
 * Analyse a shell command for data exfiltration intent (destination/direction).
 * Returns a structured result — no API call required.
 *
 * @param {string} command
 * @returns {SemanticResult}
 */
function analyzeFlow(command) {
  // ── Obfuscation check (highest priority) ────────────────────────────────
  const obfuscations = detectObfuscation(command);
  if (obfuscations.length > 0) {
    return {
      risk: 'high',
      is_exfil: true,
      reason: obfuscations[0].description,
      unapprovedDests: [],
      sensitiveFiles: [],
      technique: obfuscations.map(o => o.description).join('; '),
    };
  }

  // ── Direction check: is data going OUT? ─────────────────────────────────
  const outbound = isOutboundTransfer(command);
  if (!outbound) {
    return none('Command is inbound/read-only — not a data transfer');
  }

  // ── Destination check: where is it going? ───────────────────────────────

  // gh gist create always targets gist.github.com (public unless --secret).
  // The allowlist doesn't see a URL in the command, so inject it explicitly.
  // The secret-flag test MUST be anchored to a token boundary. `-s\b` alone
  // matched any substring, so a positional filename or description ending in
  // "-s" (e.g. `diagrams-s.txt`) silently suppressed the public-gist block.
  const HAS_SECRET_FLAG = /(?:^|\s)(?:--secret|-s)(?=\s|$)/;
  if (/\bgh\s+gist\s+create\b/.test(command) && !HAS_SECRET_FLAG.test(command)) {
    const positionalFile = command.match(/gh\s+gist\s+create\s+(?:--\S+\s+)*(\S+)/)?.[1] ?? null;
    const sensitiveFiles = positionalFile && isSensitiveFile(positionalFile) ? [positionalFile] : [];
    return {
      risk: 'high',
      is_exfil: true,
      reason: 'gh gist create without --secret publishes to gist.github.com (public)',
      unapprovedDests: ['gist.github.com (public)'],
      sensitiveFiles,
      technique: 'GitHub Gist public upload',
    };
  }

  // gh repo create — public unless --private/--internal is specified.
  // This is the the public-repo incident class scenario: an employee publishing a repo (often with
  // --source=. --push) to their personal/public GitHub account.
  if (/\bgh\s+repo\s+create\b/.test(command) && !/--private\b|--internal\b/.test(command)) {
    return {
      risk: 'high',
      is_exfil: true,
      reason: 'gh repo create without --private/--internal (repository will be public)',
      unapprovedDests: ['github.com (public repository)'],
      sensitiveFiles: [],
      technique: 'public GitHub repository creation',
    };
  }

  // git push always carries repository data. If the org is unapproved, it's
  // a high-severity exfil — treat it as data payload regardless of file refs.
  if (/\bgit\s+push\b/.test(command)) {
    const { unapproved: gitUnapproved } = classifyDestinations(command);
    if (gitUnapproved.length > 0) {
      return {
        risk: 'high',
        is_exfil: true,
        reason: `git push to unapproved destination: ${gitUnapproved[0]}`,
        unapprovedDests: gitUnapproved,
        sensitiveFiles: [],
        technique: 'git push to external remote',
      };
    }
    return none('git push to approved destination');
  }

  // docker push — default registry is Docker Hub (public). Only allow if the
  // image is tagged for an an approved registry (e.g. registry.your-company.com/...).
  if (/\bdocker\s+push\b/.test(command)) {
    const imgMatch = command.match(/\bdocker\s+push\s+([\w./:@-]+)/);
    const image = imgMatch?.[1] ?? '';
    const explicitRegistry = image.match(/^([\w.-]+(?::\d+)?)\//)?.[1] ?? null;
    const isApprovedRegistry = explicitRegistry &&
      (explicitRegistry.endsWith('.your-company.com') || explicitRegistry === 'your-company.com');

    if (!isApprovedRegistry) {
      return {
        risk: 'high',
        is_exfil: true,
        reason: `docker push targets a non-approved registry${explicitRegistry ? ': ' + explicitRegistry : ' (Docker Hub default)'}`,
        unapprovedDests: [explicitRegistry || 'docker.io (Docker Hub default)'],
        sensitiveFiles: [],
        technique: 'Docker image push to public registry',
      };
    }
    return none('docker push to an approved registry');
  }

  // npm publish — defaults to registry.npmjs.org (public). Only safe if scoped
  // to an internal registry via --registry, or restricted via --access restricted.
  if (/\bnpm\s+publish\b/.test(command)) {
    const registryMatch = command.match(/--registry[=\s]+(\S+)/);
    const accessRestricted = /--access\s+restricted\b/.test(command);
    const registry = registryMatch?.[1] ?? '';
    // Must be a HOSTNAME check, not a substring test. `registry.includes(...)`
    // accepted a hostile host whose path or query merely mentioned the domain
    // (https://evil.example/?x=your-company.com) and lookalikes such as
    // registry.your-company.com.evil.example. Route through the allowlist's own
    // suffix-matching logic instead.
    const registryHost = registry ? extractHost(registry) : null;
    const isApprovedRegistry = !!registryHost && isApprovedHost(registryHost);

    if (!isApprovedRegistry && !accessRestricted) {
      return {
        risk: 'high',
        is_exfil: true,
        reason: 'npm publish to public registry without --access restricted',
        unapprovedDests: [registry || 'registry.npmjs.org (default)'],
        sensitiveFiles: [],
        technique: 'npm publish to public registry',
      };
    }
    return none('npm publish to an approved registry or restricted access');
  }

  const { approved, unapproved } = classifyDestinations(command);

  // Data going to an approved destination = fine
  if (unapproved.length === 0 && approved.length > 0) {
    return none(`Destination is on the approved list: ${approved.join(', ')}`);
  }

  // Data going somewhere but we can't tell where
  // (e.g. a variable: curl $UPLOAD_URL -d @file)
  if (unapproved.length === 0 && approved.length === 0) {
    const { hasAnyData, sensitiveFiles } = detectDataSource(command);
    if (hasAnyData && sensitiveFiles.length > 0) {
      return {
        risk: 'medium',
        is_exfil: true,
        reason: 'Outbound transfer to unresolvable destination with sensitive files',
        unapprovedDests: ['(destination in shell variable — could not resolve)'],
        sensitiveFiles,
        technique: 'destination obscured by shell variable',
      };
    }
    return none('Outbound transfer to unknown destination, no sensitive files detected');
  }

  // ── Data source check: what is being sent? ──────────────────────────────
  const { hasAnyData, hasPipeInput, sensitiveFiles } = detectDataSource(command);

  // Unapproved destination found — determine severity by what's being sent
  const technique = buildTechnique(command, hasPipeInput);

  if (sensitiveFiles.length > 0) {
    return {
      risk: 'high',
      is_exfil: true,
      reason: `Sensitive file(s) being sent to unapproved destination: ${unapproved.join(', ')}`,
      unapprovedDests: unapproved,
      sensitiveFiles,
      technique,
    };
  }

  if (hasAnyData) {
    return {
      risk: 'high',
      is_exfil: true,
      reason: `Data being transferred to unapproved destination: ${unapproved.join(', ')}`,
      unapprovedDests: unapproved,
      sensitiveFiles: [],
      technique,
    };
  }

  // Outbound to unapproved dest but no data payload detected — medium risk
  // (could be a configuration call, health check, etc.)
  return {
    risk: 'medium',
    is_exfil: true,
    reason: `Outbound command to unapproved destination: ${unapproved.join(', ')}`,
    unapprovedDests: unapproved,
    sensitiveFiles: [],
    technique,
  };
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

function none(reason) {
  return { risk: 'none', is_exfil: false, reason, unapprovedDests: [], sensitiveFiles: [], technique: null };
}

function buildTechnique(cmd, hasPipeInput) {
  if (/\bgh\s+gist\b/.test(cmd))   return 'GitHub Gist upload';
  if (/\bnpm\s+publish\b/.test(cmd)) return 'npm registry publish';
  if (/\bdocker\s+push\b/.test(cmd)) return 'Docker registry push';
  if (/\bgit\s+push\b/.test(cmd))   return 'git push to external remote';
  if (/\bscp\b/.test(cmd))           return 'SCP file copy to remote host';
  if (/\brsync\b/.test(cmd))         return 'rsync to remote host';
  if (/\|\s*nc\b/.test(cmd))         return 'netcat pipe exfiltration';
  if (/\baws\s+s3\b/.test(cmd))      return 'AWS S3 upload';
  if (/\bgsutil\b/.test(cmd))        return 'Google Cloud Storage upload';
  if (hasPipeInput)                  return 'piped data upload via curl/wget';
  return 'curl/wget outbound POST/PUT';
}

module.exports = { analyze, analyzeFlow, detectDataSource, isOutboundTransfer, detectObfuscation };
