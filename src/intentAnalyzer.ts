import { ChatLogger } from './chatLogger';

export interface IntentResult {
  risk: 'high' | 'medium' | 'low' | 'none';
  is_exfil: boolean;
  reason: string;
  destination: string | null;
  technique: string | null;
  skipped: boolean;
}

// ---------------------------------------------------------------------------
// Mirrors dlp/semantic-analyzer.js — same logic, TypeScript form.
// No API call. Operates synchronously on the command/text string.
// ---------------------------------------------------------------------------

const APPROVED_HOSTS = [
  '.your-company.com', 'your-company.com',
  'github.com/your-org', 'github.com/your-org-dev',
  'your-company.atlassian.net', 'your-company.slack.com', 'files.slack.com',
  'circleci.com', 'buildkite.com', 'datadoghq.com', 'sentry.io',
  'storage.googleapis.com', 's3.amazonaws.com',
];

const APPROVED_GITHUB_ORGS = ['your-org', 'your-org-dev'];

const SENSITIVE_EXTENSIONS = new Set([
  '.drawio', '.puml', '.plantuml', '.mermaid', '.mmd', '.erd',
  '.tf', '.tfvars', '.hcl', '.tfstate', '.pem', '.env',
]);

const SENSITIVE_NAME_PATTERNS = [
  /arch(?:itecture)?/i, /infra(?:structure)?/i, /topology/i,
  /network/i, /security/i, /runbook/i, /credentials?/i, /secret/i, /private/i,
];

// These describe a PIPELINE, so the stages must sit near each other on one
// logical command line. The gap matcher is bounded and newline-free.
//
// An unbounded `[\s\S]*?` here is a false-positive generator: across any long
// text the tokens `gzip`, `|` and `curl` each appear somewhere, and an
// unbounded matcher spans lines to join them, so ordinary prose that merely
// discusses these tools reads as an active exfil pipeline. Mirrors the same fix
// in dlp/semantic-analyzer.js — keep the two in sync.
const GAP = '[^\\n]{0,200}?';

const OBFUSCATION_PATTERNS: Array<{ id: string; pattern: RegExp; description: string }> = [
  { id: 'base64-pipe',   pattern: new RegExp(`\\bbase64\\b${GAP}\\|${GAP}\\b(?:curl|nc|wget)\\b`),                        description: 'base64-encoded data piped to network tool' },
  { id: 'compress-pipe', pattern: new RegExp(`\\b(?:gzip|bzip2|xz|zip|tar)\\b${GAP}\\|${GAP}\\b(?:curl|nc|wget|ssh)\\b`), description: 'compressed data piped to network tool' },
  { id: 'xxd-pipe',      pattern: new RegExp(`\\bxxd\\b${GAP}\\|${GAP}\\b(?:curl|nc)\\b`),                                description: 'hex-encoded data piped to network tool' },
  { id: 'openssl-pipe',  pattern: new RegExp(`\\bopenssl\\b${GAP}enc${GAP}\\|${GAP}\\b(?:curl|nc)\\b`),                   description: 'openssl-encrypted data piped to network tool' },
  { id: 'dns-exfil',     pattern: new RegExp(`\\b(?:nslookup|dig|host)\\b${GAP}\\$\\([^\\n]*\\)`),                        description: 'potential DNS exfiltration via dynamic subdomain' },
  { id: 'eval-download', pattern: new RegExp(`\\bcurl\\b${GAP}\\|\\s*(?:bash|sh|zsh|python|node)\\b`),                    description: 'curl piped directly into shell' },
];

/** Collapse backslash line-continuations so a real multi-line command still
 *  reads as one logical line for the same-line patterns above. */
function normalizeCommand(cmd: string): string {
  return String(cmd).replace(/\\\r?\n[ \t]*/g, ' ');
}

// ---------------------------------------------------------------------------
// IntentAnalyzer
// ---------------------------------------------------------------------------

export class IntentAnalyzer {
  private logger: ChatLogger;
  private cache = new Map<string, IntentResult>();

  constructor(logger: ChatLogger) {
    this.logger = logger;
  }

  /**
   * Analyse text (shell command or AI response) for exfiltration intent.
   * Synchronous, zero API calls.
   */
  analyze(params: {
    text: string;
    sensitiveFiles?: string[];
    unapprovedDests?: string[];
    context?: string;
  }): IntentResult {
    const cacheKey = params.text.slice(0, 200);
    const cached = this.cache.get(cacheKey);
    if (cached) return cached;

    const result = this.run(params.text, params.sensitiveFiles ?? []);
    this.cache.set(cacheKey, result);

    if (result.is_exfil) {
      this.logger.log('warn', 'IntentAnalyzer: exfil detected', {
        risk: result.risk, reason: result.reason, technique: result.technique,
      });
    }

    return result;
  }

  // Async shim so callers that used the old AI-based API don't need changes.
  async analyzeAsync(params: {
    text: string;
    sensitiveFiles?: string[];
    unapprovedDests?: string[];
    context?: string;
  }): Promise<IntentResult> {
    return this.analyze(params);
  }

  private run(cmd: string, sensitiveFiles: string[]): IntentResult {
    // 1. Obfuscation check (on the continuation-collapsed form)
    const normalized = normalizeCommand(cmd);
    for (const { pattern, description } of OBFUSCATION_PATTERNS) {
      if (pattern.test(normalized)) {
        return { risk: 'high', is_exfil: true, reason: description,
                 destination: null, technique: description, skipped: false };
      }
    }

    // 2. Direction check: is data going outward?
    if (!this.isOutbound(cmd)) {
      return this.none('Read-only or inbound operation');
    }

    // 3. Destination check
    const unapproved = this.extractUnapprovedDests(cmd);

    if (unapproved.length === 0) {
      // All detected destinations are approved, or none could be extracted.
      // Check if sensitive files are involved with an unresolvable destination.
      const sensitive = [...sensitiveFiles, ...this.extractSensitiveFiles(cmd)];
      if (sensitive.length > 0 && /\$\{?\w/.test(cmd)) {
        return { risk: 'medium', is_exfil: true,
                 reason: 'Sensitive file in outbound transfer to variable destination',
                 destination: '(destination in shell variable)',
                 technique: 'destination obscured by shell variable', skipped: false };
      }
      return this.none('All destinations are on the approved list');
    }

    // 4. Data source check
    const sensitive = [...new Set([...sensitiveFiles, ...this.extractSensitiveFiles(cmd)])];
    const hasData   = this.hasDataPayload(cmd);
    const technique = this.describeTechnique(cmd);

    if (sensitive.length > 0) {
      return { risk: 'high', is_exfil: true,
               reason: `Sensitive file being sent to unapproved destination: ${unapproved[0]}`,
               destination: unapproved[0], technique, skipped: false };
    }

    if (hasData) {
      return { risk: 'high', is_exfil: true,
               reason: `Data transferred to unapproved destination: ${unapproved[0]}`,
               destination: unapproved[0], technique, skipped: false };
    }

    return { risk: 'medium', is_exfil: true,
             reason: `Outbound command to unapproved destination: ${unapproved[0]}`,
             destination: unapproved[0], technique, skipped: false };
  }

  // ── Helpers ────────────────────────────────────────────────────────────────

  private isOutbound(cmd: string): boolean {
    if (/\bgh\s+gist\s+create\b|\bgh\s+repo\s+create\b|\bnpm\s+publish\b|\bdocker\s+push\b|\bgit\s+push\b/.test(cmd)) return true;
    if (/\|\s*nc\b/.test(cmd)) return true;
    if (/\baws\s+s3\s+(?:cp|sync|mv|put-object)\b/.test(cmd)) return true;
    if (/\bgsutil\s+(?:cp|rsync|mv)\b/.test(cmd)) return true;
    if (/\bcurl\b/.test(cmd)) {
      return /-X\s+(?:POST|PUT|PATCH|DELETE)/i.test(cmd) ||
             /(?:--data(?:-binary|-urlencode)?|-d|-F|--form|--upload-file|-T)\s/.test(cmd);
    }
    if (/\bwget\b/.test(cmd)) return /--post-(?:data|file)/.test(cmd);
    if (/\bscp\b/.test(cmd)) {
      const m = cmd.match(/\bscp\b\s+(?:-\w+\s+)*(\S+)\s+(\S+)/);
      return !!m && !m[1].includes(':') && m[2].includes(':');
    }
    if (/\brsync\b/.test(cmd)) return /\brsync\b[\s\S]*?\s[\w./~-]+\s+[\w.-]+@[\w.-]+:/.test(cmd);
    return false;
  }

  private hasDataPayload(cmd: string): boolean {
    return /(?:--data(?:-binary|-urlencode)?|-d|-F|--form|--upload-file|-T)\s+["']?(?:\w+=)?@?\S/.test(cmd) ||
           /\|\s*(?:curl|nc|wget)\b/.test(cmd) ||
           /<\s*<\(/.test(cmd);
  }

  private extractSensitiveFiles(cmd: string): string[] {
    const paths = (cmd.match(/(?:^|\s)(\.?\/?[\w.-]+\/[\w./-]+|\S+\.\w{2,6})(?=\s|$)/g) ?? [])
      .map(s => s.trim()).filter(s => !s.startsWith('-'));
    return paths.filter(p => this.isSensitivePath(p));
  }

  private isSensitivePath(p: string): boolean {
    const lower = p.toLowerCase();
    const ext = '.' + lower.split('.').pop();
    if (SENSITIVE_EXTENSIONS.has(ext)) return true;
    const name = lower.split('/').pop() ?? lower;
    return SENSITIVE_NAME_PATTERNS.some(r => r.test(name));
  }

  private extractUnapprovedDests(cmd: string): string[] {
    const urlPattern = /https?:\/\/[\w./%-]+|[\w.-]+\.(?:com|io|org|net|dev|sh|co)(?:\/[\w./%-]*)?/g;
    const urls = [...new Set((cmd.match(urlPattern) ?? []))];
    const unapproved: string[] = [];

    for (const url of urls) {
      try {
        const host = new URL(url.includes('://') ? url : 'https://' + url).hostname;
        if (host === 'github.com') continue;  // check org instead
        if (!this.isApprovedHost(host)) unapproved.push(url);
      } catch { /* ignore malformed */ }
    }

    // GitHub org check
    const orgMatch = cmd.match(/github\.com[/:]([^/\s]+)/);
    if (orgMatch) {
      const org = orgMatch[1].toLowerCase();
      if (!APPROVED_GITHUB_ORGS.includes(org)) {
        unapproved.push(`github.com/${org} (unapproved org)`);
      }
    }

    return unapproved;
  }

  private isApprovedHost(host: string): boolean {
    const h = host.toLowerCase();
    return APPROVED_HOSTS.some(a => {
      if (a.startsWith('.')) return h.endsWith(a) || h === a.slice(1);
      return h === a || h.endsWith('.' + a);
    });
  }

  private describeTechnique(cmd: string): string {
    if (/\bgh\s+gist\b/.test(cmd))    return 'GitHub Gist upload';
    if (/\bnpm\s+publish\b/.test(cmd)) return 'npm registry publish';
    if (/\bdocker\s+push\b/.test(cmd)) return 'Docker registry push';
    if (/\bgit\s+push\b/.test(cmd))    return 'git push to external remote';
    if (/\bscp\b/.test(cmd))            return 'SCP file copy to remote host';
    if (/\brsync\b/.test(cmd))          return 'rsync to remote host';
    if (/\|\s*nc\b/.test(cmd))          return 'netcat pipe exfil';
    if (/\baws\s+s3\b/.test(cmd))       return 'AWS S3 upload';
    if (/\bgsutil\b/.test(cmd))         return 'GCS upload';
    return 'curl/wget outbound transfer';
  }

  private none(reason: string): IntentResult {
    return { risk: 'none', is_exfil: false, reason, destination: null, technique: null, skipped: false };
  }

  clearCache() { this.cache.clear(); }
}
