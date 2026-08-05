import * as path from 'path';
import { ChatLogger } from './chatLogger';
import { IntentAnalyzer, IntentResult } from './intentAnalyzer';

export interface DLPMatch {
  id: string;
  severity: 'high' | 'medium' | 'low';
  description: string;
  matchedText: string;
}

export interface DLPResult {
  blocked: boolean;
  violations: DLPMatch[];
}

// ---------------------------------------------------------------------------
// Pattern definitions (mirrors dlp/patterns.js for use inside the extension)
// ---------------------------------------------------------------------------

interface Pattern {
  id: string;
  pattern: RegExp;
  description: string;
  severity: 'high' | 'medium' | 'low';
}

const EXFIL_COMMANDS: Pattern[] = [
  { id: 'gh-gist-public',      pattern: /\bgh\s+gist\s+create\b(?![\s\S]*?(?:--secret|-s)\b)/, description: 'GitHub Gist created without --secret (will be public)', severity: 'high' },
  { id: 'curl-pastebin',       pattern: /\b(?:curl|wget)\b[\s\S]*?\bpastebin\.com\b/, description: 'Upload to pastebin.com', severity: 'high' },
  { id: 'curl-hastebin',       pattern: /\b(?:curl|wget)\b[\s\S]*?\bhastebin\b/, description: 'Upload to hastebin', severity: 'high' },
  { id: 'curl-paste-ee',       pattern: /\b(?:curl|wget)\b[\s\S]*?\bpaste\.ee\b/, description: 'Upload to paste.ee', severity: 'high' },
  { id: 'curl-file-upload',    pattern: /\bcurl\b[\s\S]*?(?:--data|--data-binary|-d|-F)\s+@\S+/, description: 'curl uploading local file to external URL', severity: 'high' },
  { id: 'nc-pipe',             pattern: /\|\s*nc\b/, description: 'Piping content through netcat', severity: 'high' },
  { id: 'gh-repo-public',      pattern: /\bgh\s+repo\s+create\b(?![\s\S]*?--private\b)/, description: 'GitHub repo created without --private flag', severity: 'high' },
  { id: 'npm-publish-public',  pattern: /\bnpm\s+publish\b(?![\s\S]*?--access\s+restricted\b)/, description: 'npm publish without --access restricted', severity: 'medium' },
  { id: 'aws-s3-public-acl',   pattern: /\baws\s+s3\b[\s\S]*?--acl\s+public-read/, description: 'AWS S3 with public-read ACL', severity: 'high' },
];

const EXFIL_SUGGESTION_PATTERNS: Pattern[] = [
  { id: 'suggest-gist',        pattern: /(?:gist\.github\.com|gh\s+gist\s+create|create\s+a\s+(?:public\s+)?gist)/i, description: 'Suggestion to share via GitHub Gist', severity: 'high' },
  { id: 'suggest-pastebin',    pattern: /pastebin\.com/i, description: 'Suggestion to share via Pastebin', severity: 'high' },
  { id: 'suggest-hastebin',    pattern: /hastebin\.com/i, description: 'Suggestion to share via Hastebin', severity: 'high' },
  { id: 'suggest-public-share',pattern: /(?:paste|share|upload|put|post)\s+(?:it\s+)?(?:to|on|at|in)\s+(?:a\s+)?(?:public\s+)?(?:gist|paste)/i, description: 'Suggestion to paste/share content publicly', severity: 'high' },
  { id: 'suggest-dpaste',      pattern: /dpaste\.com/i, description: 'Suggestion to share via dpaste', severity: 'medium' },
  { id: 'suggest-ix-io',       pattern: /\bix\.io\b/i, description: 'Suggestion to share via ix.io', severity: 'medium' },
  { id: 'suggest-public-repo', pattern: /\bgh\s+repo\s+create\b(?![\s\S]*?--private\b)/i, description: 'Suggestion to create public GitHub repo', severity: 'high' },
  { id: 'suggest-npm-publish', pattern: /\bnpm\s+publish\b/i, description: 'Suggestion to publish to npm (public)', severity: 'medium' },
  { id: 'suggest-s3-public',   pattern: /--acl\s+public-read/i, description: 'Suggestion to use public S3 ACL', severity: 'high' },
];

const SENSITIVE_EXTENSIONS = new Set([
  '.drawio', '.puml', '.plantuml', '.mermaid', '.mmd', '.erd',
  '.iuml', '.wsd', '.dot', '.gv', '.tf', '.tfvars', '.hcl', '.tfstate',
]);

const SENSITIVE_NAME_PATTERNS = [
  /arch(?:itecture)?/i, /infra(?:structure)?/i, /network/i, /topology/i,
  /system[-_]?design/i, /data[-_]?flow/i, /deployment/i, /threat[-_]?model/i,
  /runbook/i, /security[-_]?(?:design|arch|model)/i,
];

// ---------------------------------------------------------------------------
// DLPEngine
// ---------------------------------------------------------------------------

export class DLPEngine {
  private logger: ChatLogger;
  readonly intentAnalyzer: IntentAnalyzer;

  constructor(logger: ChatLogger) {
    this.logger = logger;
    this.intentAnalyzer = new IntentAnalyzer(logger);
  }

  /**
   * Scan a block of text that may be an AI response.
   * Detects suggestions to share content publicly.
   */
  scanAIResponse(text: string): DLPResult {
    const violations: DLPMatch[] = [];

    for (const entry of EXFIL_SUGGESTION_PATTERNS) {
      const execResult = entry.pattern.exec(text);
      if (execResult) {
        violations.push({
          id: entry.id,
          severity: entry.severity,
          description: entry.description,
          matchedText: execResult[0],
        });
        this.logger.log('warn', `DLP: AI response contains exfil suggestion`, {
          patternId: entry.id,
          description: entry.description,
          matched: execResult[0],
        });
      }
    }

    return { blocked: violations.some(v => v.severity === 'high'), violations };
  }

  /**
   * Scan a shell command (e.g. from clipboard or terminal input).
   * Detects commands that actively exfiltrate data.
   */
  scanCommand(command: string): DLPResult {
    const violations: DLPMatch[] = [];

    for (const entry of EXFIL_COMMANDS) {
      const execResult = entry.pattern.exec(command);
      if (execResult) {
        violations.push({
          id: entry.id,
          severity: entry.severity,
          description: entry.description,
          matchedText: execResult[0],
        });
        this.logger.log('warn', `DLP: Exfiltration command detected`, {
          patternId: entry.id,
          description: entry.description,
          command: command.substring(0, 200),
        });
      }
    }

    return { blocked: violations.length > 0, violations };
  }

  /**
   * Returns true if the file at filePath is a sensitive architecture/infra file.
   */
  isSensitiveFile(filePath: string): boolean {
    const lower = filePath.toLowerCase();
    const ext = path.extname(lower);
    if (SENSITIVE_EXTENSIONS.has(ext)) return true;
    const name = path.basename(lower);
    return SENSITIVE_NAME_PATTERNS.some(p => p.test(name));
  }

  /**
   * Build a human-readable summary of violations for use in VS Code notifications.
   */
  formatViolations(violations: DLPMatch[]): string {
    if (violations.length === 0) return '';
    const lines = violations.map(v => `[${v.severity.toUpperCase()}] ${v.description}`);
    return lines.join('\n');
  }
}
