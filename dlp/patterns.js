/**
 * DLP Pattern Library
 *
 * Shared between the Claude Code PreToolUse hook and the VS Code extension.
 * Three categories:
 *   EXFIL_COMMANDS   – shell commands that actively push data to public destinations
 *   EXFIL_URLS       – URLs / hostnames that appear in AI responses as "share here" suggestions
 *   SENSITIVE_FILES  – file types and name patterns that should trigger stricter scrutiny
 */

// ---------------------------------------------------------------------------
// 1. Commands that exfiltrate data when executed
// ---------------------------------------------------------------------------
const EXFIL_COMMANDS = [
  // GitHub Gist — public (no --secret / -s flag)
  {
    id: 'gh-gist-public',
    pattern: /\bgh\s+gist\s+create\b(?![\s\S]*?(?:--secret|-s)\b)/,
    description: 'GitHub Gist created without --secret flag (will be public)',
    severity: 'high',
  },

  // curl/wget posting content to known paste services
  {
    id: 'curl-pastebin',
    pattern: /\b(?:curl|wget)\b[\s\S]*?\bpastebin\.com\b/,
    description: 'Upload to pastebin.com',
    severity: 'high',
  },
  {
    id: 'curl-hastebin',
    pattern: /\b(?:curl|wget)\b[\s\S]*?\bhastebin\b/,
    description: 'Upload to hastebin',
    severity: 'high',
  },
  {
    id: 'curl-paste-ee',
    pattern: /\b(?:curl|wget)\b[\s\S]*?\bpaste\.ee\b/,
    description: 'Upload to paste.ee',
    severity: 'high',
  },
  {
    id: 'curl-dpaste',
    pattern: /\b(?:curl|wget)\b[\s\S]*?\bdpaste\.com\b/,
    description: 'Upload to dpaste.com',
    severity: 'high',
  },
  {
    id: 'curl-ix-io',
    pattern: /\b(?:curl|wget)\b[\s\S]*?\bix\.io\b/,
    description: 'Upload to ix.io',
    severity: 'high',
  },
  {
    id: 'curl-sprunge',
    pattern: /\b(?:curl|wget)\b[\s\S]*?\bsprunge\.us\b/,
    description: 'Upload to sprunge.us',
    severity: 'high',
  },
  {
    id: 'curl-rentry',
    pattern: /\b(?:curl|wget)\b[\s\S]*?\brentry\.co\b/,
    description: 'Upload to rentry.co',
    severity: 'high',
  },
  {
    id: 'curl-telegra',
    pattern: /\b(?:curl|wget)\b[\s\S]*?\btelegra\.ph\b/,
    description: 'Upload to Telegraph (telegra.ph)',
    severity: 'high',
  },

  // Generic: curl POSTing a local file to any external URL
  // Matches both:  -d @file  /  --data-binary @file
  // and:           -F file=@file  /  -F "field=@/path/to/file"
  {
    id: 'curl-file-upload',
    pattern: /\bcurl\b[\s\S]*?(?:(?:--data(?:-binary)?|-d)\s+@|(?:-F|--form)\s+["']?\w+=@)\S+/,
    description: 'curl uploading local file contents to external URL',
    severity: 'high',
  },

  // netcat pipe exfil (e.g. cat secret.txt | nc host port)
  {
    id: 'nc-pipe',
    pattern: /\|\s*nc\b/,
    description: 'Piping content through netcat to external host',
    severity: 'high',
  },

  // git push to public GitHub (non-org, non-private repo heuristic)
  // Flags --public or absence of private context on gh repo create
  {
    id: 'gh-repo-create-public',
    pattern: /\bgh\s+repo\s+create\b(?![\s\S]*?--private\b)/,
    description: 'GitHub repo created without --private flag (will be public)',
    severity: 'high',
  },

  // npm publish without --access restricted / to a non-scoped package
  {
    id: 'npm-publish-public',
    pattern: /\bnpm\s+publish\b(?![\s\S]*?--access\s+restricted\b)/,
    description: 'npm publish without --access restricted (will be public)',
    severity: 'medium',
  },

  // S3 cp/sync to public bucket (--acl public-read)
  {
    id: 'aws-s3-public-acl',
    pattern: /\baws\s+s3\b[\s\S]*?--acl\s+public-read/,
    description: 'AWS S3 copy/sync with public-read ACL',
    severity: 'high',
  },

  // gsutil making objects public
  {
    id: 'gsutil-public',
    pattern: /\bgsutil\s+(?:acl\s+set\s+public|cp\s+-a\s+public-read)/,
    description: 'Google Cloud Storage object made public via gsutil',
    severity: 'high',
  },
];

// ---------------------------------------------------------------------------
// 2. URLs / hostnames to flag in AI response text
//    (the "AI suggests sharing here" scenario)
// ---------------------------------------------------------------------------
const EXFIL_SUGGESTION_PATTERNS = [
  // GitHub Gist
  {
    id: 'suggest-gist',
    // Matches "create a gist", "gist.github.com", "gh gist create" appearing in prose
    pattern: /(?:gist\.github\.com|gh\s+gist\s+create|create\s+a\s+(?:public\s+)?gist)/i,
    description: 'AI is suggesting sharing via GitHub Gist',
    severity: 'high',
  },
  {
    id: 'suggest-pastebin',
    pattern: /pastebin\.com/i,
    description: 'AI is suggesting sharing via Pastebin',
    severity: 'high',
  },
  {
    id: 'suggest-hastebin',
    pattern: /hastebin\.com/i,
    description: 'AI is suggesting sharing via Hastebin',
    severity: 'high',
  },
  {
    id: 'suggest-public-gist',
    pattern: /(?:paste|share|upload|put|post)\s+(?:it\s+)?(?:to|on|at|in)\s+(?:a\s+)?(?:public\s+)?(?:gist|paste)/i,
    description: 'AI is suggesting uploading/sharing content publicly',
    severity: 'high',
  },
  {
    id: 'suggest-dpaste',
    pattern: /dpaste\.com/i,
    description: 'AI is suggesting sharing via dpaste',
    severity: 'medium',
  },
  {
    id: 'suggest-ix-io',
    pattern: /\bix\.io\b/i,
    description: 'AI is suggesting sharing via ix.io',
    severity: 'medium',
  },
  {
    id: 'suggest-public-repo',
    pattern: /gh\s+repo\s+create\b(?![\s\S]*?--private\b)/i,
    description: 'AI is suggesting creating a public GitHub repo',
    severity: 'high',
  },
  {
    id: 'suggest-npm-publish',
    pattern: /\bnpm\s+publish\b/i,
    description: 'AI is suggesting npm publish',
    severity: 'medium',
  },
  {
    id: 'suggest-s3-public',
    pattern: /--acl\s+public-read/i,
    description: 'AI is suggesting S3 with public-read ACL',
    severity: 'high',
  },
];

// ---------------------------------------------------------------------------
// 3. Sensitive file types and name patterns (architectural diagrams, infra, etc.)
// ---------------------------------------------------------------------------
const SENSITIVE_FILE_EXTENSIONS = new Set([
  '.drawio',    // draw.io diagrams
  '.puml',      // PlantUML
  '.plantuml',
  '.mermaid',   // Mermaid diagrams
  '.mmd',
  '.erd',       // Entity-relationship diagrams
  '.iuml',      // informal UML
  '.wsd',       // WebSequenceDiagrams
  '.dot',       // Graphviz DOT
  '.gv',        // Graphviz alternate
  '.tf',        // Terraform (infra-as-code)
  '.tfvars',
  '.hcl',       // HashiCorp config (Vault, Terraform, etc.)
  '.tfstate',   // Terraform state — highly sensitive
]);

const SENSITIVE_FILE_NAME_PATTERNS = [
  /arch(?:itecture)?/i,
  /infra(?:structure)?/i,
  /network[-_]?(?:diagram|topology|map)?/i,
  /topology/i,
  /system[-_]?design/i,
  /data[-_]?flow/i,
  /deployment/i,
  /pipeline/i,
  /vpn/i,
  /firewall/i,
  /security[-_]?(?:design|arch|model)/i,
  /threat[-_]?model/i,
  /runbook/i,
  /incident[-_]?response/i,
];

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

/**
 * Check a shell command string against all EXFIL_COMMANDS patterns.
 * Returns the first matching entry or null.
 */
function checkCommand(command) {
  for (const entry of EXFIL_COMMANDS) {
    if (entry.pattern.test(command)) {
      return entry;
    }
  }
  return null;
}

/**
 * Scan a block of text (e.g. an AI response) for exfiltration suggestions.
 * Returns all matching entries.
 */
function scanResponseText(text) {
  return EXFIL_SUGGESTION_PATTERNS.filter(entry => entry.pattern.test(text));
}

/**
 * Returns true if the file path looks like a sensitive architecture/infra file.
 */
function isSensitiveFile(filePath) {
  const lower = filePath.toLowerCase();
  const ext = '.' + lower.split('.').pop();
  if (SENSITIVE_FILE_EXTENSIONS.has(ext)) return true;
  const name = lower.split('/').pop() || lower;
  return SENSITIVE_FILE_NAME_PATTERNS.some(p => p.test(name));
}

module.exports = {
  EXFIL_COMMANDS,
  EXFIL_SUGGESTION_PATTERNS,
  SENSITIVE_FILE_EXTENSIONS,
  SENSITIVE_FILE_NAME_PATTERNS,
  checkCommand,
  scanResponseText,
  isSensitiveFile,
};
