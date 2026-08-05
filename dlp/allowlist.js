/**
 * Approved Destination Allowlist
 *
 * Defines what is explicitly PERMITTED when data leaves a developer's machine.
 * Anything not matching this list is treated as an unknown external destination
 * and escalated to the AI intent classifier before being allowed.
 *
 * Edit this file to reflect your org's actual approved services.
 */

'use strict';

// ---------------------------------------------------------------------------
// Approved hostnames / domain suffixes (exact match or suffix match)
// ---------------------------------------------------------------------------
const APPROVED_HOSTS = [
  // Internal
  '.your-company.com',
  'your-company.com',

  // Source control — approved GitHub orgs only
  // Any push/upload to github.com outside this org is flagged
  'github.com/your-org',
  'github.com/your-org-dev',   // add other org names here

  // Atlassian (Confluence, Jira)
  'your-company.atlassian.net',
  'your-company.atlassian.net',

  // Slack
  'your-company.slack.com',
  'files.slack.com',          // Slack file uploads go here

  // Approved cloud storage — internal buckets only
  // Listed as prefixes; bucket names must start with "your-org-"
  // (enforced separately — these allow the service hostname)
  'storage.googleapis.com',   // GCS — bucket name checked separately
  's3.amazonaws.com',         // S3  — bucket name checked separately
  's3.us-east-1.amazonaws.com',
  's3.us-west-2.amazonaws.com',

  // CI/CD
  'circleci.com',
  'buildkite.com',

  // Approved developer tools used company-wide
  'datadoghq.com',
  'sentry.io',
];

// ---------------------------------------------------------------------------
// Approved GitHub orgs (only these orgs are permitted for git push / gh operations)
// ---------------------------------------------------------------------------
const APPROVED_GITHUB_ORGS = [
  'your-org',
  'your-org-dev',
  // add others here
];

// ---------------------------------------------------------------------------
// Approved cloud storage bucket prefixes
// ---------------------------------------------------------------------------
const APPROVED_BUCKET_PREFIXES = [
  'your-org-',
  'your-org-',
];

// NOTE: there is deliberately no APPROVED_NPM_REGISTRIES list. The npm decision
// lives in semantic-analyzer.js and routes the --registry value through
// extractHost() + isApprovedHost() below, so npm registries obey the same
// allowlist as every other destination. A separate list existed here once, was
// never exported and never read, and only created the illusion of a control
// point — editing it changed nothing.

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

/**
 * Returns true if the given hostname is on the approved list.
 * Handles exact match and suffix match (e.g. ".your-company.com" covers "api.your-company.com").
 */
function isApprovedHost(hostname) {
  const h = hostname.toLowerCase().replace(/^https?:\/\//, '').split('/')[0];
  return APPROVED_HOSTS.some(approved => {
    if (approved.startsWith('.')) return h.endsWith(approved) || h === approved.slice(1);
    return h === approved || h.endsWith('.' + approved);
  });
}

/**
 * Extract the hostname from a URL or "user@host:path" scp syntax.
 */
function extractHost(urlOrPath) {
  try {
    // Standard URL
    const u = new URL(urlOrPath.includes('://') ? urlOrPath : 'https://' + urlOrPath);
    return u.hostname;
  } catch {
    // scp-style: user@hostname:path
    const scpMatch = urlOrPath.match(/(?:[\w.-]+@)?([\w.-]+):/);
    return scpMatch ? scpMatch[1] : null;
  }
}

/**
 * Extract all URLs from a shell command string.
 */
function extractUrls(command) {
  const urlPattern = /https?:\/\/[\w./%-]+|[\w.-]+\.(?:com|io|org|net|dev|sh|co)(?:\/[\w./%-]*)?/g;
  return [...new Set((command.match(urlPattern) || []))];
}

/**
 * Extract a GitHub org from a git remote URL or gh command.
 * e.g. "github.com/your-org/myrepo" → "your-org"
 */
function extractGitHubOrg(command) {
  const match = command.match(/github\.com[/:]([^/\s]+)/);
  return match ? match[1] : null;
}

/**
 * Extract an S3 or GCS bucket name from a command.
 */
function extractBucketName(command) {
  // s3://bucket-name/...  or  gs://bucket-name/...
  const match = command.match(/(?:s3|gs):\/\/([^/\s]+)/);
  return match ? match[1] : null;
}

/**
 * Returns true if a cloud storage bucket name is on the approved list.
 */
function isApprovedBucket(bucketName) {
  return APPROVED_BUCKET_PREFIXES.some(prefix =>
    bucketName.toLowerCase().startsWith(prefix)
  );
}

/**
 * Analyse a shell command and return a list of external destinations found,
 * separated into approved and unapproved.
 *
 * Returns: { approved: string[], unapproved: string[] }
 */
function classifyDestinations(command) {
  const approved = [];
  const unapproved = [];

  const urls = extractUrls(command);
  for (const url of urls) {
    const host = extractHost(url);
    if (!host) continue;
    // github.com itself is neutral — the ORG determines approval, handled below.
    if (host === 'github.com' || host === 'raw.githubusercontent.com') continue;
    if (isApprovedHost(host)) {
      approved.push(url);
    } else {
      unapproved.push(url);
    }
  }

  // Check GitHub org for any command referencing github.com
  if (/github\.com/.test(command)) {
    const org = extractGitHubOrg(command);
    if (org) {
      if (APPROVED_GITHUB_ORGS.includes(org.toLowerCase())) {
        approved.push(`github.com/${org}`);
      } else {
        unapproved.push(`github.com/${org} (unapproved org)`);
      }
    }
  }

  // Check cloud bucket names
  const bucket = extractBucketName(command);
  if (bucket) {
    if (!isApprovedBucket(bucket)) {
      unapproved.push(`bucket:${bucket} (unapproved bucket name)`);
    }
  }

  return { approved, unapproved };
}

module.exports = {
  APPROVED_HOSTS,
  APPROVED_GITHUB_ORGS,
  APPROVED_BUCKET_PREFIXES,
  isApprovedHost,
  extractHost,
  extractUrls,
  extractGitHubOrg,
  extractBucketName,
  isApprovedBucket,
  classifyDestinations,
};
