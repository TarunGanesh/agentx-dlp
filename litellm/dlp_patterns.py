"""
AgentX DLP detectors — Python port for the LiteLLM guardrail.

Mirrors the JS policy used by the Claude Code plugin:
  • dlp/allowlist.js        → APPROVED_HOSTS / orgs
  • dlp/content-scanner.js  → secrets, PII, classification tiers
  • dlp/patterns.js         → exfil-suggestion phrases (the "AI suggests a gist" case)

Keep this in sync with the JS side. Pure stdlib, no dependencies.
"""

import re

# ---------------------------------------------------------------------------
# Tier ranking (Confluence: PUBLIC < CONFIDENTIAL < CUSTOMER DATA < RESTRICTED)
# ---------------------------------------------------------------------------
TIER_RANK = {"none": 0, "public": 0, "confidential": 1, "customer": 2, "restricted": 3}


def max_tier(a: str, b: str) -> str:
    return a if TIER_RANK.get(a, 0) >= TIER_RANK.get(b, 0) else b


def tier_label(tier: str) -> str:
    return {
        "confidential": "CONFIDENTIAL",
        "customer": "CUSTOMER DATA",
        "restricted": "RESTRICTED",
    }.get(tier, tier)


def is_fail_closed_tier(tier: str) -> bool:
    return tier in ("customer", "restricted")


# ---------------------------------------------------------------------------
# Approved destinations  [Allowlist]  — anything else is treated as external
# ---------------------------------------------------------------------------
APPROVED_HOST_SUFFIXES = (
    ".your-company.com",
    "your-company.atlassian.net",
    "your-company.slack.com",
    "files.slack.com",
    "circleci.com",
    "buildkite.com",
    "datadoghq.com",
    "sentry.io",
)
APPROVED_GITHUB_ORGS = ("your-org", "your-org-dev")

# Known public exfil destinations  [endpoint DLP taxonomy] — used to give a precise
# label; even without this list, these are denied by NOT being approved.
PUBLIC_EXFIL_HOSTS = (
    "gist.github.com", "pastebin.com", "hastebin.com", "paste.ee", "dpaste.com",
    "ix.io", "sprunge.us", "rentry.co", "telegra.ph", "controlc.com",
    "codepen.io", "codesandbox.io", "diffchecker.com", "jwt.io", "base64.guru",
    "dropbox.com", "drive.google.com", "icloud.com", "onedrive.live.com",
    "mega.nz", "wetransfer.com", "pcloud.com", "file.io", "gofile.io",
    "discord.com", "discordapp.com", "t.me", "telegram.me",
    "gitlab.com", "bitbucket.org", "sourceforge.net",
    "api.sendgrid.com", "api.mailgun.net",
)


def _host_of(url: str):
    m = re.search(r"https?://([^/\s\"']+)", url, re.I)
    if not m:
        return None
    return m.group(1).lower().split(":")[0]


def is_approved_host(host: str) -> bool:
    if not host:
        return False
    h = host.lower()
    if h == "github.com" or h == "raw.githubusercontent.com":
        return True  # org decides; checked separately
    return any(h == s.lstrip(".") or h.endswith(s) for s in APPROVED_HOST_SUFFIXES)


# ---------------------------------------------------------------------------
# Exfil-suggestion phrases  [patterns.js]  — the model proposing a public share
# ---------------------------------------------------------------------------
SUGGESTION_PATTERNS = [
    ("suggest-gist",        r"gist\.github\.com|gh\s+gist\s+create|create\s+a\s+(?:public\s+)?gist"),
    ("suggest-paste",       r"\b(?:pastebin|hastebin|dpaste|rentry|paste\.ee|ix\.io)\b"),
    ("suggest-public-repo", r"gh\s+repo\s+create\b(?![\s\S]*?--private|[\s\S]*?--internal)"),
    ("suggest-share-public",r"(?:paste|share|upload|post|put)\s+(?:it\s+|this\s+)?(?:to|on|at|in)\s+(?:a\s+)?(?:public\s+)?(?:gist|paste\w*|the\s+internet)"),
    ("suggest-personal-cloud", r"\b(?:your\s+personal\s+)?(?:dropbox|google\s+drive|onedrive|icloud)\b"),
]
SUGGESTION_PATTERNS = [(i, re.compile(p, re.I)) for i, p in SUGGESTION_PATTERNS]

# ---------------------------------------------------------------------------
# Secret detectors  [EndpointDLP]
# ---------------------------------------------------------------------------
SECRET_DETECTORS = [
    ("aws-access-key-id", "restricted", "AWS Access Key ID",     re.compile(r"\b(?:AKIA|ASIA)[0-9A-Z]{16}\b")),
    ("aws-secret-key",    "restricted", "AWS Secret Access Key", re.compile(r"aws_secret_access_key[\"'\s]*[=:]\s*[\"']?[A-Za-z0-9/+]{40}\b", re.I)),
    ("private-key",       "restricted", "Private key (PEM)",     re.compile(r"-----BEGIN (?:RSA |EC |OPENSSH |PGP |DSA )?PRIVATE KEY-----")),
    ("github-token",      "restricted", "GitHub token",          re.compile(r"\b(?:ghp|gho|ghu|ghs|ghr)_[A-Za-z0-9]{36}\b|\bgithub_pat_[A-Za-z0-9_]{22,}\b")),
    ("slack-token",       "restricted", "Slack token",           re.compile(r"\bxox[baprs]-[A-Za-z0-9-]{10,}\b")),
    ("google-api-key",    "restricted", "Google API key",        re.compile(r"\bAIza[0-9A-Za-z_\-]{35}\b")),
    ("databricks-token",  "restricted", "Databricks token",      re.compile(r"\bdapi[0-9a-f]{32}\b")),
    ("company-api-key",   "restricted", "Company API key", re.compile(r"\bcompany_api_[A-Za-z0-9]{20,}\b", re.I)),  # TODO confirm format
    ("jwt",               "confidential", "JWT",                 re.compile(r"\beyJ[A-Za-z0-9_-]{8,}\.eyJ[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\b")),
    ("generic-credential","confidential", "Hardcoded credential",re.compile(r"\b(?:api[_-]?key|secret|passwd|password|access[_-]?token|auth[_-]?token)\b[\"'\s]*[=:]\s*[\"'][^\"'\s]{8,}[\"']", re.I)),
]

# ---------------------------------------------------------------------------
# PII detectors  [EndpointDLP]  → CUSTOMER DATA tier
# ---------------------------------------------------------------------------
PII_DETECTORS = [
    ("us-ssn",      "customer", "US SSN",             re.compile(r"\b\d{3}-\d{2}-\d{4}\b"), False),
    ("credit-card", "customer", "Credit card number", re.compile(r"\b(?:4[0-9]{12}(?:[0-9]{3})?|5[1-5][0-9]{14}|3[47][0-9]{13}|6(?:011|5[0-9]{2})[0-9]{12})\b"), True),
    ("iban",        "customer", "IBAN",               re.compile(r"\b[A-Z]{2}\d{2}[A-Z0-9]{11,30}\b"), False),
    # Deliberately NOT re.I: with the flag, [A-Z0-9] also matched lowercase, so
    # any 6-9 letter word after "passport" ("passport photos") was read as a
    # passport number and escalated to the fail-closed CUSTOMER DATA tier.
    # Require something that looks like an identifier: uppercase/digits, >=1 digit.
    ("passport",    "customer", "Passport number",    re.compile(r"\bpassport\s*(?:no\.?|number|#)?\s*[:=]?\s*(?=[A-Z0-9]{6,9}\b)(?=\S*\d)[A-Z0-9]{6,9}\b"), False),
]

# ---------------------------------------------------------------------------
# Classification markers  [EndpointDLP]+[Confluence]
# ---------------------------------------------------------------------------
CLASSIFICATION_MARKERS = [
    ("restricted",   re.compile(r"\b(?:data\s+)?classification\s*[:=\-]\s*restricted\b", re.I), "Classification: RESTRICTED"),
    # "Do Not Share" counts only as a classification LABEL, not as advice. The
    # bare phrase put routine security guidance ("do not share your MFA codes")
    # at the top fail-closed tier.
    ("restricted",   re.compile(r"\b(?:classification|marking|label|sensitivity)\s*[:=\-]\s*do\s+not\s+share\b", re.I), "Classification: Do Not Share"),
    ("restricted",   re.compile(r"(?:^|[\n(\[|])\s*DO\s+NOT\s+SHARE\s*(?=$|[\n)\]|.,;])"), "DO NOT SHARE marker"),
    ("customer",     re.compile(r"\b(?:data\s+)?classification\s*[:=\-]\s*customer(?:\s+data)?\b", re.I), "Classification: CUSTOMER DATA"),
    ("confidential", re.compile(r"\b(?:data\s+)?classification\s*[:=\-]\s*confidential\b", re.I), "Classification: CONFIDENTIAL"),
    ("confidential", re.compile(r"\bprivileged\s+and\s+confidential\b", re.I), "Privileged and Confidential"),
    ("public",       re.compile(r"\b(?:data\s+)?classification\s*[:=\-]\s*public\b", re.I), "Classification: PUBLIC"),
]


def _luhn_valid(num: str) -> bool:
    digits = [int(c) for c in re.sub(r"\D", "", num)]
    if len(digits) < 13:
        return False
    total, alt = 0, False
    for d in reversed(digits):
        if alt:
            d *= 2
            if d > 9:
                d -= 9
        total += d
        alt = not alt
    return total % 10 == 0


def scan_content(text: str):
    """Detect secrets / PII / classification markers. Returns (tier, findings)."""
    findings = []
    tier = "none"
    if not text:
        return tier, findings

    for _id, t, label, pat in SECRET_DETECTORS:
        if pat.search(text):
            findings.append({"type": "secret", "label": label, "tier": t})
            tier = max_tier(tier, t)
    for _id, t, label, pat, luhn in PII_DETECTORS:
        m = pat.search(text)
        if m and (not luhn or _luhn_valid(m.group(0))):
            findings.append({"type": "pii", "label": label, "tier": t})
            tier = max_tier(tier, t)
    for t, pat, label in CLASSIFICATION_MARKERS:
        if pat.search(text):
            findings.append({"type": "classification", "label": label, "tier": t})
            tier = max_tier(tier, t)
    return tier, findings


def scan_suggestions(text: str):
    """Detect the model proposing a public/unapproved sharing destination."""
    hits = []
    if not text:
        return hits
    for _id, pat in SUGGESTION_PATTERNS:
        m = pat.search(text)
        if m:
            hits.append({"id": _id, "match": m.group(0)})
    return hits


def scan_external_destinations(text: str):
    """Return unapproved hosts referenced in the text (URLs + known exfil hosts)."""
    unapproved = []
    if not text:
        return unapproved
    for m in re.finditer(r"https?://[^\s\"'>)]+", text, re.I):
        host = _host_of(m.group(0))
        if host and not is_approved_host(host):
            unapproved.append(host)
    # bare known exfil hosts (no scheme)
    low = text.lower()
    for h in PUBLIC_EXFIL_HOSTS:
        if h in low and h not in unapproved:
            unapproved.append(h)
    # github org check
    for m in re.finditer(r"github\.com[/:]([\w-]+)", text, re.I):
        org = m.group(1).lower()
        if org not in APPROVED_GITHUB_ORGS:
            unapproved.append(f"github.com/{org} (unapproved org)")
    return sorted(set(unapproved))


def describe(findings) -> str:
    if not findings:
        return ""
    by_tier = {}
    for f in findings:
        by_tier.setdefault(f["tier"], set()).add(f["label"])
    parts = sorted(by_tier.items(), key=lambda kv: -TIER_RANK.get(kv[0], 0))
    return " | ".join(f"{tier_label(t)}: {', '.join(sorted(ls))}" for t, ls in parts)
