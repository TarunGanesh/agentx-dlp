"""Standalone test of the DLP pattern module (no litellm needed)."""
from dlp_patterns import (
    scan_content, scan_suggestions, scan_external_destinations,
)


def response_blocks(text):
    """Mimic the guardrail's response decision."""
    reasons = []
    if scan_suggestions(text):
        reasons.append("suggestion")
    if scan_external_destinations(text):
        reasons.append("destination")
    tier, _ = scan_content(text)
    if tier != "none":
        reasons.append(f"content:{tier}")
    return (len(reasons) > 0, reasons)


# Build trigger fixtures at runtime so the source file itself stays clean of
# literal exfil phrases (avoids tripping local DLP tooling on this test file).
_GIST = "g" + "h " + "gist " + "create"
_AWSKEY = "AKIA" + "1234567890" + "ABCDEF"
_SSN = "123-45-" + "6789"

CASES = [
    ("AI suggests public gist",      f"You can run `{_GIST} diagram.drawio` then share gist.github.com/abc", True),
    ("AI suggests paste site",       "Easiest is to paste it on paste" + "bin.com and send the link", True),
    ("AI suggests personal cloud",   "Upload it to your personal dropbox and share that", True),
    ("AI echoes an AWS key",         f"Here's the key: {_AWSKEY}", True),
    ("AI echoes an SSN",             f"The applicant SSN is {_SSN}", True),
    ("AI emits RESTRICTED marker",   "Note: Classification: Restricted", True),
    ("AI suggests personal GitHub",  "Push it to git" + "hub.com/someone-personal/backup", True),
    ("benign code help",             "Here's a React component using useReducer.", False),
    ("internal wiki link"    ,        "See https://your-company.atlassian.net/wiki/x/abc", False),
    ("approved-org github",               "Open a PR against git" + "hub.com/your-org/backend", False),
]


def main():
    passed = 0
    for label, text, expect in CASES:
        blocked, reasons = response_blocks(text)
        ok = blocked == expect
        passed += ok
        mark = "OK " if ok else "XX "
        print(f"  {mark} {label:32s} expect={'BLOCK' if expect else 'ALLOW':5s} "
              f"got={'BLOCK' if blocked else 'ALLOW':5s} {reasons if blocked else ''}")
    print(f"\n{passed}/{len(CASES)} passed")


if __name__ == "__main__":
    main()
