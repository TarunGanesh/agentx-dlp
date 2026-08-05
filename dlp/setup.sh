#!/usr/bin/env bash
# setup.sh — Install the DLP PreToolUse hook into ~/.claude/settings.json
#
# This wires exfil-hook.js into Claude Code so it runs before every tool call.
# Run once. Safe to re-run (idempotent via jq merge).
#
# Requirements: node, jq

set -euo pipefail

HOOK_SCRIPT="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)/exfil-hook.js"
CLAUDE_SETTINGS="$HOME/.claude/settings.json"

# ── Preflight ────────────────────────────────────────────────────────────────
if ! command -v node &>/dev/null; then
  echo "ERROR: node is required but not found in PATH" >&2; exit 1
fi
if ! command -v jq &>/dev/null; then
  echo "ERROR: jq is required (brew install jq)" >&2; exit 1
fi
if [[ ! -f "$HOOK_SCRIPT" ]]; then
  echo "ERROR: hook script not found at $HOOK_SCRIPT" >&2; exit 1
fi

# ── Create ~/.claude dir if needed ──────────────────────────────────────────
mkdir -p "$(dirname "$CLAUDE_SETTINGS")"

# ── Seed settings.json if it doesn't exist ──────────────────────────────────
if [[ ! -f "$CLAUDE_SETTINGS" ]]; then
  echo '{}' > "$CLAUDE_SETTINGS"
fi

# ── Merge the hook entry ─────────────────────────────────────────────────────
# We add the hook for every tool (matcher = "*") so it runs on Bash, Write,
# Edit, and WebFetch.  The hook exits 0 fast for tools it doesn't care about.

HOOK_ENTRY=$(cat <<EOF
{
  "matcher": ".*",
  "hooks": [
    {
      "type": "command",
      "command": "node ${HOOK_SCRIPT}"
    }
  ]
}
EOF
)

# Read existing settings, append our hook under hooks.PreToolUse (deduped by command path)
UPDATED=$(jq \
  --argjson hook "$HOOK_ENTRY" \
  --arg cmd "node ${HOOK_SCRIPT}" \
  '
  .hooks //= {} |
  .hooks.PreToolUse //= [] |
  # Remove any existing entry with the same command to stay idempotent
  .hooks.PreToolUse |= map(select(.hooks[0].command != $cmd)) |
  .hooks.PreToolUse += [$hook]
  ' \
  "$CLAUDE_SETTINGS")

echo "$UPDATED" > "$CLAUDE_SETTINGS"

echo ""
echo "✓ DLP hook installed in $CLAUDE_SETTINGS"
echo ""
echo "Hook script: $HOOK_SCRIPT"
echo ""
echo "What it blocks:"
echo "  • gh gist create (without --secret)"
echo "  • curl/wget uploads to pastebin, hastebin, ix.io, paste.ee, etc."
echo "  • gh repo create (without --private)"
echo "  • npm publish (without --access restricted)"
echo "  • AWS S3 copies with --acl public-read"
echo "  • Piping data through netcat (| nc)"
echo "  • curl uploading local files to external URLs"
echo ""
echo "Restart Claude Code for the hook to take effect."
echo ""
