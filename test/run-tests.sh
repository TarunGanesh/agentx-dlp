#!/usr/bin/env bash
#
# AgentX DLP — hook test harness
#
# Feeds each `.event` object in test/cases.jsonl to dlp/exfil-hook.js on stdin and
# maps the hook's exit code to a verdict:
#
#     exit 2 → BLOCK      exit 0 → ALLOW      anything else → ERROR
#
# Usage:
#     bash test/run-tests.sh              # run every case
#     bash test/run-tests.sh bash/        # only cases whose label contains "bash/"
#     bash test/run-tests.sh git-push     # substring match anywhere in the label
#
# Exits non-zero if any case fails. Needs node + jq. No network, no
# ANTHROPIC_API_KEY: HOME is redirected to an empty sandbox so Layer 2's
# credential discovery finds nothing and fails open deterministically.

set -uo pipefail

SCRIPT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd -- "$SCRIPT_DIR/.." && pwd)"
HOOK="$REPO_ROOT/dlp/exfil-hook.js"
CASES="$SCRIPT_DIR/cases.jsonl"
FILTER="${1-}"

for bin in node jq; do
  command -v "$bin" >/dev/null 2>&1 || {
    printf 'error: %s not found in PATH\n' "$bin" >&2; exit 127; }
done
[ -f "$HOOK" ]  || { printf 'error: hook not found: %s\n'  "$HOOK"  >&2; exit 127; }
[ -f "$CASES" ] || { printf 'error: cases not found: %s\n' "$CASES" >&2; exit 127; }

# ── Hermetic sandbox ─────────────────────────────────────────────────────────
#  • HOME → empty dir: intent-classifier.js finds no ~/.claude/.credentials.json,
#    so Layer 2 fails open every time (no API key, no network, no latency).
#  • cwd  → empty dir: content-scanner's bounded local file reads can never hit a
#    real file, so a case's verdict never depends on the developer's working tree.
SANDBOX="$(mktemp -d "${TMPDIR:-/tmp}/dlp-tests.XXXXXX")" || exit 1
trap 'rm -rf "$SANDBOX"' EXIT INT TERM
mkdir -p "$SANDBOX/home/.claude" "$SANDBOX/cwd"
export HOME="$SANDBOX/home"
unset ANTHROPIC_API_KEY ANTHROPIC_AUTH_TOKEN
EVENT="$SANDBOX/event.json"
cd "$SANDBOX/cwd" || exit 1

if [ -t 1 ]; then
  GREEN=$'\033[32m'; RED=$'\033[31m'; DIM=$'\033[2m'; BOLD=$'\033[1m'; OFF=$'\033[0m'
else
  GREEN=''; RED=''; DIM=''; BOLD=''; OFF=''
fi

printf '\n%sAgentX DLP — hook test harness%s\n' "$BOLD" "$OFF"
printf '%shook:  %s%s\n' "$DIM" "$HOOK" "$OFF"
printf '%scases: %s%s\n' "$DIM" "$CASES" "$OFF"
[ -n "$FILTER" ] && printf '%sfilter: label contains "%s"%s\n' "$DIM" "$FILTER" "$OFF"

pass=0; fail=0; total=0; last_section=''

while IFS= read -r line || [ -n "$line" ]; do
  # skip blank lines
  [ -z "${line//[[:space:]]/}" ] && continue

  meta="$(printf '%s\n' "$line" | jq -r '[(.section // "cases"), .label, .expect] | @tsv' 2>/dev/null)"
  if [ -z "$meta" ]; then
    printf '  %sFAIL%s  %-52s (unparseable case line)\n' "$RED" "$OFF" "${line:0:52}"
    fail=$((fail + 1)); total=$((total + 1)); continue
  fi
  section="$(printf '%s' "$meta" | cut -f1)"
  label="$(printf '%s'   "$meta" | cut -f2)"
  expect="$(printf '%s'  "$meta" | cut -f3)"

  case "$label" in *"$FILTER"*) ;; *) continue ;; esac

  if [ "$section" != "$last_section" ]; then
    printf '\n%s%s%s\n' "$DIM" "$section" "$OFF"
    last_section="$section"
  fi

  printf '%s\n' "$line" | jq -c '.event' > "$EVENT"
  node "$HOOK" < "$EVENT" >/dev/null 2>&1
  code=$?

  case "$code" in
    2) actual='BLOCK' ;;
    0) actual='ALLOW' ;;
    *) actual='ERROR' ;;
  esac

  total=$((total + 1))
  if [ "$actual" = "$expect" ]; then
    pass=$((pass + 1))
    printf '  %sPASS%s  %-44s %-5s (exit %s)\n' "$GREEN" "$OFF" "$label" "$actual" "$code"
  else
    fail=$((fail + 1))
    printf '  %sFAIL%s  %-44s %-5s (exit %s)  expected %s\n' "$RED" "$OFF" "$label" "$actual" "$code" "$expect"
  fi
done < "$CASES"

printf '\n'
if [ "$total" -eq 0 ]; then
  printf '0/0 passed — no case label matched "%s"\n' "$FILTER"
  exit 1
fi
if [ "$fail" -eq 0 ]; then
  printf '%s%s/%s passed%s\n\n' "$GREEN" "$pass" "$total" "$OFF"
  exit 0
fi
printf '%s%s/%s passed%s (%s failed)\n\n' "$RED" "$pass" "$total" "$OFF" "$fail"
exit 1
