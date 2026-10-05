#!/usr/bin/env bash
# Fail if any denylisted token appears in tracked or untracked-but-unignored
# files. The denylist is NEVER stored in this repo: it comes from the DENYLIST
# env var (newline-separated) or the untracked file named by DENYLIST_FILE
# (default .denylist). Case-insensitive fixed-string match.
#
# CI sets DENYLIST from a repository secret. With no denylist configured the
# check passes with a loud notice, unless REQUIRE_DENYLIST=1 (then it fails).
set -euo pipefail
cd "$(dirname "$0")/.."

file="${DENYLIST_FILE:-.denylist}"
tokens="${DENYLIST:-}"
if [ -z "$tokens" ] && [ -f "$file" ]; then
  tokens="$(cat "$file")"
fi

if [ -z "$(printf '%s' "$tokens" | tr -d '[:space:]')" ]; then
  if [ "${REQUIRE_DENYLIST:-0}" = "1" ]; then
    echo "denylist-check: no denylist configured and REQUIRE_DENYLIST=1" >&2
    exit 2
  fi
  echo "denylist-check: NOTICE no denylist configured (set DENYLIST or $file); nothing checked" >&2
  exit 0
fi

patterns="$(mktemp)"
trap 'rm -f "$patterns"' EXIT
printf '%s\n' "$tokens" | sed -e 's/[[:space:]]*$//' -e '/^$/d' -e '/^#/d' > "$patterns"

# Never print the matched token or the line: only the file and the count.
status=0
while IFS= read -r f; do
  [ -f "$f" ] || continue
  case "$f" in scripts/denylist-check.sh|.denylist) continue ;; esac
  if hits="$(grep -I -i -c -F -f "$patterns" -- "$f" 2>/dev/null)" && [ "$hits" -gt 0 ]; then
    echo "denylist-check: FAIL $f ($hits matching line(s); token not shown)" >&2
    status=1
  fi
done < <(git ls-files --cached --others --exclude-standard)

# Also check file names and the commit messages on the branch tip.
if git ls-files --cached --others --exclude-standard | grep -i -F -f "$patterns" >/dev/null 2>&1; then
  echo "denylist-check: FAIL a tracked file name matches the denylist" >&2
  status=1
fi
if git log -n 50 --format=%B 2>/dev/null | grep -i -F -f "$patterns" >/dev/null 2>&1; then
  echo "denylist-check: FAIL a recent commit message matches the denylist" >&2
  status=1
fi

[ "$status" -eq 0 ] && echo "denylist-check: ok"
exit "$status"
