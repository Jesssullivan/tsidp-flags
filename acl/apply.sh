#!/usr/bin/env bash
# STUB. Pushes generated/policy.json to the Tailscale policy file API.
# Do not run against a real tailnet until you have reviewed the diff.
#
# Requires, all explicit:
#   CONFIRM_APPLY=apply-<tailnet>   must equal "apply-" plus TAILNET exactly
#   TAILNET                         e.g. example.ts.net (placeholder)
#   ACL_API_KEY_FILE                path to a file holding the API key; it is
#                                   read from the file and handed to curl on
#                                   stdin, never placed in argv or env
#
# Without CONFIRM_APPLY it validates only (POST /acl/validate) when a key file
# is present, and otherwise prints what it would do. It never prints the key.
set -euo pipefail
cd "$(dirname "$0")/.."

: "${TAILNET:?set TAILNET (for example example.ts.net)}"
policy="generated/policy.json"
[ -f "$policy" ] || { echo "acl-apply: run just acl-build first" >&2; exit 2; }

if [ "${CONFIRM_APPLY:-}" != "apply-${TAILNET}" ]; then
  echo "acl-apply: dry run. Would POST $policy to /api/v2/tailnet/${TAILNET}/acl" >&2
  echo "acl-apply: to apply, set CONFIRM_APPLY=apply-${TAILNET} and ACL_API_KEY_FILE" >&2
  exit 0
fi

key_file="${ACL_API_KEY_FILE:?set ACL_API_KEY_FILE to a file holding the API key}"
[ -r "$key_file" ] || { echo "acl-apply: key file not readable" >&2; exit 2; }

# The key goes to curl as a config on stdin so it never appears in argv.
printf 'header = "Authorization: Bearer %s"\n' "$(tr -d '\n' < "$key_file")" |
  curl --fail-with-body --silent --show-error --config - \
    -H "Content-Type: application/hujson" \
    --data-binary "@${policy}" \
    "https://api.tailscale.com/api/v2/tailnet/${TAILNET}/acl"
echo
echo "acl-apply: applied" >&2
