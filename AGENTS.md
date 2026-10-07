# AGENTS.md: tsidp-flags

## Rulings

The maintainer's estate-wide agent rulings apply here. They are kept outside
this public repository. In short: check ownership and live sessions before
acting, treat hooks as advisory, and leave a receipt for every change.

## What this repository is

A public reference stack that turns tailnet, tsidp and edge identity into
fail-closed boolean flags. `README.md` is the contract: trust tiers, layout
and quickstart.

## Working rules

- Every name stays a placeholder (`example.ts.net`, `you@example.com`,
  `example.org`). Never add real tailnet names, hosts, emails or ticket IDs.
  `just denylist` (backed by the private DENYLIST secret in CI) enforces it.
- Never commit `.env`, auth keys or tsidp state. `.env.example` holds
  placeholders only.
- Validate with `just check` and `just test`; `just acl-check` for policy
  changes. `just acl-apply` is a dry run unless explicitly confirmed; do not
  confirm it from an agent session.
- Probe results are hints, never access control.
- Durable notes go in `docs/agent-notes/`.
