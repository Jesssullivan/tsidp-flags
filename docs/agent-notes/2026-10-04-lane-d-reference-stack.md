# 2026-10-04 Lane D: private reference stack skeleton

Plan approved 2026-10-04 (operator interview, Lane D).

## Guard-hook refusal, then ruling

The Bash PreToolUse guard hook refused the first command that wrote
`packages/flags/src/index.ts` and `resolve.test.ts`. Verbatim output:

    FAIL unsafe agent process-control or credential-in-argv pattern(s) found
    INFO <command>:1: R-N11: agents never signal processes; ask the operator.

Cause: a false positive on the words "kill switch" in a test name and comment.
No process was signalled and the command was not reformulated (R-N12).
Operator ruling 2026-10-04, verbatim: "Yes, write via the file tool". Since
then every source file is written with the file tool, and "kill switch" is
named "global off switch".

## Provenance of vendored and ported pieces

- ACL types: Jesssullivan/tailnet-acl pull request 37 (typed grants), commit
  b642f33c494b28b7f95939649ac7fc4049519373 (see acl/vendor/tailnet-acl/PIN.md).
  That PR rendered the repo's policy byte-identically to main (sha256
  f13d078fb6cea85f8fe67fb8d4e61b45541ace85d1d8703bfa0404b46981fd6a at main
  1342ef0); `grants.json` stays there as the golden until a follow-up.
- Probe: sanitised port of an internal lab probe backend (pull request 2138,
  head b427e316e231bc72e700944c1d40de8427915ce7, the backend module only),
  renamed to placeholders, with `/v1/surface` added and the tests rewritten as
  stdlib unittest.
- tsidp: latest tag v0.0.15 (commit 437cbaea19c9fa6451292aef1f0ce075b097e5d8),
  image ghcr.io/tailscale/tsidp:v0.0.15 (alpine, entrypoint /tsidp-server).

## Verification run (local)

pnpm install; vitest flags 35, kit 40; python unittest probe 26; both apps
build; Playwright 9 (static, manifest mocked); acl-check (dhall type plus
structure); docker compose config; gitleaks clean; denylist check exercised
with a throwaway local denylist (it caught two real-name hits during
development, now fixed).

## Open items

- ACL checks and the Playwright test are not in CI (need Nix or browsers);
  run them locally via `just acl-check` and `just test-e2e`.
- The `DENYLIST` repository secret must be created for the CI denylist check
  to do anything; without it the step prints a notice and passes.
- Re-pin acl/vendor once tailnet-acl PR 37 merges.
