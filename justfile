# tsidp-flags. Run `just` for the list. Use `nix develop` for the toolchain.
set shell := ["bash", "-euo", "pipefail", "-c"]

default:
    @just --list

install:
    pnpm install --frozen-lockfile

# Unit tests: flags (vitest), kit (vitest), probe (unittest)
test: test-flags test-kit test-probe

test-flags:
    pnpm --filter @tsidp-flags/flags test

test-kit:
    pnpm --filter @tsidp-flags/kit test

test-probe:
    python3 -m unittest discover -s probe -p 'test_*.py'

# Playwright test for the static app (needs browsers: pnpm --filter @tsidp-flags/static exec playwright install chromium)
test-e2e:
    pnpm --filter @tsidp-flags/static test:e2e

build:
    pnpm --filter @tsidp-flags/kit build
    pnpm --filter @tsidp-flags/static build

check:
    pnpm -r --if-present check

# Render the example ACL and run structural checks. No network, no tailnet.
acl-build:
    python3 acl/build.py

acl-check: acl-build
    dhall type --file acl/policy.dhall > /dev/null
    python3 acl/check.py generated/policy.json

# STUB: dry run unless CONFIRM_APPLY=apply-<TAILNET> and ACL_API_KEY_FILE are set.
acl-apply:
    bash acl/apply.sh

# Fails if a denylisted token appears. DENYLIST (env) or untracked .denylist.
denylist:
    bash scripts/denylist-check.sh

secrets-scan:
    gitleaks detect --no-banner --redact
