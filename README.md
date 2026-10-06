# tsidp-flags

A reference stack for turning "who is this visitor, as far as my tailnet and my
edge can tell" into boolean **flags** that a web app can render against, with
explicit trust tiers and a fail-closed resolver.

Every name here is a placeholder (`example.ts.net`, `you@example.com`,
`example.org`). `scripts/denylist-check.sh` fails CI if tokens from a private,
untracked denylist appear anywhere.

##  Tiers

| Signal | How it arrives | Trust |
| --- | --- | --- |
| Tailnet identity | Tailscale Serve headers (`Tailscale-User-Login`, app capabilities), honored only from the configured proxy address | verified |
| tsidp OIDC | Authorization code flow with PKCE against your tsidp node; result in a signed HttpOnly session cookie | verified |
| Cloudflare Access | `Cf-Access-Jwt-Assertion` verified against the team JWKS (`jose`) | verified |
| Tailnet probe | A public page fetches the probe's `/v1/surface` (or `/probe.svg`) from the member's browser | hint |
| Cloudflare session probe | Browser-side check of an Access session | hint |
| Override | Operator-set flag; `false` is a global off switch | verified |

- **hint**: a browser-side observation. Fine for progressive enhancement on a static page, never for access control. `resolve()` caps probe sources at `hint` no matter what an adapter claims.

## Layout

| Path | What |
| --- | --- |
| `packages/flags` | TypeScript contract: `FlagSource`, `FlagRule`, `resolve(sources, rules) -> { flags, basis, status }`. Fails closed; `pending` until every source has settled. vitest covers the resolution table. |
| `acl/` | Example tailnet policy (Dhall) on tailnet-acl's typed grants, vendored at a pinned commit (`acl/vendor/tailnet-acl/PIN.md`): `group:flag-members`, `tag:flag-probe`, `tag:flag-idp`, the probe capability and the tsidp rule. |
| `probe/` | Python stdlib probe backend: `/probe.svg`, `/v1/tailnet`, `/v1/surface`, exact-origin CORS from env, `no-store`, one-user-plus-capability decision, node guard (no Funnel, one tag). |
| `idp/` | Compose service for tsidp pinned to `v0.0.15`, flags in argv, state volume, auth key from a file secret. |
| `apps/kit` | SvelteKit full stack. `hooks.server.ts` builds `FlagSource[]` from three adapters; `+layout.server.ts` returns `flags` and `basis`; the page uses `{#if data.flags.member}` so SSR never emits gated markup; `/api/gated` returns 403 without a verified flag. |
| `apps/static` | SvelteKit adapter-static for GitHub Pages. `GatedSlot` fetches the manifest from the probe or kit origin and renders nothing on failure or while pending. Playwright test with the manifest mocked. |

## Quickstart

```sh
nix develop            # node 22, pnpm, dhall, python3, just, gitleaks
cp .env.example .env   # placeholders; fill in locally, never commit
just install
just test              # flags (vitest), kit (vitest), probe (unittest)
just build             # kit and static
just acl-check         # render the example policy and run structural checks
```

Browser test for the static app (one-time browser install, then run):

```sh
pnpm --filter @tsidp-flags/static exec playwright install chromium
just test-e2e
```

### ACL

`just acl-build` renders `generated/policy.json` from `acl/policy.dhall`;
`just acl-check` type-checks it and asserts structure (admin-owned tags, Funnel
only on the idp tag, probe and tsidp capability grants present).

`just acl-apply` is a **stub**: it prints a dry run unless
`CONFIRM_APPLY=apply-<TAILNET>` equals the tailnet it targets, and then reads
the API key from the file named by `ACL_API_KEY_FILE` (handed to curl on stdin,
never argv or env). Review the diff against the live policy first. Nothing in
CI runs it.

### tsidp

```sh
mkdir -p secrets && install -m 600 /dev/null secrets/tsidp-authkey   # paste a tag:flag-idp auth key into it
docker compose up idp
```

`TAILSCALE_USE_WIP_CODE=1` is set in the compose file and is required while
tsidp is below v1.0.0. The auth key is only needed for first registration.
After tsidp is up, register your kit as a client, point `OIDC_ISSUER` at it,
and members receive `flag_member: "true"` through the `extraClaims` grant in
the ACL.

Optional: `docker compose --profile tagged-identity up --build idp-tagged`
builds tsidp from upstream `8fa860f` with a patch that lets a grant's
`taggedIdentity` sign in a tagged device. Pin, sanitisation and BSD 3-Clause
licensing notes are in [idp/tagged/README.md](idp/tagged/README.md).

### Probe

Runs on its own tailnet node (tag `tag:flag-probe`) behind
`tailscale serve --https=443 --accept-app-caps=example.org/cap/flag-probe`,
binding loopback only. Configure with env: `ALLOWED_ORIGIN` (one exact origin),
`PROBE_CAPABILITY`, `PROBE_TAG`, `TAILSCALE_BIN`, `TAILSCALE_SOCKET`.
`python3 probe/backend.py --guard-once` exits 0 only if the node is Running with
exactly its one tag and no Funnel. Tagged devices get a yes through the WhoIs
device path; a refused start exits 78. See [probe/README.md](probe/README.md).

## Behavior to know

- `resolve()` returns every flag `false` while any source is `pending`, and `status: "failed"` when nothing was granted and a source errored. A UI should render nothing gated for either.
- An `override` source claiming `false` wins over every grant. `override: on` is ignored when `NODE_ENV=production`.
- `cfSessionProbe(url)` in `@tsidp-flags/flags` asks a Cloudflare Access gated host's JSON route (for example `{"access": true}` at `/access-state.json`) with a credentialed, manual-redirect, 4 second GET. An opaque redirect (Access login) is `absent`, the exact body is `ok`, and anything else is `error`. Its source kind `cf-session-probe` is capped at `hint`.
- Serve headers count only when the TCP peer equals `TRUSTED_PROXY_ADDR`; an IPv4-mapped peer (`::ffff:127.0.0.1`) matches the IPv4 address. If adapter-node's `ADDRESS_HEADER` is set, the peer address is itself a request header, so the serve-header source refuses with `error` rather than trusting it.
- Cloudflare Access is read from the `Cf-Access-Jwt-Assertion` header or, when that is absent, the `CF_Authorization` cookie. Both are verified the same way.
- The OIDC discovery document (10 minute TTL) and each remote JWKS are cached per process, so sign-ins do not refetch them.
- On https the session cookie is `__Host-flags_session` (Secure, Path=/, no Domain); plain http keeps `flags_session`. Rotation: changing `SESSION_SECRET` signs everyone out, because old cookies stop verifying. Deploying the `__Host-` rename has the same effect once, because the old name is no longer read. Logout clears both names.
- The kit's `/api/surface` serves the manifest to a static origin set by `STATIC_ORIGIN` (exact match, no credentials), so it reflects serve-header and Cloudflare Access signals, not the same-site OIDC cookie.

Manifest contracts: Surface v1 is implemented; a production "items" shape is
documented as **proposed** in [docs/contracts.md](docs/contracts.md).

## CI

`.github/workflows/ci.yml`: install, vitest (flags, kit), probe unittest,
`just acl-check` (dhall and dhall-json release binaries pinned by sha256),
`docker compose config` for the default and `tagged-identity` profiles, build
both apps, the Playwright test for the static app (Chromium), gitleaks, denylist
check (`DENYLIST` repository secret). Locally: `just test-e2e`.

## Bazel module

`packages/flags` is also the Bazel module `tsidp_flags` (`MODULE.bazel`,
`BUILD.bazel`). `//:flags` is a `js_library` of the TypeScript source,
`//:pkg` is the `npm_package` a consumer links, and `//:contract_test` runs a
`node:test` contract check with native type stripping, so the module needs no
npm packages. `MODULE.bazel` is the only version site; the test holds
`package.json` to it. `.github/workflows/bazel.yml` runs
`bazelisk mod graph --lockfile_mode=error` and `bazelisk test //...` in
`packages/flags`.

The registry entry lives in `xoxd-ai/bazel-registry` under
`modules/tsidp_flags/<version>/`, sourced from a GitHub tag archive with
`strip_prefix` pointing at `packages/flags`:

```starlark
bazel_dep(name = "tsidp_flags", version = "0.1.0")
npm_link_package(name = "node_modules/@tsidp-flags/flags", src = "@tsidp_flags//:pkg")
```

It is never published to a package registry. The probes are hint-tier
progressive enhancement only, never an access gate.

## Dependency hygiene

- `flake.lock` pins nixpkgs for `nix develop`. Refresh it with `nix flake update`
  in its own PR.
- `.github/dependabot.yml` opens weekly grouped PRs for the pnpm workspace and
  for GitHub Actions. SvelteKit and its adapters stay on 2.x, and vitest and
  TypeScript majors are ignored, so a major move is a deliberate PR.
- Dependabot security alerts are a repository setting (Settings > Code security).

## License

MIT.
