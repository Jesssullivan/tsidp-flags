# Changelog

## 0.2.0 (2026-10-08)

Toolchain major: SvelteKit 3 and TypeScript 7. The `tsidp_flags` module source
(`packages/flags/src`) is unchanged. Its exports, its resolution table and
Surface v1 are the same as in 0.1.0. The version moves because the supported
stack changed.

### Changed

- Exact pins: `@sveltejs/kit` 3.0.1, `svelte` 5.57.2, `vite` 8.3.3,
  `typescript` 7.0.2, `vitest` 5.0.3, `@playwright/test` 1.64.0.
  Ranges: `@sveltejs/adapter-node` ^6.0.0, `@sveltejs/adapter-static` ^4.0.0.
- Node 22.17 or later (the SvelteKit 3 minimum).
- Type checking runs on TypeScript 7: `tsc` for `packages/flags`, and
  `svelte-check --tsgo --fail-on-warnings` for both apps. CI now runs
  `pnpm -r check`.
- `patches/`, `.pnpmfile.cjs` and the root `pnpm` block carry the shared
  TypeScript 7 patch set for SvelteKit 3.0.1 and svelte-check 4.7.6.
- Dependabot: one weekly grouped npm PR; the exact-pinned stack is excluded.
- `apps/static` checks `BASE_PATH` at build time: it must be empty or start
  with `/` (SvelteKit 3 types `paths.base` that way).
- `apps/static` Playwright reads `E2E_PORT` (default 4173) for its preview
  server.
- Probe tests wait for the access-log line instead of racing the server
  thread, which logs after it writes the body.

### Migration

- Bazel consumers: `bazel_dep(name = "tsidp_flags", version = "0.2.0")`. No
  code change; `npm_link_package(... src = "@tsidp_flags//:pkg")` is the same.
- Apps built from `apps/kit` or `apps/static`:
  - `svelte.config.js` is gone. Its options are now `sveltekit({ ... })`
    options in `vite.config.ts` (`adapter`, `preprocess`, `paths`).
  - `$lib` is gone. Imports use the package.json subpath import
    `#lib/<path>.js` (with the extension).
  - `tsconfig.json` extends `$app/tsconfig` and lists `include` explicitly.
    Under `svelte-check --tsgo`, a tsconfig without `include` checks nothing.
  - The `Handle` type comes from `@sveltejs/kit/hooks`.
  - `apps/kit` declares its environment in `src/env.ts` (`defineEnvVars`)
    and reads it from `$app/env/private`. `$env/dynamic/private` is
    deprecated in SvelteKit 3. Variable names and meanings are unchanged.
  - adapter-node 6 no longer reads the `ORIGIN` variable; set SvelteKit's
    `paths.origin` when the app runs behind a proxy that does not forward the
    original host.

## 0.1.0 (2026-10-07)

First release of the `tsidp_flags` Bazel module.
