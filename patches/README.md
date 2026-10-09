# TypeScript 7 patch set (RU13)

RU13 (operator ruling, 2026-10-08): the estate runs TypeScript 7.0.2 as the
`typescript` package together with SvelteKit 3.0.1. There is no fallback to
TypeScript 6 as `typescript`. Where a tool needs a change to work with
TypeScript 7, the change is a small patch applied here. site.scaffold is the
home of this patch set; other repos copy `patches/`, `.pnpmfile.cjs` and the
`pnpm` block of `package.json` from site.scaffold `main` instead of writing
their own.

## Why tools need help

TypeScript 7.0.2 is the native (Go) compiler. Its npm package ships `tsc` and
an IPC API under `typescript/unstable/*`, but its main entry point exports only
`{ version, versionMajorMinor }`. Tools that parse TypeScript in-process with
`ts.createSourceFile` (SvelteKit's `svelte-kit sync`, svelte2tsx inside
svelte-check, typescript-eslint) therefore cannot use it. Microsoft publishes
the TypeScript 6 API as [`@typescript/typescript6`](https://www.npmjs.com/package/@typescript/typescript6)
for exactly this case: tools load it beside TypeScript 7. It is a parser and
API library here; nothing type-checks with it.

Type checking runs on TypeScript 7.0.2 everywhere: `svelte-check --tsgo`
(Bazel `//:svelte_check_test`), plain `tsc`, and rules_ts.

## What is applied, and how

| Tool | Mechanism | File |
|---|---|---|
| `@sveltejs/kit` 3.0.1 | pnpm `patchedDependencies` | `@sveltejs__kit@3.0.1.patch` |
| `svelte-check` 4.7.6 | pnpm `patchedDependencies` | `svelte-check@4.7.6.patch` |
| `svelte-check` 4.7.6 (in-process parser) | pnpm `readPackage` hook: peer `typescript` becomes a dependency on the companion | `.pnpmfile.cjs` |
| typescript-eslint 8.71.1 (all `@typescript-eslint/*` that load TS) and `ts-api-utils` | the same hook | `.pnpmfile.cjs` |
| `@sveltejs/kit` 3.0.1 (companion lookup) | pnpm `packageExtensions`: optional peer `@typescript/typescript6` | `package.json` |
| `devalue` 5.9.4 (not TypeScript 7: house rule) | pnpm `patchedDependencies`; the only em dash that survives into the client bundle, caught by `//:leak_scan_test` | `devalue@5.9.4.patch` |

Each `*.patch` file starts with a header naming the upstream repository, the
files and the reason. pnpm applies them at install (`patchedDependencies` in
`package.json`); Bazel applies the same files because `npm_translate_lock`
reads `patchedDependencies` from `pnpm-lock.yaml` and the patch files are in
its `data`.

These packages declare `typescript` as a peer, and pnpm resolves a peer from
the root, where it is 7.0.2. Neither pnpm `overrides` nor `packageExtensions`
can redirect a peer (tested 2026-10-08: both still linked 7.0.2), so
`.pnpmfile.cjs` rewrites those manifests: the `typescript` peer becomes a
dependency on `npm:@typescript/typescript6@6.0.2`. Only the listed packages
see it; the root `typescript` (and every `tsc` binary on the path) stays
7.0.2. pnpm records the rewritten graph and `pnpmfileChecksum` in
`pnpm-lock.yaml`, which is what rules_js reads; the hook file is also in
`npm_translate_lock`'s `data`. The estate manifest (`estate/versions.json`)
keeps `typescript` pinned at 7.0.2 and forbids the `@typescript/native`
alias.

## Gaps (exact)

- **typescript-eslint 8.71.1** declares `typescript >=4.8.4 <6.1.0` and imports
  `typescript` in about 180 modules. There is no TypeScript 7 mode, and
  patching every import is not a minimal change, so its parser runs on the
  companion through the hook above. Lint rules that need type information
  would also run on the companion; the scaffold's ESLint config is not
  type-aware, so no type-aware rule runs today.
- **svelte-check** has no in-process TypeScript 7 path: svelte2tsx needs a JS
  parser. `--tsgo` is the native mode: svelte2tsx output is written to disk and
  TypeScript 7.0.2 (`typescript/bin/tsc`) checks it. Under `--tsgo`, a tsconfig
  without `include` reports 0 errors (sveltejs/language-tools#3136); the
  scaffold's tsconfig lists `include`, and `//:svelte_check_canary_test`
  proves a seeded error still fails.
- **SvelteKit** load-function proxies (automatic types for an unannotated
  `load`) and tsconfig validation need the companion. Without it, the patched
  Kit still writes `$types` and skips only those two steps.
- **@sveltejs/package / svelte2tsx `emitDts`** throw on TypeScript 7. The
  scaffold does not run svelte-package; a repo that does must keep its
  declaration build on the companion until upstream supports TypeScript 7.

## Upstream

`upstream/` holds an upstream-ready diff and a short rationale for each patch.
Never open pull requests or issues on repositories we do not own: upstream
contributions go through the operator (RU13).

## Changing a patch

1. Edit the pristine package copy and regenerate the diff (paths relative to
   the package root, `a/` and `b/` prefixes), keeping the header.
2. Update `patchedDependencies` if the version changes. pnpm fails the install
   when a listed patch matches no installed version, so a version bump without
   a refreshed patch is loud.
3. Regenerate `pnpm-lock.yaml`, then rerun `just check` and the Bazel suite.
4. Mirror the change into `upstream/`.
