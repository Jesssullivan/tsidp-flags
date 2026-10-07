// Bazel contract test for tsidp_flags (row TS16). It runs under node:test with
// native type stripping, so it needs no npm packages. The full vitest suite is
// src/resolve.test.ts and runs in the pnpm workspace.
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import { dirname, join } from 'node:path';
import test from 'node:test';
import { fileURLToPath } from 'node:url';

import { MAX_TRUST, parseSurface, resolve, toSurface } from '../src/index.ts';

const root = join(dirname(fileURLToPath(import.meta.url)), '..');

test('MODULE.bazel is the only version site', () => {
	const moduleBazel = readFileSync(join(root, 'MODULE.bazel'), 'utf8');
	const pkg = JSON.parse(readFileSync(join(root, 'package.json'), 'utf8'));
	const match = moduleBazel.match(/module\(\s*name = "tsidp_flags",\s*version = "([^"]+)"/);
	assert.ok(match, 'module() declares tsidp_flags with a version');
	assert.equal(pkg.version, match[1]);
	assert.equal(pkg.name, '@tsidp-flags/flags');
});

test('browser probes are capped at hint', () => {
	assert.equal(MAX_TRUST['tailnet-probe'], 'hint');
	assert.equal(MAX_TRUST['cf-session-probe'], 'hint');
	const r = resolve(
		[{ kind: 'tailnet-probe', trust: 'verified', state: 'ok', claims: { lab: true } }],
		[{ flag: 'lab' }]
	);
	assert.equal(r.flags.lab, false, 'a hint never satisfies a verified rule');
	const h = resolve(
		[{ kind: 'tailnet-probe', trust: 'verified', state: 'ok', claims: { lab: true } }],
		[{ flag: 'lab', minTrust: 'hint' }]
	);
	assert.equal(h.flags.lab, true);
	assert.deepEqual(h.basis, [{ flag: 'lab', source: 'tailnet-probe', trust: 'hint' }]);
});

test('pending fails closed and override false wins', () => {
	const pending = resolve(
		[
			{ kind: 'tsidp-oidc', trust: 'verified', state: 'ok', claims: { lab: true } },
			{ kind: 'tailnet-probe', trust: 'hint', state: 'pending' }
		],
		[{ flag: 'lab' }]
	);
	assert.equal(pending.status, 'pending');
	assert.equal(pending.flags.lab, false);
	const denied = resolve(
		[
			{ kind: 'tsidp-oidc', trust: 'verified', state: 'ok', claims: { lab: true } },
			{ kind: 'override', trust: 'verified', state: 'ok', claims: { lab: false } }
		],
		[{ flag: 'lab' }]
	);
	assert.equal(denied.flags.lab, false);
});

test('Surface v1 round-trips and parseSurface rejects junk', () => {
	const surface = toSurface(
		resolve(
			[{ kind: 'serve-header', trust: 'verified', state: 'ok', claims: { lab: true } }],
			[{ flag: 'lab' }]
		)
	);
	assert.deepEqual(parseSurface(JSON.parse(JSON.stringify(surface))), surface);
	assert.equal(parseSurface(null), null);
	assert.equal(parseSurface({ ...surface, version: 2 }), null);
	assert.equal(parseSurface({ ...surface, flags: { lab: 'yes' } }), null);
	assert.equal(parseSurface({ ...surface, basis: [{ flag: 'lab', source: 'nope', trust: 'hint' }] }), null);
});
