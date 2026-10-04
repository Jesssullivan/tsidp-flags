import { describe, expect, it } from 'vitest';
import {
	effectiveTrust,
	parseSurface,
	resolve,
	toSurface,
	type FlagRule,
	type FlagSource
} from './index';

const member: FlagRule = { flag: 'member' };
const hintMember: FlagRule = { flag: 'member', minTrust: 'hint' };

const ok = (
	kind: FlagSource['kind'],
	trust: FlagSource['trust'],
	claims: Record<string, boolean>
): FlagSource => ({ kind, trust, state: 'ok', claims });

describe('resolve: resolution table', () => {
	it('no sources: settled, all false, empty basis', () => {
		expect(resolve([], [member])).toEqual({ flags: { member: false }, basis: [], status: 'settled' });
	});

	it('no rules: nothing can be granted', () => {
		expect(resolve([ok('serve-header', 'verified', { member: true })], []).flags).toEqual({});
	});

	it.each(['serve-header', 'tsidp-oidc', 'cf-access', 'override'] as const)(
		'verified %s grants a verified rule',
		(kind) => {
			const r = resolve([ok(kind, 'verified', { member: true })], [member]);
			expect(r.flags.member).toBe(true);
			expect(r.basis).toEqual([{ flag: 'member', source: kind, trust: 'verified' }]);
			expect(r.status).toBe('settled');
		}
	);

	it.each(['tailnet-probe', 'cf-session-probe'] as const)(
		'hint %s does not grant a verified rule',
		(kind) => {
			const r = resolve([ok(kind, 'hint', { member: true })], [member]);
			expect(r.flags.member).toBe(false);
			expect(r.basis).toEqual([]);
		}
	);

	it.each(['tailnet-probe', 'cf-session-probe'] as const)('hint %s grants a hint rule', (kind) => {
		const r = resolve([ok(kind, 'hint', { member: true })], [hintMember]);
		expect(r.flags.member).toBe(true);
		expect(r.basis[0]).toEqual({ flag: 'member', source: kind, trust: 'hint' });
	});

	it('probes cannot claim verified: trust is capped by kind', () => {
		const forged = ok('tailnet-probe', 'verified', { member: true });
		expect(effectiveTrust(forged)).toBe('hint');
		expect(resolve([forged], [member]).flags.member).toBe(false);
		expect(
			resolve([ok('cf-session-probe', 'verified', { member: true })], [member]).flags.member
		).toBe(false);
	});

	it('a verified source wins over a lacking hint; either order', () => {
		const a = ok('tailnet-probe', 'hint', { member: false });
		const b = ok('tsidp-oidc', 'verified', { member: true });
		expect(resolve([a, b], [member]).flags.member).toBe(true);
		expect(resolve([b, a], [member]).flags.member).toBe(true);
	});

	it('a source that claims false, or omits the flag, grants nothing', () => {
		expect(resolve([ok('tsidp-oidc', 'verified', { member: false })], [member]).flags.member).toBe(
			false
		);
		expect(resolve([ok('tsidp-oidc', 'verified', { other: true })], [member]).flags.member).toBe(
			false
		);
	});

	it('claims for flags with no rule are ignored', () => {
		const r = resolve([ok('tsidp-oidc', 'verified', { member: true, admin: true })], [member]);
		expect(r.flags).toEqual({ member: true });
		expect(Object.hasOwn(r.flags, 'admin')).toBe(false);
	});

	it('rule.kinds restricts which sources may grant', () => {
		const rule: FlagRule = { flag: 'member', kinds: ['tsidp-oidc'] };
		expect(resolve([ok('serve-header', 'verified', { member: true })], [rule]).flags.member).toBe(
			false
		);
		expect(resolve([ok('tsidp-oidc', 'verified', { member: true })], [rule]).flags.member).toBe(
			true
		);
	});

	it('override false is a global off switch even against a verified grant', () => {
		const r = resolve(
			[ok('tsidp-oidc', 'verified', { member: true }), ok('override', 'verified', { member: false })],
			[member]
		);
		expect(r.flags.member).toBe(false);
		expect(r.basis).toEqual([]);
	});

	it('basis lists every granting source', () => {
		const r = resolve(
			[ok('tsidp-oidc', 'verified', { member: true }), ok('cf-access', 'verified', { member: true })],
			[member]
		);
		expect(r.basis.map((b) => b.source)).toEqual(['tsidp-oidc', 'cf-access']);
	});
});

describe('resolve: pending and failure', () => {
	it('any pending source: status pending and every flag false, even if another source grants', () => {
		const r = resolve(
			[
				ok('serve-header', 'verified', { member: true }),
				{ kind: 'tailnet-probe', trust: 'hint', state: 'pending' }
			],
			[member]
		);
		expect(r).toEqual({ flags: { member: false }, basis: [], status: 'pending' });
	});

	it('pending clears to the real answer once settled', () => {
		const settled = resolve(
			[
				ok('serve-header', 'verified', { member: true }),
				{ kind: 'tailnet-probe', trust: 'hint', state: 'absent' }
			],
			[member]
		);
		expect(settled.status).toBe('settled');
		expect(settled.flags.member).toBe(true);
	});

	it('all errored, nothing granted: failed, flags false', () => {
		const r = resolve([{ kind: 'cf-access', trust: 'verified', state: 'error' }], [member]);
		expect(r).toEqual({ flags: { member: false }, basis: [], status: 'failed' });
	});

	it('an errored source does not block a verified grant from another', () => {
		const r = resolve(
			[
				{ kind: 'cf-access', trust: 'verified', state: 'error' },
				ok('tsidp-oidc', 'verified', { member: true })
			],
			[member]
		);
		expect(r.flags.member).toBe(true);
		expect(r.status).toBe('settled');
	});

	it('error state with claims present still grants nothing', () => {
		const r = resolve(
			[{ kind: 'tsidp-oidc', trust: 'verified', state: 'error', claims: { member: true } }],
			[member]
		);
		expect(r.flags.member).toBe(false);
	});

	it('absent sources settle to all false', () => {
		const r = resolve([{ kind: 'serve-header', trust: 'verified', state: 'absent' }], [member]);
		expect(r).toEqual({ flags: { member: false }, basis: [], status: 'settled' });
	});

	it('unknown source kinds are ignored, fail closed', () => {
		const bogus = {
			kind: 'cookie-says-so',
			trust: 'verified',
			state: 'ok',
			claims: { member: true }
		} as unknown as FlagSource;
		expect(resolve([bogus], [member]).flags.member).toBe(false);
	});

	it('inherited object keys are not claims', () => {
		const s = ok(
			'tsidp-oidc',
			'verified',
			Object.create({ member: true }) as Record<string, boolean>
		);
		expect(resolve([s], [member]).flags.member).toBe(false);
	});
});

describe('surface (manifest) round trip', () => {
	it('toSurface then parseSurface is lossless', () => {
		const surface = toSurface(resolve([ok('tsidp-oidc', 'verified', { member: true })], [member]));
		expect(parseSurface(JSON.parse(JSON.stringify(surface)))).toEqual(surface);
	});

	it.each([
		null,
		42,
		'x',
		{},
		{ version: 2, flags: {}, basis: [], status: 'settled' },
		{ version: 1, flags: { member: 'yes' }, basis: [], status: 'settled' },
		{ version: 1, flags: [], basis: [], status: 'settled' },
		{ version: 1, flags: {}, basis: [], status: 'ready' },
		{
			version: 1,
			flags: {},
			basis: [{ flag: 'm', source: 'nope', trust: 'verified' }],
			status: 'settled'
		}
	])('rejects malformed manifest %#', (value) => {
		expect(parseSurface(value)).toBeNull();
	});
});
