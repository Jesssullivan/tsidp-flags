import { render } from 'svelte/server';
import { describe, expect, it } from 'vitest';
import type { FlagSource } from '@tsidp-flags/flags';
import { load } from './+layout.server';
import { GET as gated } from './api/gated/+server';
import Page from './+page.svelte';

const member: FlagSource = { kind: 'serve-header', trust: 'verified', state: 'ok', claims: { member: true } };
const hintOnly: FlagSource = { kind: 'tailnet-probe', trust: 'hint', state: 'ok', claims: { member: true } };
const none: FlagSource = { kind: 'serve-header', trust: 'verified', state: 'absent' };

// Cast: the handlers only read locals.sources.
const event = (sources: FlagSource[]) => ({ locals: { sources } }) as never;

describe('+layout.server load', () => {
	it('returns flags, basis and status, and nothing about identity', () => {
		const data = load(event([member])) as Record<string, unknown>;
		expect(Object.keys(data).sort()).toEqual(['basis', 'flags', 'status']);
		expect(data.flags).toEqual({ member: true });
	});
});

describe('gated /api/gated', () => {
	it('403 without a verified flag', async () => {
		const res = await gated(event([none]));
		expect(res.status).toBe(403);
		expect(res.headers.get('cache-control')).toBe('no-store');
		expect(await res.json()).toEqual({ error: 'forbidden' });
	});

	it('403 for a hint-only source claiming member', async () => {
		expect((await gated(event([hintOnly]))).status).toBe(403);
	});

	it('403 with no sources and when a source errored', async () => {
		expect((await gated(event([]))).status).toBe(403);
		expect((await gated(event([{ kind: 'cf-access', trust: 'verified', state: 'error' }]))).status).toBe(403);
	});

	it('200 with a verified member', async () => {
		const res = await gated(event([member]));
		expect(res.status).toBe(200);
		expect(await res.json()).toEqual({ data: 'members only' });
	});
});

describe('SSR never emits gated markup without the flag', () => {
	const html = (flags: Record<string, boolean>) =>
		render(Page, { props: { data: { flags, basis: [], status: 'settled' } } }).body;

	it('anonymous: no gated node and no member copy in the HTML', () => {
		const out = html({ member: false });
		expect(out).not.toContain('data-gated');
		expect(out).not.toContain('Members only');
		expect(out).toContain('This part is public.');
	});

	it('member: gated section is present', () => {
		const out = html({ member: true });
		expect(out).toContain('data-gated="member"');
		expect(out).toContain('Members only');
	});
});
