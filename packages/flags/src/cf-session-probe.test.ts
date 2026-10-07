import { describe, expect, it } from 'vitest';
import {
	CF_SESSION_PROBE_REQUEST,
	CF_SESSION_PROBE_TIMEOUT_MS,
	cfSessionProbe,
	classifyCfSession,
	type ProbeResponseLike
} from './cf-session-probe';
import { resolve, type FlagSource } from './index';

const URL_ = 'https://gated.example.org/access-state.json';

const res = (o: Partial<ProbeResponseLike> & { body?: unknown; contentType?: string | null } = {}): ProbeResponseLike => ({
	type: o.type ?? 'cors',
	status: o.status ?? 200,
	headers: { get: (n: string) => (n.toLowerCase() === 'content-type' ? (o.contentType === undefined ? 'application/json' : o.contentType) : null) },
	json: async () => {
		if (o.body instanceof Error) throw o.body;
		return o.body === undefined ? { access: true } : o.body;
	}
});

describe('cf-session-probe classifier', () => {
	it('200 JSON {access: true} is ok with the flag, at hint trust', async () => {
		expect(await classifyCfSession(res())).toEqual({
			kind: 'cf-session-probe',
			trust: 'hint',
			state: 'ok',
			claims: { member: true }
		});
		expect((await classifyCfSession(res(), 'beta')).claims).toEqual({ beta: true });
		expect((await classifyCfSession(res({ contentType: 'application/json; charset=utf-8' }))).state).toBe('ok');
	});

	it('an opaque redirect (Access login) is settled and absent', async () => {
		expect(await classifyCfSession(res({ type: 'opaqueredirect', status: 0 }))).toEqual({
			kind: 'cf-session-probe',
			trust: 'hint',
			state: 'absent'
		});
	});

	it.each([
		['404', { status: 404 }],
		['500', { status: 500 }],
		['non-JSON type', { contentType: 'text/html' }],
		['missing type', { contentType: null }],
		['access false', { body: { access: false } }],
		['access "true" string', { body: { access: 'true' } }],
		['array body', { body: [true] }],
		['bad JSON', { body: new Error('bad json') }]
	])('%s is an error (fail closed)', async (_name, o) => {
		expect((await classifyCfSession(res(o as never))).state).toBe('error');
	});
});

describe('cf-session-probe request', () => {
	it('sends a credentialed, manual-redirect, no-store simple GET', async () => {
		let seen: RequestInit | undefined;
		let seenUrl = '';
		await cfSessionProbe(URL_, {
			fetchImpl: async (u, init) => {
				seenUrl = u;
				seen = init;
				return res();
			}
		});
		expect(seenUrl).toBe(URL_);
		expect(seen).toMatchObject({
			method: 'GET',
			credentials: 'include',
			redirect: 'manual',
			cache: 'no-store',
			referrerPolicy: 'no-referrer',
			mode: 'cors'
		});
		expect(seen?.signal).toBeInstanceOf(AbortSignal);
		expect('headers' in CF_SESSION_PROBE_REQUEST).toBe(false);
		expect(Object.isFrozen(CF_SESSION_PROBE_REQUEST)).toBe(true);
	});

	it('a network error is an error source, never a rejection', async () => {
		const s = await cfSessionProbe(URL_, {
			fetchImpl: async () => {
				throw new TypeError('Failed to fetch');
			}
		});
		expect(s.state).toBe('error');
	});

	it('times out at the budget, aborts the request, and caps the budget at 4s', async () => {
		let fire: (() => void) | undefined;
		let asked = -1;
		let aborted = false;
		const p = cfSessionProbe(URL_, {
			timeoutMs: 60_000,
			setTimer: (cb, ms) => {
				fire = cb;
				asked = ms;
				return 1;
			},
			clearTimer: () => {},
			fetchImpl: (_u, init) =>
				new Promise((_ok, fail) => {
					init.signal?.addEventListener('abort', () => {
						aborted = true;
						fail(new DOMException('aborted', 'AbortError'));
					});
				})
		});
		expect(asked).toBe(CF_SESSION_PROBE_TIMEOUT_MS);
		expect(CF_SESSION_PROBE_TIMEOUT_MS).toBe(4000);
		fire?.();
		expect((await p).state).toBe('error');
		expect(aborted).toBe(true);
	});
});

describe('cf-session-probe in resolve(): capped at hint', () => {
	it('grants only a hint-tier rule, even if an adapter claims verified', () => {
		const claimed: FlagSource = { kind: 'cf-session-probe', trust: 'verified', state: 'ok', claims: { member: true } };
		expect(resolve([claimed], [{ flag: 'member' }]).flags.member).toBe(false);
		expect(resolve([claimed], [{ flag: 'member', minTrust: 'hint' }])).toEqual({
			flags: { member: true },
			basis: [{ flag: 'member', source: 'cf-session-probe', trust: 'hint' }],
			status: 'settled'
		});
	});
});
