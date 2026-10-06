/**
 * cf-session-probe: a browser-side check of whether the visitor already holds a
 * Cloudflare Access session for a gated host.
 *
 * The gated host answers a small JSON route (for example `/access-state.json`
 * returning `{"access": true}`) with exact-origin CORS and credentials allowed.
 * The origin is reachable only through Access, so a readable 200 with that
 * body means Access already let this browser in. Without a session Access
 * answers 302 to its login, which a `redirect: 'manual'` fetch sees as an
 * opaque redirect. Everything else (a CORS refusal, a network error, a
 * timeout, a 404) is an error, and the probe fails closed.
 *
 * The result is a FlagSource of kind 'cf-session-probe'. Its trust is 'hint'
 * and resolve() caps it at 'hint' whatever an adapter claims: the browser
 * observed it and no server verified it. Use it for progressive enhancement
 * only, never for access control.
 *
 * Pure: no DOM. Callers pass `fetch` (and timers in tests).
 */
import type { FlagSource } from './index';

/** Default budget before the probe counts as failed. */
export const CF_SESSION_PROBE_TIMEOUT_MS = 4000;

/**
 * The exact request options. A simple credentialed GET with no custom headers,
 * so the browser sends no preflight, and manual redirects, so Access's login
 * redirect is observable as `opaqueredirect` instead of being followed.
 */
export const CF_SESSION_PROBE_REQUEST: Readonly<RequestInit> = Object.freeze({
	method: 'GET',
	credentials: 'include',
	redirect: 'manual',
	cache: 'no-store',
	referrerPolicy: 'no-referrer',
	mode: 'cors'
});

/** The part of a fetch Response the classifier reads. */
export interface ProbeResponseLike {
	type: string;
	status: number;
	headers: { get(name: string): string | null };
	json(): Promise<unknown>;
}

const JSON_TYPE = /^application\/json\s*(?:;|$)/iu;

const source = (state: FlagSource['state'], claims?: Record<string, boolean>): FlagSource =>
	claims
		? { kind: 'cf-session-probe', trust: 'hint', state, claims }
		: { kind: 'cf-session-probe', trust: 'hint', state };

/**
 * Maps the gated host's answer to a FlagSource. Never rejects.
 * - opaque redirect (Access sends the visitor to its login): settled, absent;
 * - 200 application/json with exactly `access: true`: ok, `{ [flag]: true }`;
 * - anything else: error (fail closed).
 */
export async function classifyCfSession(response: ProbeResponseLike, flag = 'member'): Promise<FlagSource> {
	try {
		if (response.type === 'opaqueredirect') return source('absent');
		if (response.status !== 200) return source('error');
		if (!JSON_TYPE.test(response.headers.get('content-type') ?? '')) return source('error');
		const body: unknown = await response.json();
		if (typeof body === 'object' && body !== null && !Array.isArray(body)) {
			if ((body as { access?: unknown }).access === true) return source('ok', { [flag]: true });
		}
		return source('error');
	} catch {
		return source('error');
	}
}

export interface CfSessionProbeOptions {
	flag?: string;
	timeoutMs?: number;
	fetchImpl?: (input: string, init: RequestInit) => Promise<ProbeResponseLike>;
	setTimer?: (callback: () => void, ms: number) => unknown;
	clearTimer?: (handle: unknown) => void;
}

/**
 * Runs the probe once. Resolves (never rejects) with a 'cf-session-probe'
 * source; a timeout aborts the request and yields error. The timeout is capped
 * at CF_SESSION_PROBE_TIMEOUT_MS.
 */
export async function cfSessionProbe(url: string, options: CfSessionProbeOptions = {}): Promise<FlagSource> {
	const {
		flag = 'member',
		fetchImpl = (input, init) => fetch(input, init),
		setTimer = (cb, ms) => setTimeout(cb, ms),
		clearTimer = (h) => clearTimeout(h as ReturnType<typeof setTimeout>)
	} = options;
	const timeoutMs = Math.min(Math.max(options.timeoutMs ?? CF_SESSION_PROBE_TIMEOUT_MS, 0), CF_SESSION_PROBE_TIMEOUT_MS);
	const controller = new AbortController();
	let timedOut = false;
	let timer: unknown;
	const timeout = new Promise<FlagSource>((ok) => {
		timer = setTimer(() => {
			timedOut = true;
			controller.abort();
			ok(source('error'));
		}, timeoutMs);
	});
	try {
		const answer = (async () => {
			const response = await fetchImpl(url, { ...CF_SESSION_PROBE_REQUEST, signal: controller.signal });
			return timedOut ? source('error') : classifyCfSession(response, flag);
		})().catch(() => source('error'));
		return await Promise.race([answer, timeout]);
	} finally {
		clearTimer(timer);
	}
}
