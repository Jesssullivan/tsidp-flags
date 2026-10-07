import { jwtVerify, type JWTVerifyGetKey } from 'jose';
import type { FlagSource } from '@tsidp-flags/flags';
import type { Config } from './config';
import { remoteJwks } from './oidc';
import { verifySession } from './session';

export interface Runtime {
	config: Config;
	/** Verification keys for Cloudflare Access; null when cf-access is not configured. */
	cfKey: JWTVerifyGetKey | null;
}

export function makeRuntime(config: Config): Runtime {
	return {
		config,
		cfKey: config.cfAccess
			? remoteJwks(`https://${config.cfAccess.teamDomain}/cdn-cgi/access/certs`)
			: null
	};
}

const absent = (kind: FlagSource['kind']): FlagSource => ({ kind, trust: 'verified', state: 'absent' });
const failed = (kind: FlagSource['kind']): FlagSource => ({ kind, trust: 'verified', state: 'error' });

/**
 * The IPv4 form of an IPv4-mapped IPv6 address (`::ffff:127.0.0.1` ->
 * `127.0.0.1`), so a dual-stack listener still matches an IPv4
 * TRUSTED_PROXY_ADDR. Any other address is returned trimmed and lowercased.
 */
export function normalizeAddr(addr: string): string {
	const a = addr.trim().toLowerCase();
	return a.startsWith('::ffff:') && a.includes('.') ? a.slice('::ffff:'.length) : a;
}

/**
 * Tailscale Serve identity headers, trusted only when the TCP peer is the
 * configured proxy address. Any other peer: the headers are ignored entirely
 * (anyone can send a header; only the proxy overwrites it). Duplicate headers
 * are ambiguous and count as no signal. With ADDRESS_HEADER set the "peer" is
 * itself a request header, so the source refuses (error) instead of trusting it.
 */
export function serveHeaderSource(headers: Headers, peerAddr: string | null, cfg: Config): FlagSource {
	if (!cfg.trustedProxyAddr) return absent('serve-header');
	if (cfg.addressHeader) return failed('serve-header');
	if (!peerAddr || normalizeAddr(peerAddr) !== normalizeAddr(cfg.trustedProxyAddr)) return absent('serve-header');
	const login = headers.get('tailscale-user-login')?.trim();
	const caps = headers.get('tailscale-app-capabilities');
	if (!login || login.includes(',') || !caps) return absent('serve-header');
	try {
		const granted: unknown = JSON.parse(caps);
		const rules =
			typeof granted === 'object' && granted !== null && !Array.isArray(granted)
				? (granted as Record<string, unknown>)[cfg.capability]
				: undefined;
		const member = Array.isArray(rules) && rules.length > 0;
		return { kind: 'serve-header', trust: 'verified', state: 'ok', claims: { member } };
	} catch {
		return absent('serve-header');
	}
}

/** tsidp OIDC login, carried as a signed HttpOnly session cookie this app issued. */
export async function tsidpSource(cookie: string | undefined, cfg: Config): Promise<FlagSource> {
	if (!cfg.oidc || !cookie) return absent('tsidp-oidc');
	if (!cfg.sessionSecret) return failed('tsidp-oidc');
	const session = await verifySession(cfg.sessionSecret, cookie);
	if (!session) return absent('tsidp-oidc'); // expired or tampered: not signed in
	return { kind: 'tsidp-oidc', trust: 'verified', state: 'ok', claims: { member: session.member } };
}

/**
 * Cloudflare Access JWT, from the Cf-Access-Jwt-Assertion header or else the
 * CF_Authorization cookie, verified against the team JWKS either way.
 */
export async function cfAccessSource(
	jwt: string | null,
	rt: Pick<Runtime, 'config' | 'cfKey'>
): Promise<FlagSource> {
	const cf = rt.config.cfAccess;
	if (!cf || !jwt) return absent('cf-access');
	if (!rt.cfKey) return failed('cf-access');
	try {
		const { payload } = await jwtVerify(jwt, rt.cfKey, {
			issuer: `https://${cf.teamDomain}`,
			audience: cf.aud
		});
		const email = typeof payload.email === 'string' ? payload.email.toLowerCase() : '';
		return {
			kind: 'cf-access',
			trust: 'verified',
			state: 'ok',
			claims: { member: email !== '' && rt.config.memberEmails.includes(email) }
		};
	} catch {
		return failed('cf-access');
	}
}

export function overrideSource(cfg: Config): FlagSource | null {
	return cfg.override
		? { kind: 'override', trust: 'verified', state: 'ok', claims: { member: cfg.override === 'on' } }
		: null;
}

export interface RequestInput {
	headers: Headers;
	peerAddr: string | null;
	sessionCookie: string | undefined;
	/** CF_Authorization cookie; used only when the Cf-Access-Jwt-Assertion header is absent. */
	cfCookie?: string;
}

/** One FlagSource per adapter; an adapter that throws becomes an error source (fail closed). */
export async function buildSources(input: RequestInput, rt: Runtime): Promise<FlagSource[]> {
	const guard = async (kind: FlagSource['kind'], f: () => FlagSource | Promise<FlagSource>) => {
		try {
			return await f();
		} catch {
			return failed(kind);
		}
	};
	const sources = await Promise.all([
		guard('serve-header', () => serveHeaderSource(input.headers, input.peerAddr, rt.config)),
		guard('tsidp-oidc', () => tsidpSource(input.sessionCookie, rt.config)),
		guard('cf-access', () =>
			cfAccessSource(input.headers.get('cf-access-jwt-assertion') ?? input.cfCookie ?? null, rt)
		)
	]);
	const override = overrideSource(rt.config);
	return override ? [...sources, override] : sources;
}
