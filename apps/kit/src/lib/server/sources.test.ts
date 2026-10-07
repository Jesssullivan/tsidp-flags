import { createServer, type Server } from 'node:http';
import type { AddressInfo } from 'node:net';
import { SignJWT, createRemoteJWKSet, exportJWK, generateKeyPair, type JWK } from 'jose';
import { afterAll, beforeAll, describe, expect, it } from 'vitest';
import { resolve } from '@tsidp-flags/flags';
import { RULES } from '../rules';
import { loadConfig, type Config } from './config';
import { signSession } from './session';
import { buildSources, cfAccessSource, normalizeAddr, serveHeaderSource, tsidpSource } from './sources';

const SECRET = Buffer.alloc(32, 7).toString('base64');
const CAP = 'example.org/cap/flag-probe';
const PROXY = '100.64.0.9';

const base = {
	OIDC_ISSUER: 'https://idp.example.ts.net',
	OIDC_CLIENT_ID: 'flags-kit',
	OIDC_REDIRECT_URI: 'https://kit.example.org/auth/callback',
	SESSION_SECRET: SECRET,
	TRUSTED_PROXY_ADDR: PROXY,
	PROBE_CAPABILITY: CAP,
	CF_ACCESS_TEAM_DOMAIN: 'example.cloudflareaccess.com',
	CF_ACCESS_AUD: 'aud-1',
	FLAG_MEMBER_EMAILS: 'you@example.com'
};
const cfg = (extra: Record<string, string> = {}): Config => loadConfig({ ...base, ...extra });

const headers = (h: Record<string, string>) => new Headers(h);
const MEMBER_HEADERS = {
	'tailscale-user-login': 'you@example.com',
	'tailscale-app-capabilities': JSON.stringify({ [CAP]: [{ member: true }] })
};

describe('serve-header source: trusted only from the configured proxy', () => {
	it('grants member from the trusted proxy with login and capability', () => {
		const s = serveHeaderSource(headers(MEMBER_HEADERS), PROXY, cfg());
		expect(s).toMatchObject({ kind: 'serve-header', trust: 'verified', state: 'ok', claims: { member: true } });
	});

	it('ignores the same headers from any other peer', () => {
		expect(serveHeaderSource(headers(MEMBER_HEADERS), '203.0.113.5', cfg()).state).toBe('absent');
		expect(serveHeaderSource(headers(MEMBER_HEADERS), null, cfg()).state).toBe('absent');
	});

	it('trusts nothing when no proxy address is configured', () => {
		const c = loadConfig({ ...base, TRUSTED_PROXY_ADDR: '' });
		expect(serveHeaderSource(headers(MEMBER_HEADERS), PROXY, c).state).toBe('absent');
	});

	it('login without the capability is not a member', () => {
		const h = { ...MEMBER_HEADERS, 'tailscale-app-capabilities': JSON.stringify({ 'other/cap/x': [{}] }) };
		expect(serveHeaderSource(headers(h), PROXY, cfg()).claims).toEqual({ member: false });
		const empty = { ...MEMBER_HEADERS, 'tailscale-app-capabilities': JSON.stringify({ [CAP]: [] }) };
		expect(serveHeaderSource(headers(empty), PROXY, cfg()).claims).toEqual({ member: false });
	});

	it('an IPv4-mapped IPv6 peer matches the IPv4 proxy address, either way round', () => {
		expect(normalizeAddr('::ffff:100.64.0.9')).toBe(PROXY);
		expect(normalizeAddr('::FFFF:100.64.0.9')).toBe(PROXY);
		expect(normalizeAddr('fd7a:115c:a1e0::9')).toBe('fd7a:115c:a1e0::9');
		expect(serveHeaderSource(headers(MEMBER_HEADERS), `::ffff:${PROXY}`, cfg()).claims).toEqual({ member: true });
		const mappedCfg = cfg({ TRUSTED_PROXY_ADDR: `::ffff:${PROXY}` });
		expect(serveHeaderSource(headers(MEMBER_HEADERS), PROXY, mappedCfg).claims).toEqual({ member: true });
		expect(serveHeaderSource(headers(MEMBER_HEADERS), '::ffff:203.0.113.5', cfg()).state).toBe('absent');
	});

	it('refuses (error) when ADDRESS_HEADER is set, even from the proxy address', () => {
		const c = cfg({ ADDRESS_HEADER: 'x-forwarded-for' });
		expect(c.addressHeader).toBe('x-forwarded-for');
		expect(serveHeaderSource(headers(MEMBER_HEADERS), PROXY, c)).toMatchObject({ kind: 'serve-header', state: 'error' });
		expect(resolve([serveHeaderSource(headers(MEMBER_HEADERS), PROXY, c)], RULES)).toMatchObject({
			flags: { member: false },
			status: 'failed'
		});
	});

	it('ADDRESS_HEADER without a trusted proxy configured is simply no signal', () => {
		const c = loadConfig({ ...base, TRUSTED_PROXY_ADDR: '', ADDRESS_HEADER: 'x-forwarded-for' });
		expect(serveHeaderSource(headers(MEMBER_HEADERS), PROXY, c).state).toBe('absent');
	});

	it('missing login, malformed or duplicated capability headers are no signal', () => {
		expect(serveHeaderSource(headers({ 'tailscale-app-capabilities': '{}' }), PROXY, cfg()).state).toBe('absent');
		expect(
			serveHeaderSource(headers({ ...MEMBER_HEADERS, 'tailscale-app-capabilities': 'not json' }), PROXY, cfg()).state
		).toBe('absent');
		const dup = new Headers(MEMBER_HEADERS);
		dup.append('tailscale-app-capabilities', JSON.stringify({ [CAP]: [{}] }));
		expect(serveHeaderSource(dup, PROXY, cfg()).state).toBe('absent');
		const twoLogins = new Headers(MEMBER_HEADERS);
		twoLogins.append('tailscale-user-login', 'x@example.com');
		expect(serveHeaderSource(twoLogins, PROXY, cfg()).state).toBe('absent');
	});
});

describe('tsidp-oidc source: signed HttpOnly session cookie', () => {
	const secret = new Uint8Array(Buffer.from(SECRET, 'base64'));

	it('a valid member session grants member', async () => {
		const token = await signSession(secret, { member: true, sub: 'you@example.com' });
		expect(await tsidpSource(token, cfg())).toMatchObject({ state: 'ok', claims: { member: true } });
	});

	it('a valid non-member session is ok but false', async () => {
		const token = await signSession(secret, { member: false, sub: 'x@example.com' });
		expect(await tsidpSource(token, cfg())).toMatchObject({ state: 'ok', claims: { member: false } });
	});

	it('tampered, foreign-key and expired cookies are not signed in', async () => {
		const good = await signSession(secret, { member: true, sub: 'a' });
		const [h, p, s] = good.split('.');
		const forgedPayload = Buffer.from(JSON.stringify({ member: true, sub: 'a', iss: 'flags-kit', aud: 'session' })).toString('base64url');
		expect((await tsidpSource(`${h}.${forgedPayload}.${s}`, cfg())).state).toBe('absent');
		const other = await signSession(new Uint8Array(32).fill(1), { member: true, sub: 'a' });
		expect((await tsidpSource(other, cfg())).state).toBe('absent');
		const expired = await signSession(secret, { member: true, sub: 'a' }, 60, 1_000);
		expect((await tsidpSource(expired, cfg())).state).toBe('absent');
		expect(p).toBeTruthy();
	});

	it('no cookie, or OIDC not configured: absent; no session secret: error', async () => {
		expect((await tsidpSource(undefined, cfg())).state).toBe('absent');
		expect((await tsidpSource('x', loadConfig({}))).state).toBe('absent');
		const noSecret = loadConfig({ ...base, SESSION_SECRET: 'short' });
		expect((await tsidpSource('x', noSecret)).state).toBe('error');
	});
});

describe('cf-access source against a fake JWKS served over http', () => {
	let server: Server;
	let jwksUrl: URL;
	let privateKey: CryptoKey;
	let strangerKey: CryptoKey;
	const kid = 'test-key-1';

	beforeAll(async () => {
		const pair = await generateKeyPair('ES256');
		privateKey = pair.privateKey as CryptoKey;
		strangerKey = (await generateKeyPair('ES256')).privateKey as CryptoKey;
		const jwk: JWK = { ...(await exportJWK(pair.publicKey)), kid, alg: 'ES256', use: 'sig' };
		server = createServer((_req, res) => {
			res.setHeader('content-type', 'application/json');
			res.end(JSON.stringify({ keys: [jwk] }));
		});
		await new Promise<void>((ok) => server.listen(0, '127.0.0.1', ok));
		jwksUrl = new URL(`http://127.0.0.1:${(server.address() as AddressInfo).port}/cdn-cgi/access/certs`);
	});
	afterAll(() => new Promise<void>((ok) => server.close(() => ok())));

	const jwt = (claims: Record<string, unknown>, key = privateKey, opts: { iss?: string; aud?: string; exp?: string } = {}) =>
		new SignJWT(claims)
			.setProtectedHeader({ alg: 'ES256', kid })
			.setIssuer(opts.iss ?? 'https://example.cloudflareaccess.com')
			.setAudience(opts.aud ?? 'aud-1')
			.setIssuedAt()
			.setExpirationTime(opts.exp ?? '5m')
			.sign(key);

	const rt = () => ({ config: cfg(), cfKey: createRemoteJWKSet(jwksUrl) });

	it('a valid token for a listed email grants member', async () => {
		const s = await cfAccessSource(await jwt({ email: 'You@Example.com' }), rt());
		expect(s).toMatchObject({ kind: 'cf-access', trust: 'verified', state: 'ok', claims: { member: true } });
	});

	it('a valid token for an unlisted email is ok but not a member', async () => {
		const s = await cfAccessSource(await jwt({ email: 'other@example.com' }), rt());
		expect(s).toMatchObject({ state: 'ok', claims: { member: false } });
	});

	it.each([
		['wrong audience', { aud: 'other' }],
		['wrong issuer', { iss: 'https://evil.example.com' }],
		['expired', { exp: '-1m' }]
	])('rejects a token with %s', async (_name, opts) => {
		const s = await cfAccessSource(await jwt({ email: 'you@example.com' }, privateKey, opts), rt());
		expect(s.state).toBe('error');
	});

	it('rejects a token signed by a different key', async () => {
		const s = await cfAccessSource(await jwt({ email: 'you@example.com' }, strangerKey), rt());
		expect(s.state).toBe('error');
	});

	it('rejects garbage and an unsigned (alg none) token', async () => {
		expect((await cfAccessSource('not.a.jwt', rt())).state).toBe('error');
		const none = `${Buffer.from('{"alg":"none"}').toString('base64url')}.${Buffer.from('{"email":"you@example.com"}').toString('base64url')}.`;
		expect((await cfAccessSource(none, rt())).state).toBe('error');
	});

	it('no header: absent; not configured: absent', async () => {
		expect((await cfAccessSource(null, rt())).state).toBe('absent');
		expect((await cfAccessSource('x', { config: loadConfig({}), cfKey: null })).state).toBe('absent');
	});

	it('end to end: buildSources then resolve gates on the verified result', async () => {
		const good = await jwt({ email: 'you@example.com' });
		const run = (h: Record<string, string>) =>
			buildSources({ headers: headers(h), peerAddr: '203.0.113.5', sessionCookie: undefined }, rt());
		expect(resolve(await run({ 'cf-access-jwt-assertion': good }), RULES).flags.member).toBe(true);
		expect(resolve(await run({ 'cf-access-jwt-assertion': 'bad' }), RULES)).toMatchObject({
			flags: { member: false },
			status: 'failed'
		});
		expect(resolve(await run({}), RULES)).toMatchObject({ flags: { member: false }, status: 'settled' });
	});

	it('accepts the CF_Authorization cookie when the header is absent', async () => {
		const good = await jwt({ email: 'you@example.com' });
		const run = (h: Record<string, string>, cfCookie?: string) =>
			buildSources({ headers: headers(h), peerAddr: '203.0.113.5', sessionCookie: undefined, cfCookie }, rt());
		expect(resolve(await run({}, good), RULES)).toMatchObject({
			flags: { member: true },
			basis: [{ flag: 'member', source: 'cf-access', trust: 'verified' }]
		});
		expect(resolve(await run({}, 'bad'), RULES)).toMatchObject({ flags: { member: false }, status: 'failed' });
	});

	it('the header wins over the cookie', async () => {
		const good = await jwt({ email: 'you@example.com' });
		const other = await jwt({ email: 'other@example.com' });
		const sources = await buildSources(
			{ headers: headers({ 'cf-access-jwt-assertion': other }), peerAddr: null, sessionCookie: undefined, cfCookie: good },
			rt()
		);
		expect(resolve(sources, RULES).flags.member).toBe(false);
	});
});

describe('buildSources', () => {
	it('spoofed serve headers from a stranger never yield a member', async () => {
		const sources = await buildSources(
			{ headers: headers(MEMBER_HEADERS), peerAddr: '198.51.100.7', sessionCookie: undefined },
			{ config: cfg(), cfKey: null }
		);
		expect(resolve(sources, RULES).flags.member).toBe(false);
	});

	it('the trusted proxy path yields a member with a serve-header basis', async () => {
		const sources = await buildSources(
			{ headers: headers(MEMBER_HEADERS), peerAddr: PROXY, sessionCookie: undefined },
			{ config: cfg(), cfKey: null }
		);
		expect(resolve(sources, RULES)).toMatchObject({
			flags: { member: true },
			basis: [{ flag: 'member', source: 'serve-header', trust: 'verified' }]
		});
	});

	it('the dev override on is ignored in production; off always applies', async () => {
		const input = { headers: headers(MEMBER_HEADERS), peerAddr: PROXY, sessionCookie: undefined };
		const prodOn = { config: cfg({ NODE_ENV: 'production', FLAG_OVERRIDE_MEMBER: 'on' }), cfKey: null };
		expect(prodOn.config.override).toBeNull();
		const off = { config: cfg({ NODE_ENV: 'production', FLAG_OVERRIDE_MEMBER: 'off' }), cfKey: null };
		expect(resolve(await buildSources(input, off), RULES).flags.member).toBe(false);
	});
});
