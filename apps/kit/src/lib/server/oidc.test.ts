import { createHash } from 'node:crypto';
import { SignJWT, createLocalJWKSet, exportJWK, generateKeyPair, type JWK } from 'jose';
import { beforeEach, describe, expect, it } from 'vitest';
import {
	DISCOVERY_TTL_MS,
	authorizeUrl,
	clearOidcCaches,
	discover,
	discoverCached,
	exchangeCode,
	pkcePair,
	remoteJwks,
	verifyIdToken,
	type ProviderMeta
} from './oidc';

const ISSUER = 'https://idp.example.ts.net';
const meta: ProviderMeta = {
	issuer: ISSUER,
	authorization_endpoint: `${ISSUER}/authorize`,
	token_endpoint: `${ISSUER}/token`,
	jwks_uri: `${ISSUER}/.well-known/jwks.json`
};
const cfg = { issuer: ISSUER, clientId: 'flags-kit', clientSecret: null, redirectUri: 'https://kit.example.org/auth/callback' };

describe('PKCE', () => {
	it('challenge is base64url(sha256(verifier))', () => {
		const { verifier, challenge } = pkcePair(Buffer.alloc(32, 1));
		expect(challenge).toBe(createHash('sha256').update(verifier).digest('base64url'));
		expect(verifier).toMatch(/^[A-Za-z0-9_-]{43}$/);
	});

	it('fresh pairs differ', () => {
		expect(pkcePair().verifier).not.toBe(pkcePair().verifier);
	});

	it('authorize URL carries S256 challenge, state, nonce and no verifier', () => {
		const { verifier, challenge } = pkcePair();
		const url = new URL(authorizeUrl(meta, cfg, { state: 's1', nonce: 'n1', challenge }));
		expect(url.searchParams.get('code_challenge_method')).toBe('S256');
		expect(url.searchParams.get('code_challenge')).toBe(challenge);
		expect(url.searchParams.get('state')).toBe('s1');
		expect(url.searchParams.get('nonce')).toBe('n1');
		expect(url.searchParams.get('response_type')).toBe('code');
		expect(url.toString()).not.toContain(verifier);
	});
});

describe('discovery and code exchange', () => {
	const json = (body: unknown, status = 200) => new Response(JSON.stringify(body), { status });

	it('rejects a discovery document whose issuer differs', async () => {
		await expect(discover(ISSUER, async () => json({ ...meta, issuer: 'https://evil.example' }))).rejects.toThrow();
	});

	it('discovers and exchanges with the verifier in the form body', async () => {
		expect(await discover(ISSUER, async () => json(meta))).toEqual(meta);
		let sent = '';
		const token = await exchangeCode(meta, cfg, 'code-1', 'ver-1', async (_u, init) => {
			sent = String(init?.body);
			return json({ id_token: 'x.y.z' });
		});
		expect(token).toBe('x.y.z');
		const form = new URLSearchParams(sent);
		expect(form.get('code_verifier')).toBe('ver-1');
		expect(form.get('grant_type')).toBe('authorization_code');
	});

	it('fails on a non-200 token response', async () => {
		await expect(exchangeCode(meta, cfg, 'c', 'v', async () => json({}, 400))).rejects.toThrow();
	});
});

describe('verifyIdToken with a fake JWKS', () => {
	async function setup() {
		const { publicKey, privateKey } = await generateKeyPair('ES256');
		const jwk: JWK = { ...(await exportJWK(publicKey)), kid: 'k1', alg: 'ES256' };
		const getKey = createLocalJWKSet({ keys: [jwk] });
		const mint = (claims: Record<string, unknown>, opts: { iss?: string; aud?: string; key?: CryptoKey } = {}) =>
			new SignJWT(claims)
				.setProtectedHeader({ alg: 'ES256', kid: 'k1' })
				.setIssuer(opts.iss ?? ISSUER)
				.setAudience(opts.aud ?? 'flags-kit')
				.setIssuedAt()
				.setExpirationTime('5m')
				.sign(opts.key ?? (privateKey as CryptoKey));
		return { getKey, mint };
	}

	it('flag_member "true" (string, as tsidp extraClaims renders it) is a member', async () => {
		const { getKey, mint } = await setup();
		const id = await verifyIdToken(await mint({ nonce: 'n', email: 'you@example.com', flag_member: 'true' }), meta, cfg, 'n', getKey);
		expect(id).toEqual({ sub: 'you@example.com', member: true });
	});

	it('missing or other flag_member is not a member', async () => {
		const { getKey, mint } = await setup();
		expect((await verifyIdToken(await mint({ nonce: 'n' }), meta, cfg, 'n', getKey)).member).toBe(false);
		expect((await verifyIdToken(await mint({ nonce: 'n', flag_member: 'false' }), meta, cfg, 'n', getKey)).member).toBe(false);
	});

	it.each([
		['nonce mismatch', { nonce: 'other' }, {}],
		['wrong audience', { nonce: 'n' }, { aud: 'someone-else' }],
		['wrong issuer', { nonce: 'n' }, { iss: 'https://evil.example' }]
	])('rejects %s', async (_n, claims, opts) => {
		const { getKey, mint } = await setup();
		await expect(verifyIdToken(await mint(claims, opts), meta, cfg, 'n', getKey)).rejects.toThrow();
	});

	it('rejects a token signed by an unknown key', async () => {
		const { getKey, mint } = await setup();
		const stranger = (await generateKeyPair('ES256')).privateKey as CryptoKey;
		await expect(verifyIdToken(await mint({ nonce: 'n' }, { key: stranger }), meta, cfg, 'n', getKey)).rejects.toThrow();
	});
});

describe('module-level discovery and JWKS caches', () => {
	const json = (body: unknown, status = 200) => new Response(JSON.stringify(body), { status });
	beforeEach(() => clearOidcCaches());

	it('fetches discovery once per issuer within the TTL, then again after it', async () => {
		let calls = 0;
		const f = async () => {
			calls += 1;
			return json(meta);
		};
		const t0 = 1_000_000;
		expect(await discoverCached(ISSUER, f, t0)).toEqual(meta);
		expect(await discoverCached(ISSUER, f, t0 + 1000)).toEqual(meta);
		expect(calls).toBe(1);
		await discoverCached(ISSUER, f, t0 + DISCOVERY_TTL_MS + 1);
		expect(calls).toBe(2);
	});

	it('does not cache a failed discovery', async () => {
		let calls = 0;
		const bad = async () => {
			calls += 1;
			return json({}, 500);
		};
		await expect(discoverCached(ISSUER, bad, 5)).rejects.toThrow();
		await new Promise((ok) => setTimeout(ok, 0));
		await expect(discoverCached(ISSUER, bad, 6)).rejects.toThrow();
		expect(calls).toBe(2);
		expect(await discoverCached(ISSUER, async () => json(meta), 7)).toEqual(meta);
	});

	it('reuses one remote key set per jwks_uri', () => {
		const a = remoteJwks('https://idp.example.ts.net/.well-known/jwks.json');
		expect(remoteJwks('https://idp.example.ts.net/.well-known/jwks.json')).toBe(a);
		expect(remoteJwks('https://other.example.ts.net/jwks')).not.toBe(a);
	});
});
