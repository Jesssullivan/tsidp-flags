import { createHash, randomBytes } from 'node:crypto';
import { createRemoteJWKSet, jwtVerify, type JWTVerifyGetKey } from 'jose';
import type { OidcConfig } from './config';

type Fetch = typeof fetch;

export interface ProviderMeta {
	issuer: string;
	authorization_endpoint: string;
	token_endpoint: string;
	jwks_uri: string;
}

const b64url = (buf: Buffer) => buf.toString('base64url');

/** PKCE (RFC 7636) S256 pair. */
export function pkcePair(bytes = randomBytes(32)): { verifier: string; challenge: string } {
	const verifier = b64url(bytes);
	const challenge = b64url(createHash('sha256').update(verifier).digest());
	return { verifier, challenge };
}

export const randomToken = () => b64url(randomBytes(24));

export async function discover(issuer: string, fetchFn: Fetch = fetch): Promise<ProviderMeta> {
	const res = await fetchFn(`${issuer}/.well-known/openid-configuration`, {
		headers: { accept: 'application/json' }
	});
	if (!res.ok) throw new Error('oidc discovery failed');
	const meta = (await res.json()) as Partial<ProviderMeta>;
	if (
		meta.issuer !== issuer ||
		!meta.authorization_endpoint ||
		!meta.token_endpoint ||
		!meta.jwks_uri
	) {
		throw new Error('oidc discovery document mismatch');
	}
	return meta as ProviderMeta;
}

/** How long a discovery document is reused before it is fetched again. */
export const DISCOVERY_TTL_MS = 10 * 60 * 1000;

const discoveryCache = new Map<string, { at: number; meta: Promise<ProviderMeta> }>();
const jwksCache = new Map<string, JWTVerifyGetKey>();

/**
 * Module-level discovery cache: one fetch per issuer per TTL, shared by login
 * and callback. A failed fetch is not cached, so the next request retries.
 */
export function discoverCached(
	issuer: string,
	fetchFn: Fetch = fetch,
	now: number = Date.now()
): Promise<ProviderMeta> {
	const hit = discoveryCache.get(issuer);
	if (hit && now - hit.at < DISCOVERY_TTL_MS) return hit.meta;
	const meta = discover(issuer, fetchFn);
	discoveryCache.set(issuer, { at: now, meta });
	meta.catch(() => {
		if (discoveryCache.get(issuer)?.meta === meta) discoveryCache.delete(issuer);
	});
	return meta;
}

/**
 * Module-level remote JWKS per jwks_uri. jose caches keys and rate-limits
 * refetches inside one JWKS object, so reusing it keeps that cache warm
 * instead of fetching the key set on every sign-in.
 */
export function remoteJwks(uri: string): JWTVerifyGetKey {
	let keys = jwksCache.get(uri);
	if (!keys) {
		keys = createRemoteJWKSet(new URL(uri));
		jwksCache.set(uri, keys);
	}
	return keys;
}

/** Test hook: forget cached discovery documents and key sets. */
export function clearOidcCaches(): void {
	discoveryCache.clear();
	jwksCache.clear();
}

export function authorizeUrl(
	meta: ProviderMeta,
	cfg: OidcConfig,
	p: { state: string; nonce: string; challenge: string }
): string {
	const url = new URL(meta.authorization_endpoint);
	url.search = new URLSearchParams({
		response_type: 'code',
		client_id: cfg.clientId,
		redirect_uri: cfg.redirectUri,
		scope: 'openid email profile',
		state: p.state,
		nonce: p.nonce,
		code_challenge: p.challenge,
		code_challenge_method: 'S256'
	}).toString();
	return url.toString();
}

export async function exchangeCode(
	meta: ProviderMeta,
	cfg: OidcConfig,
	code: string,
	verifier: string,
	fetchFn: Fetch = fetch
): Promise<string> {
	const body = new URLSearchParams({
		grant_type: 'authorization_code',
		code,
		redirect_uri: cfg.redirectUri,
		client_id: cfg.clientId,
		code_verifier: verifier
	});
	if (cfg.clientSecret) body.set('client_secret', cfg.clientSecret);
	const res = await fetchFn(meta.token_endpoint, {
		method: 'POST',
		headers: { 'content-type': 'application/x-www-form-urlencoded', accept: 'application/json' },
		body
	});
	if (!res.ok) throw new Error('token exchange failed');
	const json = (await res.json()) as { id_token?: unknown };
	if (typeof json.id_token !== 'string') throw new Error('no id_token');
	return json.id_token;
}

export interface Identity {
	sub: string;
	member: boolean;
}

/** Verify signature, issuer, audience, expiry and nonce; derive membership from the flag_member claim. */
export async function verifyIdToken(
	idToken: string,
	meta: ProviderMeta,
	cfg: OidcConfig,
	nonce: string,
	getKey: JWTVerifyGetKey
): Promise<Identity> {
	const { payload } = await jwtVerify(idToken, getKey, {
		issuer: meta.issuer,
		audience: cfg.clientId
	});
	if (payload.nonce !== nonce) throw new Error('nonce mismatch');
	const claim = payload.flag_member;
	return {
		sub: typeof payload.email === 'string' ? payload.email : String(payload.sub ?? ''),
		member: claim === true || claim === 'true'
	};
}
