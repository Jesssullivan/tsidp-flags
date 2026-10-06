import { SignJWT, jwtVerify } from 'jose';

export const SESSION_COOKIE = 'flags_session';
/**
 * Session cookie name on https. The __Host- prefix makes the browser require
 * Secure, Path=/ and no Domain, so a sibling subdomain cannot plant or shadow
 * the session. Plain http (local dev) keeps the unprefixed name, which browsers
 * would otherwise reject.
 */
export const SECURE_SESSION_COOKIE = '__Host-flags_session';
export const sessionCookieName = (secure: boolean) => (secure ? SECURE_SESSION_COOKIE : SESSION_COOKIE);
/** Cloudflare Access sets this cookie on the protected hostname; it carries the same JWT as the header. */
export const CF_ACCESS_COOKIE = 'CF_Authorization';
export const FLOW_COOKIE = 'flags_oidc_flow';
const ISSUER = 'flags-kit';

export interface SessionPayload {
	member: boolean;
	/** Display handle only; never sent to the client or logged. */
	sub: string;
}

export interface FlowPayload {
	state: string;
	verifier: string;
	nonce: string;
}

async function sign(
	secret: Uint8Array,
	payload: Record<string, unknown>,
	audience: string,
	ttlSeconds: number,
	now: number
): Promise<string> {
	return new SignJWT(payload)
		.setProtectedHeader({ alg: 'HS256' })
		.setIssuer(ISSUER)
		.setAudience(audience)
		.setIssuedAt(now)
		.setExpirationTime(now + ttlSeconds)
		.sign(secret);
}

async function verify(
	secret: Uint8Array,
	token: string,
	audience: string,
	now: number
): Promise<Record<string, unknown> | null> {
	try {
		const { payload } = await jwtVerify(token, secret, {
			algorithms: ['HS256'],
			issuer: ISSUER,
			audience,
			currentDate: new Date(now * 1000)
		});
		return payload as Record<string, unknown>;
	} catch {
		return null;
	}
}

export const nowSeconds = () => Math.floor(Date.now() / 1000);

export function signSession(secret: Uint8Array, s: SessionPayload, ttl = 3600, now = nowSeconds()) {
	return sign(secret, { member: s.member, sub: s.sub }, 'session', ttl, now);
}

export async function verifySession(
	secret: Uint8Array,
	token: string,
	now = nowSeconds()
): Promise<SessionPayload | null> {
	const p = await verify(secret, token, 'session', now);
	if (!p || typeof p.member !== 'boolean' || typeof p.sub !== 'string') return null;
	return { member: p.member, sub: p.sub };
}

export function signFlow(secret: Uint8Array, f: FlowPayload, ttl = 600, now = nowSeconds()) {
	return sign(secret, { state: f.state, verifier: f.verifier, nonce: f.nonce }, 'flow', ttl, now);
}

export async function verifyFlow(
	secret: Uint8Array,
	token: string,
	now = nowSeconds()
): Promise<FlowPayload | null> {
	const p = await verify(secret, token, 'flow', now);
	if (!p || typeof p.state !== 'string' || typeof p.verifier !== 'string' || typeof p.nonce !== 'string')
		return null;
	return { state: p.state, verifier: p.verifier, nonce: p.nonce };
}

/** Cookie attributes for both cookies: HttpOnly always, Secure whenever the site is https. */
export function cookieOptions(secure: boolean, maxAge: number) {
	return { path: '/', httpOnly: true, sameSite: 'lax' as const, secure, maxAge };
}
