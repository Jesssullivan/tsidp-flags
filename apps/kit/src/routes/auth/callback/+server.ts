import { error, redirect } from '@sveltejs/kit';
import { getConfig } from '$lib/server/runtime';
import { discoverCached, exchangeCode, remoteJwks, verifyIdToken } from '$lib/server/oidc';
import { FLOW_COOKIE, cookieOptions, sessionCookieName, signSession, verifyFlow } from '$lib/server/session';
import type { RequestHandler } from './$types';

export const GET: RequestHandler = async ({ cookies, url }) => {
	const cfg = getConfig();
	if (!cfg.oidc || !cfg.sessionSecret) error(503, 'sign-in is not configured');
	const secure = url.protocol === 'https:';

	const flowCookie = cookies.get(FLOW_COOKIE);
	cookies.delete(FLOW_COOKIE, { path: '/' });
	const flow = flowCookie ? await verifyFlow(cfg.sessionSecret, flowCookie) : null;
	const code = url.searchParams.get('code');
	if (!flow || !code || url.searchParams.get('state') !== flow.state) {
		error(400, 'sign-in could not be completed; start again');
	}

	try {
		const meta = await discoverCached(cfg.oidc.issuer);
		const idToken = await exchangeCode(meta, cfg.oidc, code, flow.verifier);
		const identity = await verifyIdToken(
			idToken,
			meta,
			cfg.oidc,
			flow.nonce,
			remoteJwks(meta.jwks_uri)
		);
		cookies.set(
			sessionCookieName(secure),
			await signSession(cfg.sessionSecret, identity),
			cookieOptions(secure, 3600)
		);
	} catch {
		error(400, 'sign-in could not be completed; start again');
	}
	redirect(302, '/');
};
