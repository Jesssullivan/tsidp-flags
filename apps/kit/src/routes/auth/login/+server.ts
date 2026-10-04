import { error, redirect } from '@sveltejs/kit';
import { getConfig } from '$lib/server/runtime';
import { authorizeUrl, discover, pkcePair, randomToken } from '$lib/server/oidc';
import { FLOW_COOKIE, cookieOptions, signFlow } from '$lib/server/session';
import type { RequestHandler } from './$types';

/** Start the authorization code flow with PKCE. State, verifier and nonce ride in a signed 10 minute cookie. */
export const GET: RequestHandler = async ({ cookies, url }) => {
	const cfg = getConfig();
	if (!cfg.oidc || !cfg.sessionSecret) error(503, 'sign-in is not configured');
	const meta = await discover(cfg.oidc.issuer);
	const { verifier, challenge } = pkcePair();
	const state = randomToken();
	const nonce = randomToken();
	cookies.set(
		FLOW_COOKIE,
		await signFlow(cfg.sessionSecret, { state, verifier, nonce }),
		cookieOptions(url.protocol === 'https:', 600)
	);
	redirect(302, authorizeUrl(meta, cfg.oidc, { state, nonce, challenge }));
};
