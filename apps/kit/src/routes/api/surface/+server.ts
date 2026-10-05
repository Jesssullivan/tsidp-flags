import { json } from '@sveltejs/kit';
import { resolve, toSurface } from '@tsidp-flags/flags';
import { getConfig } from '$lib/server/runtime';
import { RULES } from '$lib/rules';
import type { RequestHandler } from './$types';

/** Manifest for a static page. Exact-origin CORS from STATIC_ORIGIN; no credentials. */
function cors(request: Request): Record<string, string> {
	const allowed = getConfig().staticOrigin;
	return allowed && request.headers.get('origin') === allowed
		? { 'access-control-allow-origin': allowed, vary: 'Origin' }
		: { vary: 'Origin' };
}

export const GET: RequestHandler = ({ locals, request }) =>
	json(toSurface(resolve(locals.sources, RULES)), {
		headers: { 'cache-control': 'no-store', ...cors(request) }
	});

export const OPTIONS: RequestHandler = ({ request }) =>
	new Response(null, {
		status: 204,
		headers: { 'access-control-allow-methods': 'GET', 'cache-control': 'no-store', ...cors(request) }
	});
