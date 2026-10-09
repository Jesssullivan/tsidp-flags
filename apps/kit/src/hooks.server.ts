import type { Handle } from '@sveltejs/kit/hooks';
import { getRuntime } from '#lib/server/runtime.js';
import { CF_ACCESS_COOKIE, sessionCookieName } from '#lib/server/session.js';
import { buildSources } from '#lib/server/sources.js';

/** Build FlagSource[] for the request. Resolution happens in +layout.server.ts. */
export const handle: Handle = async ({ event, resolve }) => {
	let peerAddr: string | null = null;
	try {
		peerAddr = event.getClientAddress();
	} catch {
		peerAddr = null; // unknown peer: serve headers are then not trusted
	}
	event.locals.sources = await buildSources(
		{
			headers: event.request.headers,
			peerAddr,
			sessionCookie: event.cookies.get(sessionCookieName(event.url.protocol === 'https:')),
			cfCookie: event.cookies.get(CF_ACCESS_COOKIE)
		},
		getRuntime()
	);
	const response = await resolve(event);
	response.headers.set('cache-control', 'no-store');
	response.headers.append('vary', 'Cookie');
	return response;
};
