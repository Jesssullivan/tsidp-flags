import { redirect } from '@sveltejs/kit';
import { SECURE_SESSION_COOKIE, SESSION_COOKIE } from '#lib/server/session.js';
import type { RequestHandler } from './$types';

export const POST: RequestHandler = ({ cookies }) => {
	// Clear both names: the __Host- cookie (https) and the plain one (http, or
	// a session issued before the __Host- rename).
	cookies.delete(SECURE_SESSION_COOKIE, { path: '/', secure: true });
	cookies.delete(SESSION_COOKIE, { path: '/' });
	redirect(303, '/');
};
