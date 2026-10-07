import { describe, expect, it } from 'vitest';
import { SECURE_SESSION_COOKIE, SESSION_COOKIE, cookieOptions, sessionCookieName } from './session';

describe('session cookie name and attributes', () => {
	it('uses the __Host- prefix on https and the plain name on http', () => {
		expect(sessionCookieName(true)).toBe(SECURE_SESSION_COOKIE);
		expect(SECURE_SESSION_COOKIE.startsWith('__Host-')).toBe(true);
		expect(sessionCookieName(false)).toBe(SESSION_COOKIE);
	});

	it('https attributes satisfy the __Host- rules: Secure, Path=/, no Domain', () => {
		const o = cookieOptions(true, 3600) as Record<string, unknown>;
		expect(o).toMatchObject({ secure: true, path: '/', httpOnly: true });
		expect('domain' in o).toBe(false);
	});
});
