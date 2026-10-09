import { defineEnvVars } from '@sveltejs/kit/env';

// SvelteKit 3 explicit environment variables (replaces $env/dynamic/private).
// Every variable is private, read when the server starts, and optional: an
// unset or blank value turns its feature off (see lib/server/config.ts, which
// owns the parsing and the fail-closed defaults).
const optional = (description: string) => ({
	description,
	schema: (value: string | undefined) => value
});

export const variables = defineEnvVars({
	NODE_ENV: optional('production disables FLAG_OVERRIDE_MEMBER=on'),
	TRUSTED_PROXY_ADDR: optional('Serve headers are trusted only from this TCP peer address'),
	ADDRESS_HEADER: optional('adapter-node ADDRESS_HEADER; when set, the serve-header source refuses'),
	PROBE_CAPABILITY: optional('App capability required in Tailscale-App-Capabilities'),
	OIDC_ISSUER: optional('tsidp issuer URL'),
	OIDC_CLIENT_ID: optional('OIDC client id'),
	OIDC_REDIRECT_URI: optional('OIDC redirect URI (.../auth/callback)'),
	OIDC_CLIENT_SECRET_FILE: optional('Path to a file holding the OIDC client secret'),
	SESSION_SECRET: optional('Base64 HS256 session secret, 32+ bytes'),
	CF_ACCESS_TEAM_DOMAIN: optional('Cloudflare Access team domain'),
	CF_ACCESS_AUD: optional('Cloudflare Access application audience tag'),
	FLAG_MEMBER_EMAILS: optional('Comma-separated emails that count as members for cf-access'),
	STATIC_ORIGIN: optional('Exact origin allowed to read /api/surface cross-origin'),
	FLAG_OVERRIDE_MEMBER: optional('Dev override: on or off ("on" is ignored in production)')
});
