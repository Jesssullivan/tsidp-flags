export interface OidcConfig {
	issuer: string;
	clientId: string;
	clientSecret: string | null;
	redirectUri: string;
}

export interface CfAccessConfig {
	teamDomain: string;
	aud: string;
}

export interface Config {
	/** Serve headers are trusted only from this peer address. */
	trustedProxyAddr: string | null;
	/**
	 * adapter-node ADDRESS_HEADER. When set, getClientAddress() reads a request
	 * header instead of the TCP peer, so the proxy check cannot be trusted and
	 * the serve-header source refuses (fails closed).
	 */
	addressHeader: string | null;
	/** App capability that must appear in Tailscale-App-Capabilities. */
	capability: string;
	oidc: OidcConfig | null;
	/** HS256 secret for session cookies; null disables OIDC sessions. */
	sessionSecret: Uint8Array | null;
	cfAccess: CfAccessConfig | null;
	/** Emails (lowercase) that count as members for cf-access. */
	memberEmails: string[];
	/** Exact origin allowed to read /api/surface cross-origin. */
	staticOrigin: string | null;
	/** Dev override: member forced on or off. 'on' is ignored in production. */
	override: 'on' | 'off' | null;
}

type Env = Readonly<Record<string, string | undefined>>;

const nonEmpty = (v: string | undefined): string | null => (v && v.trim() ? v.trim() : null);

export function loadConfig(env: Env, readSecretFile: (path: string) => string = () => ''): Config {
	const issuer = nonEmpty(env.OIDC_ISSUER);
	const clientId = nonEmpty(env.OIDC_CLIENT_ID);
	const redirectUri = nonEmpty(env.OIDC_REDIRECT_URI);
	const secretFile = nonEmpty(env.OIDC_CLIENT_SECRET_FILE);
	const team = nonEmpty(env.CF_ACCESS_TEAM_DOMAIN);
	const aud = nonEmpty(env.CF_ACCESS_AUD);
	const secret = nonEmpty(env.SESSION_SECRET);
	const sessionSecret = secret ? Buffer.from(secret, 'base64') : null;
	const production = env.NODE_ENV === 'production';
	const override = nonEmpty(env.FLAG_OVERRIDE_MEMBER);

	return {
		trustedProxyAddr: nonEmpty(env.TRUSTED_PROXY_ADDR),
		addressHeader: nonEmpty(env.ADDRESS_HEADER),
		capability: nonEmpty(env.PROBE_CAPABILITY) ?? 'example.org/cap/flag-probe',
		oidc:
			issuer && clientId && redirectUri
				? {
						issuer: issuer.replace(/\/$/, ''),
						clientId,
						redirectUri,
						clientSecret: secretFile ? readSecretFile(secretFile).trim() || null : null
					}
				: null,
		sessionSecret: sessionSecret && sessionSecret.length >= 32 ? new Uint8Array(sessionSecret) : null,
		cfAccess: team && aud ? { teamDomain: team.replace(/^https?:\/\//, '').replace(/\/$/, ''), aud } : null,
		memberEmails: (env.FLAG_MEMBER_EMAILS ?? '')
			.split(',')
			.map((e) => e.trim().toLowerCase())
			.filter(Boolean),
		staticOrigin: nonEmpty(env.STATIC_ORIGIN),
		override: override === 'off' ? 'off' : override === 'on' && !production ? 'on' : null
	};
}
