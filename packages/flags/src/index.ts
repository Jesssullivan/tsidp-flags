/**
 * Flag resolution contract.
 *
 * A FlagSource is one observation about the visitor (a header, an OIDC login,
 * a Cloudflare Access JWT, a browser-side probe). A FlagRule says which flag a
 * source may grant and how much trust it needs. resolve() is pure, fails
 * closed, and reports `pending` until every source has settled.
 *
 * Trust tiers:
 *   verified  a server checked a signature, a trusted-proxy address or a
 *             session it issued. Safe to gate server-rendered markup and APIs.
 *   hint      a browser-side observation (image or fetch probe). Fine for
 *             progressive enhancement, never for access control.
 */

export type Trust = 'verified' | 'hint';

export type SourceKind =
	| 'override'
	| 'serve-header'
	| 'tsidp-oidc'
	| 'cf-access'
	| 'tailnet-probe'
	| 'cf-session-probe';

/** pending: still in flight. ok: settled with claims. absent: settled, nothing seen. error: settled, failed. */
export type SourceState = 'pending' | 'ok' | 'absent' | 'error';

export interface FlagSource {
	kind: SourceKind;
	/** Trust the adapter claims; resolve() caps it at MAX_TRUST[kind]. */
	trust: Trust;
	state: SourceState;
	/** flag name -> asserted value. Only read when state is 'ok'. */
	claims?: Readonly<Record<string, boolean>>;
}

export interface FlagRule {
	flag: string;
	/** Lowest trust that may grant this flag. Defaults to 'verified'. */
	minTrust?: Trust;
	/** Restrict to these source kinds. Defaults to every kind. */
	kinds?: readonly SourceKind[];
}

export type Flags = Record<string, boolean>;

export interface BasisEntry {
	flag: string;
	source: SourceKind;
	/** Effective (capped) trust of the granting source. */
	trust: Trust;
}

export type Status = 'pending' | 'settled' | 'failed';

export interface Resolution {
	flags: Flags;
	basis: BasisEntry[];
	status: Status;
}

/** Client-side probes can never exceed 'hint', whatever an adapter claims. */
export const MAX_TRUST: Readonly<Record<SourceKind, Trust>> = {
	override: 'verified',
	'serve-header': 'verified',
	'tsidp-oidc': 'verified',
	'cf-access': 'verified',
	'tailnet-probe': 'hint',
	'cf-session-probe': 'hint'
};

const RANK: Readonly<Record<Trust, number>> = { hint: 0, verified: 1 };

export function effectiveTrust(source: FlagSource): Trust {
	const cap = MAX_TRUST[source.kind];
	return RANK[source.trust] <= RANK[cap] ? source.trust : cap;
}

function isKnownKind(kind: unknown): kind is SourceKind {
	return typeof kind === 'string' && Object.hasOwn(MAX_TRUST, kind);
}

function ownClaim(source: FlagSource, flag: string): boolean | undefined {
	const claims = source.claims;
	if (!claims || !Object.hasOwn(claims, flag)) return undefined;
	return claims[flag];
}

/**
 * resolve(sources, rules):
 *  - unknown flags (no rule) are false; an unknown source kind is ignored
 *  - a flag is true only if some source in state 'ok' claims it === true,
 *    the rule allows its kind, and its effective trust >= rule.minTrust
 *  - an 'override' source claiming false is a global off switch: deny wins
 *  - while any source is pending: status 'pending' and EVERY flag is false
 *  - settled, no flag granted, and some source errored: status 'failed'
 *  - otherwise status 'settled'
 */
export function resolve(sources: readonly FlagSource[], rules: readonly FlagRule[]): Resolution {
	const flags: Flags = {};
	for (const rule of rules) flags[rule.flag] = false;

	const known = sources.filter((s) => isKnownKind(s?.kind));
	if (known.some((s) => s.state === 'pending')) {
		return { flags, basis: [], status: 'pending' };
	}

	const basis: BasisEntry[] = [];
	for (const rule of rules) {
		const min = RANK[rule.minTrust ?? 'verified'];
		const denied = known.some(
			(s) => s.kind === 'override' && s.state === 'ok' && ownClaim(s, rule.flag) === false
		);
		if (denied) continue;
		for (const source of known) {
			if (source.state !== 'ok') continue;
			if (rule.kinds && !rule.kinds.includes(source.kind)) continue;
			if (ownClaim(source, rule.flag) !== true) continue;
			const trust = effectiveTrust(source);
			if (RANK[trust] < min) continue;
			flags[rule.flag] = true;
			basis.push({ flag: rule.flag, source: source.kind, trust });
		}
	}

	const granted = Object.values(flags).some(Boolean);
	const errored = known.some((s) => s.state === 'error');
	return { flags, basis, status: !granted && errored ? 'failed' : 'settled' };
}

/** A manifest as served by the probe's /v1/surface and the kit's /api/surface. */
export interface Surface {
	version: 1;
	flags: Flags;
	basis: BasisEntry[];
	status: Status;
}

export function toSurface(resolution: Resolution): Surface {
	return { version: 1, ...resolution };
}

/** Parse untrusted JSON into a Surface, or null. */
export function parseSurface(value: unknown): Surface | null {
	if (typeof value !== 'object' || value === null) return null;
	const v = value as Record<string, unknown>;
	if (v.version !== 1) return null;
	if (v.status !== 'pending' && v.status !== 'settled' && v.status !== 'failed') return null;
	if (typeof v.flags !== 'object' || v.flags === null || Array.isArray(v.flags)) return null;
	const flags: Flags = {};
	for (const [k, val] of Object.entries(v.flags)) {
		if (typeof val !== 'boolean') return null;
		flags[k] = val;
	}
	if (!Array.isArray(v.basis)) return null;
	const basis: BasisEntry[] = [];
	for (const b of v.basis) {
		if (typeof b !== 'object' || b === null) return null;
		const e = b as Record<string, unknown>;
		if (typeof e.flag !== 'string' || !isKnownKind(e.source)) return null;
		if (e.trust !== 'verified' && e.trust !== 'hint') return null;
		basis.push({ flag: e.flag, source: e.source, trust: e.trust });
	}
	return { version: 1, flags, basis, status: v.status };
}

export {
	CF_SESSION_PROBE_REQUEST,
	CF_SESSION_PROBE_TIMEOUT_MS,
	cfSessionProbe,
	classifyCfSession,
	type CfSessionProbeOptions,
	type ProbeResponseLike
} from './cf-session-probe';
