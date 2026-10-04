import { resolve } from '@tsidp-flags/flags';
import { RULES } from '$lib/rules';
import type { LayoutServerLoad } from './$types';

/** Flags and basis for every page. Never returns the identity behind them. */
export const load: LayoutServerLoad = ({ locals }) => {
	const { flags, basis, status } = resolve(locals.sources, RULES);
	return { flags, basis, status };
};
