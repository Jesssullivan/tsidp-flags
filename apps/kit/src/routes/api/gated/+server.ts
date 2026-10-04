import { json } from '@sveltejs/kit';
import { resolve } from '@tsidp-flags/flags';
import { RULES } from '$lib/rules';
import type { RequestHandler } from './$types';

/** 403 without a verified member flag. RULES requires verified trust. */
export const GET: RequestHandler = ({ locals }) => {
	const { flags } = resolve(locals.sources, RULES);
	if (!flags.member) {
		return json({ error: 'forbidden' }, { status: 403, headers: { 'cache-control': 'no-store' } });
	}
	return json({ data: 'members only' }, { headers: { 'cache-control': 'no-store' } });
};
