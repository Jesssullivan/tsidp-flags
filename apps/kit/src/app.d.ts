import type { FlagSource } from '@tsidp-flags/flags';

declare global {
	namespace App {
		interface Locals {
			/** Built once per request in hooks.server.ts. */
			sources: FlagSource[];
		}
	}
}

export {};
