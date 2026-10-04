import type { FlagRule } from '@tsidp-flags/flags';

/** The kit gates on verified signals only; browser-side probes are hints and never count here. */
export const RULES: readonly FlagRule[] = [{ flag: 'member', minTrust: 'verified' }];
