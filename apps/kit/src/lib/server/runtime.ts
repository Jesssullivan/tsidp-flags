import { readFileSync } from 'node:fs';
import { env } from '$env/dynamic/private';
import { loadConfig } from './config';
import { makeRuntime, type Runtime } from './sources';

let runtime: Runtime | undefined;

export function getRuntime(): Runtime {
	runtime ??= makeRuntime(loadConfig(env, (p) => readFileSync(p, 'utf8')));
	return runtime;
}

export const getConfig = () => getRuntime().config;
