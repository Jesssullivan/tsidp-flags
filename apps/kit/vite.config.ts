import adapter from '@sveltejs/adapter-node';
import { sveltekit } from '@sveltejs/kit/vite';
import { vitePreprocess } from '@sveltejs/vite-plugin-svelte';
import { defineConfig } from 'vitest/config';

export default defineConfig({
	plugins: [
		// SvelteKit 3: the former svelte.config.js options are sveltekit() options.
		sveltekit({
			preprocess: vitePreprocess(),
			// SvelteKit's default CSRF origin check stays on; cookies and CORS are explicit.
			adapter: adapter()
		})
	],
	test: {
		include: ['src/**/*.test.ts'],
		environment: 'node'
	}
});
