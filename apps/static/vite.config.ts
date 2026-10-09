import adapter from '@sveltejs/adapter-static';
import { sveltekit } from '@sveltejs/kit/vite';
import { vitePreprocess } from '@sveltejs/vite-plugin-svelte';
import { defineConfig } from 'vite';

// GitHub Pages serves a project site under /<repo>; set BASE_PATH=/<repo> in that build.
// SvelteKit 3 types paths.base as '' or a string starting with '/', so check it here.
const isBasePath = (value: string): value is '' | `/${string}` => value === '' || value.startsWith('/');
const base = process.env.BASE_PATH ?? '';
if (!isBasePath(base)) throw new Error(`BASE_PATH must be empty or start with '/', got '${base}'`);

export default defineConfig({
	plugins: [
		// SvelteKit 3: the former svelte.config.js options are sveltekit() options.
		sveltekit({
			preprocess: vitePreprocess(),
			adapter: adapter({ fallback: '404.html' }),
			paths: { base }
		})
	]
});
