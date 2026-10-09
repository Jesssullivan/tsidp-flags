import { defineConfig } from '@playwright/test';

// E2E_PORT moves the preview server off 4173 on a shared host where that port is taken.
const port = Number(process.env.E2E_PORT ?? 4173);
const origin = `http://127.0.0.1:${port}`;

export default defineConfig({
	testDir: 'e2e',
	timeout: 30_000,
	use: { baseURL: origin },
	webServer: {
		command: `pnpm build && pnpm preview --host 127.0.0.1 --port ${port} --strictPort`,
		url: origin,
		reuseExistingServer: !process.env.CI,
		timeout: 120_000
	}
});
