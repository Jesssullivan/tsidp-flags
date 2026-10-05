import { expect, test, type Page, type Route } from '@playwright/test';

const MANIFEST = '**/v1/surface';

const surface = (member: boolean, status = 'settled') => ({
	version: 1,
	flags: { member },
	basis: member ? [{ flag: 'member', source: 'tailnet-probe', trust: 'hint' }] : [],
	status
});

const json = (body: unknown, status = 200) => (route: Route) =>
	route.fulfill({ status, contentType: 'application/json', body: JSON.stringify(body) });

/** Resolves with the slot's verdict once GatedSlot has settled. */
async function visit(page: Page) {
	await page.addInitScript(() => {
		(window as unknown as { __slot: Promise<{ open: boolean }> }).__slot = new Promise((ok) =>
			window.addEventListener('gatedslot:settled', (e) => ok((e as CustomEvent).detail), { once: true })
		);
	});
	await page.goto('/');
	return page.evaluate(() => (window as unknown as { __slot: Promise<{ open: boolean }> }).__slot);
}

test('anonymous (manifest says false): zero gated nodes', async ({ page }) => {
	await page.route(MANIFEST, json(surface(false)));
	expect(await visit(page)).toEqual({ open: false });
	await expect(page.locator('[data-gated]')).toHaveCount(0);
	await expect(page.getByText('Members only')).toHaveCount(0);
	await expect(page.getByText('This page is public static HTML.')).toBeVisible();
});

test('member (settled manifest says true): gated node present', async ({ page }) => {
	await page.route(MANIFEST, json(surface(true)));
	expect(await visit(page)).toEqual({ open: true });
	await expect(page.locator('[data-gated="member"]')).toHaveCount(1);
	await expect(page.getByText('Members only')).toBeVisible();
});

test('pending manifest: zero gated nodes even when the flag says true', async ({ page }) => {
	await page.route(MANIFEST, json(surface(true, 'pending')));
	expect(await visit(page)).toEqual({ open: false });
	await expect(page.locator('[data-gated]')).toHaveCount(0);
});

test.describe('failure renders nothing', () => {
	test('HTTP 500', async ({ page }) => {
		await page.route(MANIFEST, json({ error: 'x' }, 500));
		expect(await visit(page)).toEqual({ open: false });
		await expect(page.locator('[data-gated]')).toHaveCount(0);
	});

	test('network failure', async ({ page }) => {
		await page.route(MANIFEST, (route) => route.abort());
		expect(await visit(page)).toEqual({ open: false });
		await expect(page.locator('[data-gated]')).toHaveCount(0);
	});

	test('malformed JSON', async ({ page }) => {
		await page.route(MANIFEST, (route) => route.fulfill({ status: 200, body: '{nope' }));
		expect(await visit(page)).toEqual({ open: false });
		await expect(page.locator('[data-gated]')).toHaveCount(0);
	});

	test('schema violation (flag is a string)', async ({ page }) => {
		await page.route(MANIFEST, json({ version: 1, flags: { member: 'true' }, basis: [], status: 'settled' }));
		expect(await visit(page)).toEqual({ open: false });
		await expect(page.locator('[data-gated]')).toHaveCount(0);
	});
});

test('prerendered HTML never contains the gated markup', async ({ request }) => {
	const html = await (await request.get('/')).text();
	expect(html).not.toContain('data-gated');
	expect(html).not.toContain('Members only');
	expect(html).toContain('This page is public static HTML.');
});

test('the manifest request carries no credentials', async ({ page }) => {
	let credentialed = true;
	await page.route(MANIFEST, async (route) => {
		const h = route.request().headers();
		credentialed = 'cookie' in h || 'authorization' in h;
		await json(surface(false))(route);
	});
	await visit(page);
	expect(credentialed).toBe(false);
});
