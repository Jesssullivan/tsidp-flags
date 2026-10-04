<script lang="ts">
	import { onMount, type Snippet } from 'svelte';
	import { parseSurface } from '@tsidp-flags/flags';

	let {
		manifestUrl,
		flag = 'member',
		timeoutMs = 4000,
		children
	}: { manifestUrl: string; flag?: string; timeoutMs?: number; children: Snippet } = $props();

	// Closed until proven open. Prerendered HTML and every failure path contain
	// no gated node: the slot renders only after a settled manifest says true.
	let open = $state(false);

	onMount(async () => {
		const controller = new AbortController();
		const timer = setTimeout(() => controller.abort(), timeoutMs);
		try {
			const res = await fetch(manifestUrl, {
				credentials: 'omit',
				cache: 'no-store',
				signal: controller.signal
			});
			if (!res.ok) return;
			const surface = parseSurface(await res.json());
			open = surface !== null && surface.status === 'settled' && surface.flags[flag] === true;
		} catch {
			open = false; // network error, timeout, bad JSON: render nothing
		} finally {
			clearTimeout(timer);
			window.dispatchEvent(new CustomEvent('gatedslot:settled', { detail: { open } }));
		}
	});
</script>

{#if open}
	{@render children()}
{/if}
