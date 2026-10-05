<script lang="ts">
	import GatedSlot from '$lib/GatedSlot.svelte';

	// The probe (or kit) origin that serves the flag manifest. Placeholder default.
	const manifestUrl = import.meta.env.VITE_MANIFEST_URL ?? 'https://probe.example.ts.net/v1/surface';
</script>

<main>
	<h1>Static flags demo</h1>
	<p>This page is public static HTML.</p>

	<GatedSlot {manifestUrl}>
		<section data-gated="member">
			<h2>Members only</h2>
			<p>Shown after a settled manifest granted the member flag. A hint, not access control.</p>
		</section>
	</GatedSlot>
</main>
