<script lang="ts">
	let { data } = $props();
</script>

<main>
	<h1>Flags demo</h1>
	<p>This part is public.</p>

	<!-- Server-rendered gate: when the flag is false this markup is never emitted. -->
	{#if data.flags.member}
		<section data-gated="member">
			<h2>Members only</h2>
			<p>Shown because a verified source granted the member flag.</p>
		</section>
	{:else}
		<p><a href="/auth/login">Sign in</a></p>
	{/if}
</main>
