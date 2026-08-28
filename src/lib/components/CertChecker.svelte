<script lang="ts">
	import { m } from '#lib/paraglide/messages.js';
	import { describeCert, parseCertificates, type CertInfo } from '#lib/cert.js';
	import CertCard from './CertCard.svelte';
	import CertInput from './CertInput.svelte';
	import PrivateKeyCard from './PrivateKeyCard.svelte';

	let input = $state('');
	let privateKey = $state<{ pem: string; source: string } | null>(null);
	let results = $state<CertInfo[]>([]);
	let error = $state('');
	let busy = $state(false);

	async function check() {
		error = '';
		results = [];
		busy = true;
		try {
			const certs = parseCertificates(input);
			if (!certs.length) {
				error = m.error_no_cert();
				return;
			}
			results = await Promise.all(certs.map((c) => describeCert(c)));
		} catch {
			error = m.error_no_cert();
		} finally {
			busy = false;
		}
	}
</script>

<div class="grid items-start gap-6 lg:grid-cols-[minmax(0,2fr)_minmax(0,3fr)]">
	<section class="card border border-base-300 bg-base-100 shadow-sm lg:sticky lg:top-6">
		<div class="card-body gap-4 p-6">
			<div>
				<h2 class="card-title text-base">{m.tab_checker()}</h2>
				<p class="mt-1 text-sm text-base-content/70">{m.checker_desc()}</p>
			</div>

			<CertInput
				bind:value={input}
				onerror={(msg) => (error = msg)}
				onprivatekey={(pem, source) => (privateKey = { pem, source })}
			/>

			<button
				class="btn w-full btn-primary sm:w-auto"
				onclick={check}
				disabled={busy || !input.trim()}
			>
				{#if busy}<span class="loading loading-xs loading-spinner"
					></span>{m.working()}{:else}{m.check_button()}{/if}
			</button>

			{#if error}
				<div role="alert" class="alert text-sm alert-error">{error}</div>
			{/if}
		</div>
	</section>

	<section class="space-y-4">
		{#if privateKey}
			<PrivateKeyCard
				pem={privateKey.pem}
				source={privateKey.source}
				onclear={() => (privateKey = null)}
			/>
		{/if}
		{#if results.length}
			{#if results.length > 1}
				<p class="text-sm text-base-content/60">{m.certs_found({ count: results.length })}</p>
			{/if}
			{#each results as info (info.sha256)}
				<CertCard {info} />
			{/each}
		{:else}
			<div
				class="flex min-h-64 items-center justify-center rounded-2xl border-2 border-dashed border-base-300 p-8 text-sm text-base-content/40"
			>
				{m.results_placeholder()}
			</div>
		{/if}
	</section>
</div>
