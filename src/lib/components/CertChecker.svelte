<script lang="ts">
	import { m } from '#lib/paraglide/messages.js';
	import { describeCert, matchesHostname, parseCertificates, type CertInfo } from '#lib/cert.js';
	import CertCard from './CertCard.svelte';
	import CertInput from './CertInput.svelte';

	let input = $state('');
	let hostname = $state('');
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

	const hostnameResult = $derived(
		results.length && hostname.trim() ? matchesHostname(results[0], hostname) : null
	);
</script>

<p class="mb-4 text-sm text-base-content/70">{m.checker_desc()}</p>

<CertInput bind:value={input} onerror={(msg) => (error = msg)} />

<div class="mt-4 flex flex-wrap items-end gap-3">
	<label class="form-control">
		<span class="label-text mb-1 block text-xs text-base-content/60">{m.hostname_label()}</span>
		<input
			type="text"
			bind:value={hostname}
			class="input-bordered input w-56 font-mono input-sm"
			placeholder={m.hostname_placeholder()}
			spellcheck="false"
		/>
	</label>
	<button class="btn btn-primary btn-sm" onclick={check} disabled={busy || !input.trim()}>
		{#if busy}<span class="loading loading-xs loading-spinner"
			></span>{m.working()}{:else}{m.check_button()}{/if}
	</button>
</div>

{#if error}
	<div role="alert" class="mt-4 alert text-sm alert-error">{error}</div>
{/if}

{#if results.length}
	<div class="mt-6 space-y-4">
		{#if hostnameResult !== null}
			<div role="alert" class="alert text-sm {hostnameResult ? 'alert-success' : 'alert-error'}">
				{hostnameResult
					? m.hostname_match({ host: hostname.trim() })
					: m.hostname_no_match({ host: hostname.trim() })}
			</div>
		{/if}
		{#if results.length > 1}
			<p class="text-sm text-base-content/60">{m.certs_found({ count: results.length })}</p>
		{/if}
		{#each results as info (info.sha256)}
			<CertCard {info} />
		{/each}
	</div>
{/if}
