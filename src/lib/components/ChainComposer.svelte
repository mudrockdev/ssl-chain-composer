<script lang="ts">
	import { m } from '#lib/paraglide/messages.js';
	import { buildBundle, bundleDomain, bundleFileName, zipBundle } from '#lib/bundle.js';
	import { composeChain, parseCertificates, type ChainResult } from '#lib/cert.js';
	import CertCard from './CertCard.svelte';
	import CertInput from './CertInput.svelte';

	let input = $state('');
	let result = $state<ChainResult | null>(null);
	let error = $state('');
	let busy = $state(false);
	let includeRoot = $state(true);
	let copied = $state(false);

	async function compose() {
		error = '';
		result = null;
		copied = false;
		busy = true;
		try {
			const certs = parseCertificates(input);
			if (!certs.length) {
				error = m.error_no_cert();
				return;
			}
			result = await composeChain(certs);
		} catch {
			error = m.error_no_cert();
		} finally {
			busy = false;
		}
	}

	function roleOf(index: number): 'leaf' | 'intermediate' | 'root' {
		if (index === 0 && !result!.ordered[0].isCA) return 'leaf';
		if (result!.ordered[index].selfSigned) return 'root';
		return index === 0 ? 'leaf' : 'intermediate';
	}

	const composedPem = $derived.by(() => {
		if (!result) return '';
		const certs =
			includeRoot || !result.rootIncluded
				? result.ordered
				: result.ordered.filter((c) => !c.selfSigned);
		return certs.map((c) => c.pem).join('\n') + '\n';
	});

	function download(data: BlobPart, type: string, name: string) {
		const url = URL.createObjectURL(new Blob([data], { type }));
		const a = document.createElement('a');
		a.href = url;
		a.download = name;
		a.click();
		URL.revokeObjectURL(url);
	}

	async function copyPem() {
		await navigator.clipboard.writeText(composedPem);
		copied = true;
		setTimeout(() => (copied = false), 2000);
	}

	function downloadPem() {
		download(composedPem, 'application/x-pem-file', 'chain.pem');
	}

	function downloadZip() {
		if (!result) return;
		const zip = zipBundle(buildBundle(result));
		download(zip as BlobPart, 'application/zip', bundleFileName(bundleDomain(result)));
	}
</script>

<div class="grid items-start gap-6 lg:grid-cols-[minmax(0,2fr)_minmax(0,3fr)]">
	<section class="card border border-base-300 bg-base-100 shadow-sm lg:sticky lg:top-6">
		<div class="card-body gap-4 p-6">
			<div>
				<h2 class="card-title text-base">{m.tab_composer()}</h2>
				<p class="mt-1 text-sm text-base-content/70">{m.composer_desc()}</p>
			</div>

			<CertInput bind:value={input} onerror={(msg) => (error = msg)} />

			<button
				class="btn w-full btn-primary sm:w-auto"
				onclick={compose}
				disabled={busy || !input.trim()}
			>
				{#if busy}<span class="loading loading-xs loading-spinner"
					></span>{m.working()}{:else}{m.compose_button()}{/if}
			</button>

			{#if error}
				<div role="alert" class="alert text-sm alert-error">{error}</div>
			{/if}
		</div>
	</section>

	<section class="space-y-4">
		{#if result}
			{#if result.rootIncluded}
				<div role="alert" class="alert text-sm alert-success">{m.chain_complete_root()}</div>
			{:else if result.missingIssuer}
				<div role="alert" class="alert text-sm alert-warning">
					{m.chain_missing({ issuer: result.missingIssuer })}
				</div>
			{/if}
			{#each result.fetchedFrom as url (url)}
				<div role="alert" class="alert text-sm break-all alert-info">{m.aia_fetched({ url })}</div>
			{/each}
			{#if result.fetchedFrom.length}
				<p class="text-xs text-base-content/60">{m.aia_relay_note()}</p>
			{/if}
			{#if result.fetchFailedUrl}
				<div role="alert" class="alert text-sm break-all alert-warning">
					{m.aia_failed({ url: result.fetchFailedUrl })}
				</div>
			{/if}
			{#if result.extras.length}
				<p class="text-sm text-base-content/60">{m.extras_note({ count: result.extras.length })}</p>
			{/if}

			<div>
				{#each result.ordered as info, i (info.sha256)}
					<CertCard {info} role={roleOf(i)} />
					{#if i < result.ordered.length - 1}
						<div class="my-1 flex items-center gap-2 py-1 pl-6">
							<span class={result.links[i] ? 'text-success' : 'text-error'}>
								{result.links[i] ? '↓ ✓' : '↓ ✗'}
							</span>
							<span class="text-xs {result.links[i] ? 'text-base-content/60' : 'text-error'}">
								{result.links[i] ? m.link_ok() : m.link_bad()}
							</span>
						</div>
					{/if}
				{/each}
			</div>

			<div class="card border border-base-300 bg-base-100 shadow-sm">
				<div class="card-body gap-3 p-6">
					<div class="flex flex-wrap items-center gap-3">
						<h3 class="mr-auto card-title text-base">{m.composed_chain()}</h3>
						{#if result.rootIncluded}
							<label class="label cursor-pointer gap-2 text-sm">
								<input type="checkbox" class="checkbox checkbox-sm" bind:checked={includeRoot} />
								{m.include_root()}
							</label>
						{/if}
					</div>
					<p class="text-xs text-base-content/60">{m.chain_order()} {m.root_note()}</p>
					<textarea
						readonly
						class="textarea-bordered textarea h-48 w-full font-mono text-xs leading-relaxed"
						value={composedPem}></textarea>
					<div class="card-actions">
						<button class="btn btn-outline btn-sm" onclick={copyPem}>
							{copied ? m.copied() : m.copy()}
						</button>
						<button class="btn btn-outline btn-sm" onclick={downloadPem}>{m.download_pem()}</button>
						<button class="btn btn-outline btn-sm" onclick={downloadZip}>{m.download_zip()}</button>
					</div>
				</div>
			</div>
		{:else}
			<div
				class="flex min-h-64 items-center justify-center rounded-2xl border-2 border-dashed border-base-300 p-8 text-sm text-base-content/40"
			>
				{m.results_placeholder()}
			</div>
		{/if}
	</section>
</div>
