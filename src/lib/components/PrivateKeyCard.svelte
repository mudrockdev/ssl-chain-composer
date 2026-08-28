<script lang="ts">
	import { m } from '#lib/paraglide/messages.js';

	let { pem, source, onclear }: { pem: string; source: string; onclear?: () => void } = $props();

	let revealed = $state(false);
	let copied = $state(false);

	async function copy() {
		await navigator.clipboard.writeText(pem);
		copied = true;
		setTimeout(() => (copied = false), 2000);
	}

	function download() {
		const url = URL.createObjectURL(new Blob([pem], { type: 'application/x-pem-file' }));
		const a = document.createElement('a');
		a.href = url;
		a.download = 'privkey.pem';
		a.click();
		URL.revokeObjectURL(url);
	}
</script>

<div class="card border border-warning/40 bg-base-100 shadow-sm">
	<div class="card-body gap-3 p-6">
		<div class="flex flex-wrap items-center gap-2">
			<h3 class="mr-auto card-title text-base">{m.private_key_title()}</h3>
			<span class="badge badge-sm badge-warning">{m.private_key_badge()}</span>
		</div>
		<p class="text-sm text-base-content/70">{m.private_key_from({ name: source })}</p>
		<p class="text-sm text-warning">{m.private_key_warning()}</p>

		{#if revealed}
			<textarea
				readonly
				class="textarea-bordered textarea h-40 w-full font-mono text-xs leading-relaxed"
				value={pem}></textarea>
		{/if}

		<div class="card-actions">
			<button class="btn btn-outline btn-sm" onclick={() => (revealed = !revealed)}>
				{revealed ? m.private_key_hide() : m.private_key_show()}
			</button>
			<button class="btn btn-outline btn-sm" onclick={copy}>
				{copied ? m.copied() : m.copy()}
			</button>
			<button class="btn btn-outline btn-sm" onclick={download}>{m.download_key()}</button>
			{#if onclear}
				<button class="btn btn-ghost btn-sm" onclick={onclear}>{m.clear()}</button>
			{/if}
		</div>
	</div>
</div>
