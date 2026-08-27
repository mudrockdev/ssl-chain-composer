<script lang="ts">
	import { m } from '#lib/paraglide/messages.js';
	import { parseCertificateFile } from '#lib/cert.js';

	let { value = $bindable(''), onerror }: { value?: string; onerror?: (message: string) => void } =
		$props();

	let fileInput: HTMLInputElement | undefined = $state();

	async function onFiles(event: Event) {
		const files = (event.currentTarget as HTMLInputElement).files;
		if (!files) return;
		for (const file of files) {
			try {
				const certs = parseCertificateFile(await file.arrayBuffer());
				if (!certs.length) throw new Error('empty');
				const pems = certs.map((c) => c.toString('pem')).join('\n');
				value = value.trim() ? `${value.trim()}\n${pems}` : pems;
			} catch {
				onerror?.(m.error_file_read({ name: file.name }));
			}
		}
		if (fileInput) fileInput.value = '';
	}
</script>

<textarea
	bind:value
	class="textarea-bordered textarea h-48 w-full font-mono text-xs leading-relaxed"
	placeholder={m.paste_placeholder()}
	spellcheck="false"></textarea>
<div class="mt-2 flex flex-wrap items-center gap-2">
	<button type="button" class="btn btn-outline btn-sm" onclick={() => fileInput?.click()}>
		{m.upload_file()}
	</button>
	<input
		bind:this={fileInput}
		type="file"
		class="hidden"
		multiple
		accept=".pem,.crt,.cer,.der,.cert,.txt"
		onchange={onFiles}
	/>
	{#if value.trim()}
		<button type="button" class="btn btn-ghost btn-sm" onclick={() => (value = '')}>
			{m.clear()}
		</button>
	{/if}
	<span class="ml-auto text-xs text-base-content/50">{m.privacy_note()}</span>
</div>
