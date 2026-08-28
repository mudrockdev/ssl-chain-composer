<script lang="ts">
	import { m } from '#lib/paraglide/messages.js';
	import { parseCertificateFile } from '#lib/cert.js';
	import { extractPfx, isPfxFile, PfxPasswordError } from '#lib/pfx.js';

	let {
		value = $bindable(''),
		onerror,
		onprivatekey
	}: {
		value?: string;
		onerror?: (message: string) => void;
		onprivatekey?: (pem: string, source: string) => void;
	} = $props();

	let fileInput: HTMLInputElement | undefined = $state();

	/** PFX awaiting a password: kept in memory so the user can retry without re-picking it. */
	let locked = $state<{ name: string; data: ArrayBuffer } | null>(null);
	let password = $state('');
	let unlocking = $state(false);
	let wrongPassword = $state(false);

	function addPem(pem: string) {
		value = value.trim() ? `${value.trim()}\n${pem}` : pem;
	}

	/** Returns false when the file needs a password. */
	async function openPfx(name: string, data: ArrayBuffer, pass: string): Promise<boolean> {
		try {
			const { certificates, privateKeyPem } = await extractPfx(data, pass);
			if (certificates.length) {
				addPem(certificates.map((c) => c.toString('pem')).join('\n'));
			}
			if (privateKeyPem) onprivatekey?.(privateKeyPem, name);
			if (!certificates.length && !privateKeyPem) onerror?.(m.error_file_read({ name }));
			return true;
		} catch (err) {
			if (err instanceof PfxPasswordError) return false;
			onerror?.(m.error_pfx_read({ name }));
			return true;
		}
	}

	async function onFiles(event: Event) {
		const files = (event.currentTarget as HTMLInputElement).files;
		if (!files) return;
		for (const file of files) {
			const data = await file.arrayBuffer();
			if (isPfxFile(file.name)) {
				// most PFX files are protected; try an empty password before asking
				if (!(await openPfx(file.name, data, ''))) {
					locked = { name: file.name, data };
					password = '';
					wrongPassword = false;
				}
				continue;
			}
			try {
				const certs = parseCertificateFile(data);
				if (!certs.length) throw new Error('empty');
				addPem(certs.map((c) => c.toString('pem')).join('\n'));
			} catch {
				onerror?.(m.error_file_read({ name: file.name }));
			}
		}
		if (fileInput) fileInput.value = '';
	}

	async function unlock() {
		if (!locked) return;
		unlocking = true;
		wrongPassword = false;
		try {
			if (await openPfx(locked.name, locked.data, password)) {
				locked = null;
				password = '';
			} else {
				wrongPassword = true;
			}
		} finally {
			unlocking = false;
		}
	}
</script>

<textarea
	bind:value
	class="textarea-bordered textarea h-64 w-full font-mono text-xs leading-relaxed"
	placeholder={m.paste_placeholder()}
	spellcheck="false"></textarea>

{#if locked}
	<div class="mt-2 rounded-box border border-base-300 bg-base-200 p-4">
		<p class="text-sm">{m.pfx_password_prompt({ name: locked.name })}</p>
		<form class="mt-2 flex flex-wrap gap-2" onsubmit={(e) => (e.preventDefault(), unlock())}>
			<!-- svelte-ignore a11y_autofocus -->
			<input
				type="password"
				bind:value={password}
				autofocus
				autocomplete="off"
				class="input-bordered input input-sm min-w-0 flex-1 font-mono"
				placeholder={m.pfx_password_placeholder()}
			/>
			<button type="submit" class="btn btn-sm btn-primary" disabled={unlocking}>
				{#if unlocking}<span class="loading loading-xs loading-spinner"
					></span>{m.working()}{:else}{m.pfx_unlock()}{/if}
			</button>
			<button type="button" class="btn btn-ghost btn-sm" onclick={() => (locked = null)}>
				{m.clear()}
			</button>
		</form>
		{#if wrongPassword}
			<p class="mt-2 text-sm text-error">{m.pfx_wrong_password()}</p>
		{/if}
	</div>
{/if}

<div class="mt-2 flex flex-wrap items-center gap-2">
	<button type="button" class="btn btn-outline btn-sm" onclick={() => fileInput?.click()}>
		{m.upload_file()}
	</button>
	<input
		bind:this={fileInput}
		type="file"
		class="hidden"
		multiple
		accept=".pem,.crt,.cer,.der,.cert,.txt,.pfx,.p12"
		onchange={onFiles}
	/>
	{#if value.trim()}
		<button type="button" class="btn btn-ghost btn-sm" onclick={() => (value = '')}>
			{m.clear()}
		</button>
	{/if}
	<span class="text-xs text-base-content/50">{m.upload_hint()}</span>
	<span class="ml-auto text-xs text-base-content/50">{m.privacy_note()}</span>
</div>
