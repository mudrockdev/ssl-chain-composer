<script lang="ts">
	import { m } from '#lib/paraglide/messages.js';
	import { getLocale } from '#lib/paraglide/runtime.js';
	import { daysUntil, validityStatus, type CertInfo } from '#lib/cert.js';

	let { info, role }: { info: CertInfo; role?: 'leaf' | 'intermediate' | 'root' } = $props();

	const status = $derived(validityStatus(info));
	const days = $derived(daysUntil(info.notAfter));

	function fmt(d: Date): string {
		return d.toLocaleString(getLocale(), { dateStyle: 'medium', timeStyle: 'short' });
	}
</script>

<div class="card border border-base-300 bg-base-100 shadow-sm">
	<div class="card-body gap-3 p-5">
		<div class="flex flex-wrap items-center gap-2">
			<h3 class="mr-auto card-title text-base break-all">{info.subjectCN}</h3>
			{#if role === 'leaf'}
				<span class="badge badge-sm badge-neutral">{m.badge_leaf()}</span>
			{:else if role === 'intermediate'}
				<span class="badge badge-sm badge-neutral">{m.badge_intermediate()}</span>
			{:else if role === 'root'}
				<span class="badge badge-sm badge-neutral">{m.badge_root()}</span>
			{/if}
			{#if info.isCA && role !== 'root' && role !== 'intermediate'}
				<span class="badge badge-ghost badge-sm">{m.badge_ca()}</span>
			{/if}
			{#if info.selfSigned}
				<span class="badge badge-sm badge-warning">{m.badge_self_signed()}</span>
			{/if}
			{#if info.fetched}
				<span class="badge badge-sm badge-info">{m.badge_fetched()}</span>
			{/if}
			{#if status === 'expired'}
				<span class="badge badge-sm badge-error">{m.status_expired()}</span>
			{:else if status === 'not_yet_valid'}
				<span class="badge badge-sm badge-warning">{m.status_not_yet_valid()}</span>
			{:else if days <= 30}
				<span class="badge badge-sm badge-warning"
					>{m.status_valid()} — {m.expires_in_days({ days })}</span
				>
			{:else}
				<span class="badge badge-sm badge-success"
					>{m.status_valid()} — {m.expires_in_days({ days })}</span
				>
			{/if}
		</div>

		<dl class="grid grid-cols-1 gap-x-6 gap-y-1.5 text-sm sm:grid-cols-[max-content_1fr]">
			<dt class="font-medium text-base-content/60">{m.field_subject()}</dt>
			<dd class="break-all">{info.subject}</dd>
			<dt class="font-medium text-base-content/60">{m.field_issuer()}</dt>
			<dd class="break-all">{info.issuer}</dd>
			<dt class="font-medium text-base-content/60">{m.field_valid_from()}</dt>
			<dd>{fmt(info.notBefore)}</dd>
			<dt class="font-medium text-base-content/60">{m.field_valid_to()}</dt>
			<dd class={status === 'expired' ? 'font-semibold text-error' : ''}>
				{fmt(info.notAfter)}
				{#if status === 'expired'}({m.expired_days_ago({ days: -days })}){/if}
			</dd>
			{#if info.sans.length}
				<dt class="font-medium text-base-content/60">{m.field_sans()}</dt>
				<dd class="flex flex-wrap gap-1">
					{#each info.sans as san (san)}
						<span class="badge badge-outline font-mono badge-sm">{san}</span>
					{/each}
				</dd>
			{/if}
			<dt class="font-medium text-base-content/60">{m.field_public_key()}</dt>
			<dd>{info.keyAlg}</dd>
			<dt class="font-medium text-base-content/60">{m.field_sig_alg()}</dt>
			<dd>{info.sigAlg}</dd>
			<dt class="font-medium text-base-content/60">{m.field_serial()}</dt>
			<dd class="font-mono text-xs break-all">{info.serial}</dd>
			{#if info.keyUsages.length}
				<dt class="font-medium text-base-content/60">{m.field_key_usage()}</dt>
				<dd>{info.keyUsages.join(', ')}</dd>
			{/if}
			{#if info.extKeyUsages.length}
				<dt class="font-medium text-base-content/60">{m.field_ext_key_usage()}</dt>
				<dd>{info.extKeyUsages.join(', ')}</dd>
			{/if}
			<dt class="font-medium text-base-content/60">{m.field_sha1()}</dt>
			<dd class="font-mono text-xs break-all">{info.sha1}</dd>
			<dt class="font-medium text-base-content/60">{m.field_sha256()}</dt>
			<dd class="font-mono text-xs break-all">{info.sha256}</dd>
		</dl>
	</div>
</div>
