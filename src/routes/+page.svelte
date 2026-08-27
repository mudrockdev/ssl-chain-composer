<script lang="ts">
	import type { Path } from '$app/types';
	import { resolve } from '$app/paths';
	import { page } from '$app/state';
	import { m } from '#lib/paraglide/messages.js';
	import { getLocale, locales, localizeHref } from '#lib/paraglide/runtime.js';
	import CertChecker from '#lib/components/CertChecker.svelte';
	import ChainComposer from '#lib/components/ChainComposer.svelte';

	let tab = $state<'checker' | 'composer'>('checker');
</script>

<svelte:head>
	<title>{m.app_title()}</title>
	<meta name="description" content={m.app_subtitle()} />
</svelte:head>

<div class="min-h-screen bg-base-200">
	<header class="mx-auto max-w-3xl px-4 pt-10 pb-6 text-center">
		<div class="mb-2 flex justify-end gap-1">
			{#each locales as locale (locale)}
				<a
					href={resolve(localizeHref(page.url.pathname, { locale }) as Path)}
					class="btn btn-ghost uppercase btn-xs"
					class:btn-active={locale === getLocale()}>{locale}</a
				>
			{/each}
		</div>
		<h1 class="text-3xl font-bold">{m.app_title()}</h1>
		<p class="mx-auto mt-2 max-w-xl text-sm text-base-content/70">{m.app_subtitle()}</p>
	</header>

	<main class="mx-auto max-w-3xl px-4 pb-16">
		<div role="tablist" class="tabs tabs-box mb-6 justify-center">
			<button
				role="tab"
				class="tab"
				class:tab-active={tab === 'checker'}
				onclick={() => (tab = 'checker')}>{m.tab_checker()}</button
			>
			<button
				role="tab"
				class="tab"
				class:tab-active={tab === 'composer'}
				onclick={() => (tab = 'composer')}>{m.tab_composer()}</button
			>
		</div>

		{#if tab === 'checker'}
			<CertChecker />
		{:else}
			<ChainComposer />
		{/if}
	</main>
</div>
