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
	<header class="border-b border-base-300 bg-base-100">
		<div class="mx-auto flex max-w-7xl flex-wrap items-center gap-x-6 gap-y-3 px-4 py-4 lg:px-8">
			<div class="mr-auto">
				<h1 class="text-xl font-bold tracking-tight">{m.app_title()}</h1>
				<p class="mt-0.5 hidden max-w-2xl text-sm text-base-content/60 sm:block">
					{m.app_subtitle()}
				</p>
			</div>

			<div role="tablist" class="tabs tabs-box tabs-sm sm:tabs-md">
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

			<div class="join">
				{#each locales as locale (locale)}
					<a
						href={resolve(localizeHref(page.url.pathname, { locale }) as Path)}
						class="btn join-item uppercase btn-sm {locale === getLocale()
							? 'btn-neutral'
							: 'btn-ghost'}">{locale}</a
					>
				{/each}
			</div>
		</div>
	</header>

	<main class="mx-auto max-w-7xl px-4 py-8 lg:px-8">
		{#if tab === 'checker'}
			<CertChecker />
		{:else}
			<ChainComposer />
		{/if}
	</main>
</div>
