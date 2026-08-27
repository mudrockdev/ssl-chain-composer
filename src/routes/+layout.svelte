<script lang="ts">
	import type { Path } from '$app/types';
	import { resolve } from '$app/paths';
	import { page } from '$app/state';
	import {
		baseLocale,
		extractLocaleFromUrl,
		getTextDirection,
		locales,
		localizeHref,
		overwriteGetLocale
	} from '#lib/paraglide/runtime.js';
	import './layout.css';
	import favicon from '#lib/assets/favicon.svg';

	let { children } = $props();

	// Static site: no server middleware — the locale is derived from the URL
	// both during prerendering and on the client.
	overwriteGetLocale(() => extractLocaleFromUrl(page.url.href) ?? baseLocale);

	const locale = $derived(extractLocaleFromUrl(page.url.href) ?? baseLocale);

	// <html lang/dir> can't be set from a component; sync it after hydration
	$effect(() => {
		document.documentElement.lang = locale;
		document.documentElement.dir = getTextDirection(locale);
	});
</script>

<svelte:head>
	<link rel="icon" href={favicon} />
</svelte:head>

{@render children()}

<!-- crawlable links so every locale gets prerendered -->
<div style="display:none">
	{#each locales as l (l)}
		<a href={resolve(localizeHref(page.url.pathname, { locale: l }) as Path)}>{l}</a>
	{/each}
</div>
