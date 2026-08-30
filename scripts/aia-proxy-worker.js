/**
 * Minimal CORS proxy for AIA certificate downloads, deployable on Cloudflare
 * Workers (free tier: 100k requests/day). Public CORS proxies are hobby
 * projects and several are SNI-blocked in some countries — this gives the app
 * its own reliable fallback on a workers.dev subdomain.
 *
 * Deploy (pick one):
 *   1. Dashboard: https://dash.cloudflare.com → Workers & Pages → Create →
 *      paste this file → Deploy. Note the URL, e.g. https://aia-proxy.<you>.workers.dev
 *   2. CLI: bunx wrangler deploy scripts/aia-proxy-worker.js --name aia-proxy
 *
 * Then point the app at it in .env:
 *   VITE_AIA_PROXY=https://aia-proxy.<you>.workers.dev/?url=
 *
 * Usage: GET /?url=<encoded AIA URL>
 * Restricted on purpose: GET only, http(s) targets only, 5s timeout, 100 KB
 * response cap — enough for any certificate, useless as a general proxy.
 */

const MAX_BYTES = 100_000;
const CORS_HEADERS = {
	'access-control-allow-origin': '*',
	'access-control-allow-methods': 'GET',
	'cache-control': 'public, max-age=86400'
};

export default {
	async fetch(request) {
		if (request.method !== 'GET') {
			return new Response('method not allowed', { status: 405, headers: CORS_HEADERS });
		}
		const target = new URL(request.url).searchParams.get('url');
		console.log(request);
		let parsed;
		try {
			parsed = new URL(target ?? '');
		} catch {
			return new Response('missing or invalid ?url=', { status: 400, headers: CORS_HEADERS });
		}
		if (parsed.protocol !== 'http:' && parsed.protocol !== 'https:') {
			return new Response('http(s) targets only', { status: 400, headers: CORS_HEADERS });
		}

		let upstream;
		try {
			upstream = await fetch(parsed, {
				signal: AbortSignal.timeout(5000),
				redirect: 'follow',
				headers: { 'user-agent': 'aia-proxy' }
			});
		} catch {
			return new Response('upstream fetch failed', { status: 502, headers: CORS_HEADERS });
		}
		if (!upstream.ok) {
			return new Response(`upstream returned ${upstream.status}`, {
				status: 502,
				headers: CORS_HEADERS
			});
		}

		const body = await upstream.arrayBuffer();
		if (body.byteLength > MAX_BYTES) {
			return new Response('response too large for a certificate', {
				status: 502,
				headers: CORS_HEADERS
			});
		}
		return new Response(body, {
			headers: {
				...CORS_HEADERS,
				'content-type': upstream.headers.get('content-type') ?? 'application/pkix-cert'
			}
		});
	}
};
