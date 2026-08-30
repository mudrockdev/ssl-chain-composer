import type * as x509 from '@peculiar/x509';
import { parseCertificateFile } from './parse.js';

/**
 * Why this file exists.
 *
 * A certificate's AIA extension points at the issuer certificate, e.g.
 * http://secure.globalsign.com/cacert/gsrsaovsslca2018.crt — but a browser cannot read it:
 *
 *   1. the URL is plain http://, which is blocked as mixed content on an https page, and
 *   2. CA servers do not send `Access-Control-Allow-Origin`, so even over https the
 *      response is withheld from the page by the same-origin policy.
 *
 * Neither is fixable on the CA's side and this app has no backend, so downloads go through
 * public CORS relays that re-serve the bytes with the missing header. Only the CA's own
 * public certificate URL is ever sent to a relay — never a user's certificate.
 *
 * The relays are tried together and the first usable response wins, so one being slow,
 * rate-limited or down does not break the download.
 */
/**
 * Optional self-hosted relay (see scripts/aia-proxy-worker.js), e.g.
 * `VITE_AIA_PROXY=https://aia-proxy.example.workers.dev` in .env. Recommended:
 * the public relays below are hobby projects and some are SNI-blocked in some
 * countries. Accepts a bare base URL or a full template ending in `?url=`.
 */
const CUSTOM_RELAY: string | undefined = import.meta.env.VITE_AIA_PROXY;

function customRelay(base: string): (url: string) => string {
	const trimmed = base.trim().replace(/\/+$/, '');
	const prefix = trimmed.includes('?') ? trimmed : `${trimmed}/?url=`;
	return (url) => `${prefix}${encodeURIComponent(url)}`;
}

const RELAYS: Array<(url: string) => string> = [
	...(CUSTOM_RELAY ? [customRelay(CUSTOM_RELAY)] : []),
	(url) => `https://cors.eu.org/${url}`,
	(url) => `https://corsproxy.io/?url=${encodeURIComponent(url)}`,
	(url) => `https://api.allorigins.win/raw?url=${encodeURIComponent(url)}`,
	(url) => `https://api.codetabs.com/v1/proxy?quest=${encodeURIComponent(url)}`,
	(url) => `https://api.cors.lol/?url=${encodeURIComponent(url)}`
];

const DIRECT_TIMEOUT_MS = 5_000;
const RELAY_TIMEOUT_MS = 12_000;

/** Downloaded issuer certificates, keyed by AIA URL, for the lifetime of the page. */
const cache = new Map<string, x509.X509Certificate[]>();

async function load(url: string, timeoutMs: number): Promise<x509.X509Certificate[]> {
	try {
		const res = await fetch(url, { signal: AbortSignal.timeout(timeoutMs), redirect: 'follow' });
		if (!res.ok) return [];
		const buf = await res.arrayBuffer();
		if (!buf.byteLength) return [];
		return parseCertificateFile(buf);
	} catch {
		// blocked, offline, timed out, or the response was not a certificate
		return [];
	}
}

/** Resolve with the first non-empty result; null once every attempt has come up empty. */
function firstNonEmpty<T>(attempts: Array<Promise<T[]>>): Promise<T[]> {
	return new Promise((resolve) => {
		let pending = attempts.length;
		if (!pending) return resolve([]);
		for (const attempt of attempts) {
			attempt.then(
				(result) => {
					if (result.length) resolve(result);
					else if (--pending === 0) resolve([]);
				},
				() => {
					if (--pending === 0) resolve([]);
				}
			);
		}
	});
}

/**
 * Download the certificate(s) published at an AIA caIssuers URL.
 * Returns [] when the certificate could not be retrieved by any route.
 */
export async function fetchCaIssuers(url: string): Promise<x509.X509Certificate[]> {
	const cached = cache.get(url);
	if (cached) return cached;

	// upgrade http:// so the direct attempt is not killed as mixed content
	const direct = url.replace(/^http:\/\//i, 'https://');
	let certs = await load(direct, DIRECT_TIMEOUT_MS);

	// the CA sent no CORS header (the common case) — go through the relays
	if (!certs.length) {
		certs = await firstNonEmpty(RELAYS.map((relay) => load(relay(url), RELAY_TIMEOUT_MS)));
	}

	if (certs.length) cache.set(url, certs);
	return certs;
}
