#!/usr/bin/env bun
/**
 * Build-time generator for src/lib/embedded-certs.ts.
 *
 * Downloads the CA issuer certificates that AIA caIssuers URLs of the major
 * public CAs (last ~10 years) point to, follows the AIA pointers of the
 * downloaded certificates too (which yields the root certificate URLs), and
 * embeds everything as a `URL → PEM` map. The chain composer checks this map
 * first, so missing intermediates resolve without any network request — no
 * CORS or mixed-content problems.
 *
 * The output file is gitignored. It is refreshed by `vite build` and
 * `bun run gen:certs`, and generated on demand when missing by the
 * `bun test` preload (see bunfig.toml). Unreachable seed URLs are reported
 * but never fail the run — CAs retire repository paths all the time.
 */
import 'reflect-metadata';
import * as x509 from '@peculiar/x509';
import { AsnConvert } from '@peculiar/asn1-schema';
import { ContentInfo, SignedData } from '@peculiar/asn1-cms';
import { existsSync } from 'fs';
import { parseCertificateFile } from '../src/lib/cert';

const OUT_FILE = new URL('../src/lib/embedded-certs.ts', import.meta.url).pathname;
const CONCURRENCY = 8;
/** seed URLs + up to three hops of AIA pointers (intermediate → root) */
const MAX_ROUNDS = 4;
const TIMEOUT_MS = 15_000;
/** ignore certificates that expired more than 10 years ago */
const EXPIRY_CUTOFF = Date.now() - 10 * 365.25 * 86_400_000;
const ID_SIGNED_DATA = '1.2.840.113549.1.7.2';

/** AIA pointers found inside fetched certs that are known to be dead — never probed. */
const DEAD_DISCOVERED = new Set([
	'http://apps.identrust.com/roots/dstrootcax3.p7c',
	'http://x.ss2.us/x.cer'
]);

function seedUrls(): string[] {
	const urls: string[] = [];

	// --- Sectigo / Comodo / USERTrust (incl. ZeroSSL & cPanel brands) ---
	for (const name of [
		'SectigoRSADomainValidationSecureServerCA',
		'SectigoRSAOrganizationValidationSecureServerCA',
		'SectigoRSAExtendedValidationSecureServerCA',
		'SectigoECCDomainValidationSecureServerCA',
		'SectigoECCOrganizationValidationSecureServerCA',
		'SectigoECCExtendedValidationSecureServerCA',
		'SectigoPublicServerAuthenticationCADVR36',
		'SectigoPublicServerAuthenticationCAOVR36',
		'SectigoPublicServerAuthenticationCAEVR36',
		'SectigoPublicServerAuthenticationCADVE36',
		'SectigoPublicServerAuthenticationCAOVE36',
		'SectigoPublicServerAuthenticationCAEVE36',
		'SectigoPublicServerAuthenticationRootR46',
		'SectigoPublicServerAuthenticationRootE46',
		'USERTrustRSAAAACA',
		'USERTrustECCAAACA',
		'cPanelIncCertificationAuthority'
	]) {
		urls.push(`http://crt.sectigo.com/${name}.crt`);
	}
	urls.push(
		'http://crt.usertrust.com/USERTrustRSAAddTrustCA.crt',
		'http://crt.usertrust.com/USERTrustECCAddTrustCA.crt',
		'http://crt.comodoca.com/COMODORSAAddTrustCA.crt',
		'http://crt.comodoca.com/COMODORSADomainValidationSecureServerCA.crt',
		'http://crt.comodoca.com/COMODORSAOrganizationValidationSecureServerCA.crt',
		'http://crt.comodoca.com/COMODORSAExtendedValidationSecureServerCA.crt',
		'http://crt.comodoca.com/COMODOECCDomainValidationSecureServerCA2.crt',
		'http://zerossl.crt.sectigo.com/ZeroSSLRSADomainSecureSiteCA.crt',
		'http://zerossl.crt.sectigo.com/ZeroSSLECCDomainSecureSiteCA.crt'
	);

	// --- DigiCert (incl. GeoTrust / Thawte / RapidSSL / Cloudflare brands) ---
	for (const name of [
		'DigiCertSHA2SecureServerCA',
		'DigiCertSHA2SecureServerCA-2',
		'DigiCertSHA2HighAssuranceServerCA',
		'DigiCertSHA2ExtendedValidationServerCA',
		'DigiCertTLSRSASHA2562020CA1',
		'DigiCertTLSRSASHA2562020CA1-1',
		'DigiCertTLSHybridECCSHA3842020CA1',
		'DigiCertTLSHybridECCSHA3842020CA1-1',
		'DigiCertGlobalG2TLSRSASHA2562020CA1',
		'DigiCertGlobalG2TLSRSASHA2562020CA1-1',
		'DigiCertGlobalG3TLSECCSHA3842020CA1',
		'DigiCertGlobalG3TLSECCSHA3842020CA1-1',
		'DigiCertG5TLSRSA4096SHA3842021CA1-1',
		'DigiCertG5TLSECCSHA3842021CA1-1',
		'DigiCertEVRSACAG2',
		'DigiCertGlobalCAG2',
		'GeoTrustRSACA2018',
		'GeoTrustECCCA2018',
		'GeoTrustTLSRSACAG1',
		'GeoTrustTLSECCCAG1',
		'RapidSSLRSACA2018',
		'RapidSSLTLSRSACAG1',
		'RapidSSLTLSECCCAG1',
		'ThawteRSACA2018',
		'ThawteTLSRSACAG1',
		'ThawteEVRSACAG2',
		'CloudflareIncECCCA-3'
	]) {
		urls.push(`http://cacerts.digicert.com/${name}.crt`);
	}

	// --- Let's Encrypt (X1/X3 era, R3/R4 + E1/E2, 2024 R10-R14 + E5-E9,
	//     2026 Root YE/YR hierarchy with YE1+/YR1+ issuing CAs) ---
	const lencr = ['r3', 'r4', 'e1', 'e2', 'ye', 'yr'];
	for (let n = 10; n <= 14; n++) lencr.push(`r${n}`);
	for (let n = 5; n <= 9; n++) lencr.push(`e${n}`);
	for (let n = 1; n <= 3; n++) lencr.push(`ye${n}`, `yr${n}`);
	for (const name of lencr) {
		urls.push(`http://${name}.i.lencr.org/`);
	}
	urls.push('http://cert.int-x3.letsencrypt.org/', 'http://cert.int-x1.letsencrypt.org/');

	// --- Google Trust Services ---
	for (const name of ['wr1', 'wr2', 'wr3', 'wr4', 'wr5', 'we1', 'we2', 'we3', 'we4', 'we5']) {
		urls.push(`http://i.pki.goog/${name}.crt`);
	}
	urls.push(
		'http://pki.goog/repo/certs/gts1c3.der',
		'http://pki.goog/repo/certs/gts1d4.der',
		'http://pki.goog/repo/certs/gts1p5.der'
	);

	// --- Amazon Trust Services ---
	for (const gen of ['r2m', 'e2m', 'e3m']) {
		for (const n of ['01', '02', '03', '04']) {
			urls.push(`http://crt.${gen}${n}.amazontrust.com/${gen}${n}.cer`);
		}
	}

	// --- GoDaddy / Starfield ---
	urls.push(
		'http://certificates.godaddy.com/repository/gdig2.crt',
		'http://certs.starfieldtech.com/repository/sfig2.crt'
	);

	// --- GlobalSign (classic + Atlas quarterly issuing CAs) ---
	for (const name of [
		'gsrsadvsslca2018',
		'gsrsaovsslca2018',
		'gsgccr3dvtlsca2020',
		'gsalphasha2g2r1',
		'gsdomainvalsha2g2r1',
		'gsorganizationvalsha2g2r1',
		'gsextendvalsha2g3r3'
	]) {
		urls.push(`http://secure.globalsign.com/cacert/${name}.crt`);
	}
	// Atlas issuing CAs are published per quarter — probe 2022 up to the current quarter
	const now = new Date();
	const currentQuarter = Math.floor(now.getMonth() / 3) + 1;
	for (let year = 2022; year <= now.getFullYear(); year++) {
		for (let quarter = 1; quarter <= 4; quarter++) {
			if (year === now.getFullYear() && quarter > currentQuarter) break;
			for (const kind of ['dv', 'ov']) {
				urls.push(
					`http://secure.globalsign.com/cacert/gsatlasr3${kind}tlsca${year}q${quarter}.crt`
				);
			}
		}
	}

	// --- Entrust ---
	urls.push(
		'http://aia.entrust.net/l1k-chain256.cer',
		'http://aia.entrust.net/l1m-chain256.cer',
		'http://aia.entrust.net/l1j-ec1.cer'
	);

	// --- Microsoft (Azure / microsoft.com issuing CAs) ---
	for (const n of ['01', '02']) {
		urls.push(encodeURI(`http://www.microsoft.com/pki/mscorp/Microsoft RSA TLS CA ${n}.crt`));
	}
	for (const n of ['01', '02', '05', '06']) {
		urls.push(
			encodeURI(
				`http://www.microsoft.com/pkiops/certs/Microsoft Azure TLS Issuing CA ${n} - xsign.crt`
			)
		);
	}
	for (const alg of ['RSA', 'ECC']) {
		for (const n of ['03', '04', '07', '08']) {
			urls.push(
				encodeURI(
					`http://www.microsoft.com/pkiops/certs/Microsoft Azure ${alg} TLS Issuing CA ${n} - xsign.crt`
				)
			);
		}
	}

	// --- Certum ---
	urls.push('http://repository.certum.pl/dvcasha2.cer', 'http://repository.certum.pl/ovcasha2.cer');

	return [...new Set(urls)];
}

async function fetchBuffer(url: string): Promise<ArrayBuffer | null> {
	for (let attempt = 0; attempt < 2; attempt++) {
		try {
			const res = await fetch(url, {
				signal: AbortSignal.timeout(TIMEOUT_MS),
				headers: { 'user-agent': 'embedded-certs-generator' }
			});
			if (!res.ok) return null;
			return await res.arrayBuffer();
		} catch {
			// retry once on network errors / timeouts
		}
	}
	return null;
}

/** Parse PEM text, a single DER certificate, or a PKCS#7 (CMS) chain. */
function parseAnyCertificates(buf: ArrayBuffer): x509.X509Certificate[] {
	try {
		return parseCertificateFile(buf);
	} catch {
		// not PEM / plain DER — try PKCS#7
	}
	try {
		const info = AsnConvert.parse(new Uint8Array(buf), ContentInfo);
		if (info.contentType !== ID_SIGNED_DATA) return [];
		const signed = AsnConvert.parse(info.content, SignedData);
		const certs: x509.X509Certificate[] = [];
		for (const choice of signed.certificates ?? []) {
			if (choice.certificate) {
				certs.push(new x509.X509Certificate(AsnConvert.serialize(choice.certificate)));
			}
		}
		return certs;
	} catch {
		return [];
	}
}

function isWantedCa(cert: x509.X509Certificate): boolean {
	const bc = cert.getExtension(x509.BasicConstraintsExtension);
	return (bc?.ca ?? false) && cert.notAfter.getTime() >= EXPIRY_CUTOFF;
}

function caIssuerUrlsOf(cert: x509.X509Certificate): string[] {
	const aia = cert.getExtension(x509.AuthorityInfoAccessExtension);
	return (
		aia?.caIssuers
			.filter((n) => n.type === 'url')
			.map((n) => n.value)
			.filter((u) => /^https?:\/\//i.test(u)) ?? []
	);
}

async function runPool<T>(items: T[], worker: (item: T) => Promise<void>): Promise<void> {
	const queue = [...items];
	await Promise.all(
		Array.from({ length: Math.min(CONCURRENCY, queue.length) }, async () => {
			for (let item = queue.shift(); item !== undefined; item = queue.shift()) {
				await worker(item);
			}
		})
	);
}

function getCN(cert: x509.X509Certificate): string {
	return cert.subjectName.getField('CN')[0] ?? cert.subject;
}

async function generate(): Promise<void> {
	const found = new Map<string, x509.X509Certificate[]>();
	const failed: string[] = [];
	const visited = new Set<string>([...DEAD_DISCOVERED].map((u) => u.toLowerCase()));

	let round = seedUrls();
	for (let depth = 0; depth < MAX_ROUNDS && round.length; depth++) {
		for (const url of round) visited.add(url.toLowerCase());
		const discovered = new Set<string>();
		await runPool(round, async (url) => {
			const buf = await fetchBuffer(url);
			const certs = buf ? parseAnyCertificates(buf).filter(isWantedCa) : [];
			if (!certs.length) {
				failed.push(url);
				return;
			}
			found.set(url, certs);
			for (const cert of certs) {
				for (const aia of caIssuerUrlsOf(cert)) {
					if (!visited.has(aia.toLowerCase())) discovered.add(aia);
				}
			}
		});
		console.log(`round ${depth + 1}: ${round.length} URLs → ${found.size} total hits`);
		round = [...discovered];
	}

	if (found.size === 0) {
		if (existsSync(OUT_FILE)) {
			console.warn('no certificates fetched (offline?) — keeping the existing embedded-certs.ts');
			return;
		}
		throw new Error('no certificates fetched and no existing embedded-certs.ts');
	}

	const entries = [...found.entries()].sort(([a], [b]) => a.localeCompare(b));
	const certCount = entries.reduce((n, [, certs]) => n + certs.length, 0);
	const date = (d: Date) => d.toISOString().slice(0, 10);

	let body = '';
	for (const [url, certs] of entries) {
		const label = certs.map((c) => `${getCN(c)} (${date(c.notBefore)} → ${date(c.notAfter)})`);
		body += `\t// ${label.join(', ')}\n`;
		body += `\t'${url}': \`${certs.map((c) => c.toString('pem')).join('\n')}\`,\n`;
	}

	const output = `// AUTO-GENERATED FILE — do not edit by hand.
// Regenerate with: bun run gen:certs (scripts/generate-embedded-certs.ts)
// ${entries.length} URLs, ${certCount} certificates.

/**
 * CA certificates keyed by the AIA caIssuers URL that serves them.
 * A value may contain multiple concatenated PEM blocks when the URL
 * serves a PKCS#7 chain.
 */
export const EMBEDDED_CERTS: Record<string, string> = {
${body}};
`;

	await Bun.write(OUT_FILE, output);
	Bun.spawnSync(['bun', 'x', 'prettier', '--write', OUT_FILE]);

	console.log(`\nwrote ${OUT_FILE}: ${entries.length} URLs, ${certCount} certificates`);
	if (failed.length) {
		console.log(`\nunreachable/unparsable URLs (${failed.length}):`);
		for (const url of failed.sort()) console.log(`  ${url}`);
	}
}

async function isPopulated(): Promise<boolean> {
	return existsSync(OUT_FILE) && (await Bun.file(OUT_FILE).text()).includes('BEGIN CERTIFICATE');
}

// Run as CLI (bun run gen:certs, vite build): always refresh.
// Preloaded by `bun test` (import.meta.main is false): only generate when the
// gitignored output file is missing/empty — and never call process.exit, which
// would kill the test runner.
if (import.meta.main || !(await isPopulated())) {
	await generate();
}
