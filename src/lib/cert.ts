// tsyringe (used by @peculiar/x509) requires a reflect polyfill loaded first
import 'reflect-metadata';
import * as x509 from '@peculiar/x509';
import { fetchCaIssuers } from './ca-fetch.js';

export { parseCertificateFile, parseCertificates } from './parse.js';

export interface CertInfo {
	cert: x509.X509Certificate;
	pem: string;
	subject: string;
	subjectCN: string;
	issuer: string;
	issuerCN: string;
	notBefore: Date;
	notAfter: Date;
	serial: string;
	sigAlg: string;
	keyAlg: string;
	sans: string[];
	keyUsages: string[];
	extKeyUsages: string[];
	isCA: boolean;
	selfSigned: boolean;
	sha1: string;
	sha256: string;
	caIssuerUrls: string[];
	/** true when this cert was downloaded via AIA instead of provided by the user */
	fetched: boolean;
}

export interface ChainResult {
	ordered: CertInfo[];
	/** signature of ordered[i] verified against ordered[i+1] */
	links: boolean[];
	/** last cert is a self-signed root */
	rootIncluded: boolean;
	/** issuer name we could not find (chain incomplete) */
	missingIssuer: string | null;
	/** AIA URLs certificates were successfully fetched from */
	fetchedFrom: string[];
	/** AIA URL that failed to fetch (likely CORS) */
	fetchFailedUrl: string | null;
	/** provided certs that are not part of the chain */
	extras: CertInfo[];
}

const EKU_NAMES: Record<string, string> = {
	'1.3.6.1.5.5.7.3.1': 'TLS server authentication',
	'1.3.6.1.5.5.7.3.2': 'TLS client authentication',
	'1.3.6.1.5.5.7.3.3': 'Code signing',
	'1.3.6.1.5.5.7.3.4': 'Email protection',
	'1.3.6.1.5.5.7.3.8': 'Time stamping',
	'1.3.6.1.5.5.7.3.9': 'OCSP signing'
};

const KEY_USAGE_NAMES: [number, string][] = [
	[x509.KeyUsageFlags.digitalSignature, 'digitalSignature'],
	[x509.KeyUsageFlags.nonRepudiation, 'nonRepudiation'],
	[x509.KeyUsageFlags.keyEncipherment, 'keyEncipherment'],
	[x509.KeyUsageFlags.dataEncipherment, 'dataEncipherment'],
	[x509.KeyUsageFlags.keyAgreement, 'keyAgreement'],
	[x509.KeyUsageFlags.keyCertSign, 'keyCertSign'],
	[x509.KeyUsageFlags.cRLSign, 'cRLSign'],
	[x509.KeyUsageFlags.encipherOnly, 'encipherOnly'],
	[x509.KeyUsageFlags.decipherOnly, 'decipherOnly']
];

function hex(buf: ArrayBuffer): string {
	return [...new Uint8Array(buf)]
		.map((b) => b.toString(16).padStart(2, '0'))
		.join(':')
		.toUpperCase();
}

function getCN(name: x509.Name, fallback: string): string {
	const cn = name.getField('CN');
	if (cn.length) return cn[0];
	const o = name.getField('O');
	if (o.length) return o[0];
	return fallback;
}

export async function describeCert(cert: x509.X509Certificate, fetched = false): Promise<CertInfo> {
	const [sha1, sha256, selfSigned] = await Promise.all([
		cert.getThumbprint('SHA-1').then(hex),
		cert.getThumbprint('SHA-256').then(hex),
		cert.isSelfSigned()
	]);

	let keyAlg = cert.publicKey.algorithm.name;
	try {
		const key = await cert.publicKey.export();
		const alg = key.algorithm as RsaKeyAlgorithm & EcKeyAlgorithm;
		if (alg.modulusLength) keyAlg = `${alg.name} ${alg.modulusLength} bit`;
		else if (alg.namedCurve) keyAlg = `${alg.name} (${alg.namedCurve})`;
	} catch {
		// unsupported key type in this browser; keep the algorithm name
	}

	const sigAlg = cert.signatureAlgorithm.hash?.name
		? `${cert.signatureAlgorithm.name} (${cert.signatureAlgorithm.hash.name})`
		: cert.signatureAlgorithm.name;

	const san = cert.getExtension(x509.SubjectAlternativeNameExtension);
	const sans =
		san?.names.items.map((n) => (n.type === 'dns' ? n.value : `${n.type}:${n.value}`)) ?? [];

	const ku = cert.getExtension(x509.KeyUsagesExtension);
	const keyUsages = ku
		? KEY_USAGE_NAMES.filter(([flag]) => ku.usages & flag).map(([, name]) => name)
		: [];

	const eku = cert.getExtension(x509.ExtendedKeyUsageExtension);
	const extKeyUsages = eku?.usages.map((oid) => EKU_NAMES[oid as string] ?? oid) ?? [];

	const bc = cert.getExtension(x509.BasicConstraintsExtension);
	const aia = cert.getExtension(x509.AuthorityInfoAccessExtension);
	const caIssuerUrls = aia?.caIssuers.filter((n) => n.type === 'url').map((n) => n.value) ?? [];

	return {
		cert,
		pem: cert.toString('pem'),
		subject: cert.subject,
		subjectCN: getCN(cert.subjectName, cert.subject),
		issuer: cert.issuer,
		issuerCN: getCN(cert.issuerName, cert.issuer),
		notBefore: cert.notBefore,
		notAfter: cert.notAfter,
		serial: cert.serialNumber.toUpperCase(),
		sigAlg,
		keyAlg,
		sans,
		keyUsages,
		extKeyUsages,
		isCA: bc?.ca ?? false,
		selfSigned,
		sha1,
		sha256,
		caIssuerUrls,
		fetched
	};
}

async function verifiesAgainst(
	child: x509.X509Certificate,
	parent: x509.X509Certificate
): Promise<boolean> {
	try {
		return await child.verify({ publicKey: parent, signatureOnly: true });
	} catch {
		return false;
	}
}

/**
 * Pick the issuer for `child` out of downloaded candidates. A CA may publish several
 * certificates with the same subject (cross-signed variants), so prefer one whose
 * signature actually verifies and only fall back to a name match.
 */
async function pickIssuer(
	child: x509.X509Certificate,
	candidates: x509.X509Certificate[]
): Promise<x509.X509Certificate | null> {
	const named = candidates.filter((c) => c.subject === child.issuer);
	for (const cand of named) {
		if (await verifiesAgainst(child, cand)) return cand;
	}
	return named[0] ?? null;
}

/** Order the given certs into a chain (leaf first), fetching missing intermediates via AIA. */
export async function composeChain(certs: x509.X509Certificate[]): Promise<ChainResult> {
	const infos = await Promise.all(certs.map((c) => describeCert(c)));

	// leaf = a cert that does not issue any other provided cert; prefer non-CA
	const issuesOther = (c: CertInfo) =>
		infos.some((o) => o !== c && o.issuer === c.subject && !o.selfSigned);
	const leaf =
		infos.find((c) => !c.isCA && !issuesOther(c)) ?? infos.find((c) => !issuesOther(c)) ?? infos[0];

	const ordered: CertInfo[] = [leaf];
	const links: boolean[] = [];
	const fetchedFrom: string[] = [];
	let fetchFailedUrl: string | null = null;
	let missingIssuer: string | null = null;
	let rootIncluded = leaf.selfSigned;

	let current = leaf;
	while (!current.selfSigned && ordered.length < 10) {
		// find issuer among remaining provided certs
		let parent: CertInfo | undefined;
		for (const cand of infos) {
			if (ordered.includes(cand) || cand.subject !== current.issuer) continue;
			if (await verifiesAgainst(current.cert, cand.cert)) {
				parent = cand;
				break;
			}
		}
		// subject matched but signature did not verify — still show it, flag the link
		if (!parent) {
			const bySubject = infos.find(
				(cand) => !ordered.includes(cand) && cand.subject === current.issuer
			);
			if (bySubject) {
				ordered.push(bySubject);
				links.push(false);
				current = bySubject;
				continue;
			}
		}
		// try AIA download (direct, then via CORS relay — see ca-fetch.ts)
		if (!parent) {
			for (const url of current.caIssuerUrls) {
				const cert = await pickIssuer(current.cert, await fetchCaIssuers(url));
				if (cert) {
					parent = await describeCert(cert, true);
					fetchedFrom.push(url);
					break;
				}
				fetchFailedUrl = url;
			}
		}
		if (!parent) {
			missingIssuer = current.issuerCN;
			break;
		}
		fetchFailedUrl = null;
		ordered.push(parent);
		links.push(await verifiesAgainst(current.cert, parent.cert));
		current = parent;
		rootIncluded = current.selfSigned;
	}

	const extras = infos.filter((c) => !ordered.includes(c));
	return { ordered, links, rootIncluded, missingIssuer, fetchedFrom, fetchFailedUrl, extras };
}

/** Wildcard-aware hostname check against SANs (falls back to CN when no SAN). */
export function matchesHostname(info: CertInfo, hostname: string): boolean {
	const host = hostname.trim().toLowerCase().replace(/\.$/, '');
	if (!host) return false;
	const names = info.sans.filter((n) => !n.includes(':')).length
		? info.sans.filter((n) => !n.includes(':'))
		: [info.subjectCN];
	return names.some((name) => {
		const n = name.toLowerCase().replace(/\.$/, '');
		if (n === host) return true;
		if (n.startsWith('*.')) {
			const suffix = n.slice(1); // ".example.com"
			const rest = host.slice(0, -suffix.length);
			return host.endsWith(suffix) && rest.length > 0 && !rest.includes('.');
		}
		return false;
	});
}

export function daysUntil(date: Date): number {
	return Math.floor((date.getTime() - Date.now()) / 86_400_000);
}

export type ValidityStatus = 'valid' | 'expired' | 'not_yet_valid';

export function validityStatus(info: CertInfo, at = new Date()): ValidityStatus {
	if (at < info.notBefore) return 'not_yet_valid';
	if (at > info.notAfter) return 'expired';
	return 'valid';
}
