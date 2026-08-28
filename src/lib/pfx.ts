import type forge from 'node-forge';
import * as x509 from '@peculiar/x509';

/**
 * PKCS#12 (.pfx/.p12) reading, entirely in the browser.
 *
 * This deliberately does NOT use openssl-wasm: both published builds (1.1.1 and 3.1.0)
 * decode PKCS#12 private keys incorrectly — the emitted key has a zero modulus, so
 * `openssl rsa -noout -modulus` hashes to the same value for every input file. The
 * certificates it emits are fine, but the keys are unusable. node-forge round-trips both
 * byte-for-byte against the reference `openssl pkcs12` commands (see tests/pfx.test.ts).
 */

/** Bag attributes are exposed as arrays of binary strings. */
type Bag = forge.pkcs12.Bag & { attributes?: Record<string, string[] | undefined> };

export interface PfxContents {
	/** unencrypted PKCS#8 PEM, equivalent to `openssl pkcs12 -nocerts -nodes` */
	privateKeyPem: string | null;
	/** the certificate belonging to the key, equivalent to `openssl pkcs12 -clcerts -nokeys` */
	clientCertificate: x509.X509Certificate | null;
	/** the remaining CA certificates, equivalent to `openssl pkcs12 -cacerts -nokeys` */
	caCertificates: x509.X509Certificate[];
	/** every certificate in the file, client certificate first */
	certificates: x509.X509Certificate[];
}

/** The PFX could not be opened with the supplied password. */
export class PfxPasswordError extends Error {
	constructor() {
		super('incorrect password');
		this.name = 'PfxPasswordError';
	}
}

/** The PFX is not readable for some reason other than the password. */
export class PfxError extends Error {
	constructor(message: string) {
		super(message);
		this.name = 'PfxError';
	}
}

/** forge reports both a wrong password and a corrupted file as a MAC failure. */
const BAD_PASSWORD_RE = /mac could not be verified|invalid password/i;

function derToBytes(der: forge.util.ByteStringBuffer): Uint8Array {
	const raw = der.getBytes();
	const bytes = new Uint8Array(raw.length);
	for (let i = 0; i < raw.length; i++) bytes[i] = raw.charCodeAt(i) & 0xff;
	return bytes;
}

function toPem(label: string, bytes: Uint8Array): string {
	let base64 = '';
	for (let i = 0; i < bytes.length; i += 0x8000) {
		base64 += String.fromCharCode(...bytes.subarray(i, i + 0x8000));
	}
	const body = btoa(base64).replace(/(.{64})/g, '$1\n').trimEnd();
	return `-----BEGIN ${label}-----\n${body}\n-----END ${label}-----`;
}

function localKeyId(bag: Bag): string | null {
	return bag.attributes?.localKeyId?.[0] ?? null;
}

export async function extractPfx(
	data: ArrayBuffer | Uint8Array,
	password: string
): Promise<PfxContents> {
	// keeps node-forge out of the initial bundle — it only loads when a PFX is opened
	const { default: forge } = await import('node-forge');
	const { asn1, pkcs12, pki, util } = forge;

	const bytes = data instanceof Uint8Array ? data : new Uint8Array(data);
	// forge wants a standalone ArrayBuffer, and the input may be a view into a larger one
	const buffer = bytes.buffer.slice(
		bytes.byteOffset,
		bytes.byteOffset + bytes.byteLength
	) as ArrayBuffer;

	let container: forge.pkcs12.Pkcs12Pfx;
	try {
		container = pkcs12.pkcs12FromAsn1(
			asn1.fromDer(util.createBuffer(buffer)),
			password
		) as forge.pkcs12.Pkcs12Pfx;
	} catch (err) {
		const message = err instanceof Error ? err.message : String(err);
		if (BAD_PASSWORD_RE.test(message)) throw new PfxPasswordError();
		throw new PfxError(message);
	}

	const bagsOfType = (type: string): Bag[] =>
		(container.getBags({ bagType: type })[type] ?? []) as Bag[];

	// forge parses RSA keys and RSA-signed certificates; when it cannot (EC, for example)
	// it leaves the decrypted DER behind in bag.asn1, which is what we actually want
	const keyBag = [
		...bagsOfType(pki.oids.pkcs8ShroudedKeyBag),
		...bagsOfType(pki.oids.keyBag)
	].find((bag) => bag.asn1 || bag.key);

	let privateKeyPem: string | null = null;
	if (keyBag) {
		const keyInfo = keyBag.asn1 ?? pki.wrapRsaPrivateKey(pki.privateKeyToAsn1(keyBag.key!));
		privateKeyPem = toPem('PRIVATE KEY', derToBytes(asn1.toDer(keyInfo)));
	}

	const certificates: x509.X509Certificate[] = [];
	const clientIds = new Set<string>();
	const keyId = keyBag ? localKeyId(keyBag) : null;

	for (const bag of bagsOfType(pki.oids.certBag)) {
		// cert.tbsCertificate is the cached original, so re-encoding preserves the signed bytes
		const der = bag.asn1
			? derToBytes(asn1.toDer(bag.asn1))
			: bag.cert
				? derToBytes(asn1.toDer(pki.certificateToAsn1(bag.cert)))
				: null;
		if (!der) continue;

		const cert = new x509.X509Certificate(
			der.buffer.slice(der.byteOffset, der.byteOffset + der.byteLength) as ArrayBuffer
		);
		certificates.push(cert);

		// PKCS#12 marks the key's own certificate by giving it the key's localKeyId
		const id = localKeyId(bag);
		if (id !== null && id === keyId) clientIds.add(cert.serialNumber + cert.subject);
	}

	if (!certificates.length && !privateKeyPem) {
		throw new PfxError('the file contains no certificates or private key');
	}

	// fall back to the first end-entity certificate when the file carries no localKeyId
	const isClient = (cert: x509.X509Certificate) =>
		clientIds.size
			? clientIds.has(cert.serialNumber + cert.subject)
			: !cert.getExtension(x509.BasicConstraintsExtension)?.ca;

	const clientCertificate = certificates.find(isClient) ?? null;
	const caCertificates = certificates.filter((cert) => cert !== clientCertificate);

	return {
		privateKeyPem,
		clientCertificate,
		caCertificates,
		certificates: clientCertificate ? [clientCertificate, ...caCertificates] : caCertificates
	};
}

/** True for file names that look like PKCS#12 containers. */
export function isPfxFile(name: string): boolean {
	return /\.(pfx|p12)$/i.test(name);
}
