import type * as x509 from '@peculiar/x509';
import type { OpenSslRunner } from './openssl.js';
import { parseCertificates } from './parse.js';

const IN_FILE = 'input.p12';
const OUT_FILE = 'output.pem';

const PRIVATE_KEY_RE =
	/-----BEGIN ((?:RSA |EC |DSA )?PRIVATE KEY)-----[A-Za-z0-9+/=\s]+?-----END \1-----/;

/** OpenSSL reports a bad password (or a tampered file) as a MAC verification failure. */
const BAD_PASSWORD_RE = /mac verify (error|failure)/i;

export interface PfxContents {
	/** unencrypted PEM private key, or null when the file holds certificates only */
	privateKeyPem: string | null;
	certificates: x509.X509Certificate[];
	/** the file uses obsolete RC2/40-bit encryption and needed OpenSSL's legacy provider */
	legacy: boolean;
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

/** First line of OpenSSL's stderr, used as the human-facing reason a file failed to open. */
function reason(stderr: string): string {
	return stderr.trim().split('\n')[0] || 'the file could not be read as PKCS#12';
}

/**
 * Extract the private key and certificates from a PKCS#12 (.pfx/.p12) file.
 *
 * Files written by older Windows and Java tooling are encrypted with RC2-40, which
 * OpenSSL 3 only decrypts through its legacy provider, so the read is retried with
 * `-legacy` before giving up.
 *
 * `run` is injectable so this can be exercised without a browser; in the app it defaults
 * to the WASM build, imported lazily so the 2.6 MB binary is only downloaded when a PFX
 * is actually opened.
 */
export async function extractPfx(
	data: ArrayBuffer | Uint8Array,
	password: string,
	run?: OpenSslRunner
): Promise<PfxContents> {
	const exec = run ?? (await import('./openssl.js')).runOpenSSL;
	const bytes = data instanceof Uint8Array ? data : new Uint8Array(data);

	const read = (legacy: boolean) =>
		exec(
			[
				'pkcs12',
				'-in',
				IN_FILE,
				// -nodes: write the private key unencrypted so it is usable as-is
				'-nodes',
				'-passin',
				`pass:${password}`,
				'-out',
				OUT_FILE,
				...(legacy ? ['-legacy'] : [])
			],
			{ [IN_FILE]: bytes },
			[OUT_FILE]
		);

	let legacy = false;
	let result = await read(false);
	if (!result.files[OUT_FILE] && !BAD_PASSWORD_RE.test(result.stderr)) {
		legacy = true;
		result = await read(true);
	}

	const pem = result.files[OUT_FILE];
	if (!pem) {
		if (BAD_PASSWORD_RE.test(result.stderr)) throw new PfxPasswordError();
		throw new PfxError(reason(result.stderr));
	}

	// OpenSSL surrounds the PEM blocks with bag attributes; a key-only PFX has no certificates
	const text = new TextDecoder().decode(pem);
	const certificates = text.includes('-----BEGIN CERTIFICATE-----') ? parseCertificates(text) : [];
	if (!certificates.length && !PRIVATE_KEY_RE.test(text)) {
		throw new PfxError(reason(result.stderr));
	}

	return {
		privateKeyPem: text.match(PRIVATE_KEY_RE)?.[0].trim() ?? null,
		certificates,
		legacy
	};
}

/** True for file names that look like PKCS#12 containers. */
export function isPfxFile(name: string): boolean {
	return /\.(pfx|p12)$/i.test(name);
}
