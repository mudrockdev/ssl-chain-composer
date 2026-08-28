// tsyringe (used by @peculiar/x509) requires a reflect polyfill loaded first
import 'reflect-metadata';
import { ContentInfo, SignedData } from '@peculiar/asn1-cms';
import { AsnConvert } from '@peculiar/asn1-schema';
import * as x509 from '@peculiar/x509';

const PEM_RE =
	/-----BEGIN (?:TRUSTED )?CERTIFICATE-----[A-Za-z0-9+/=\s]+?-----END (?:TRUSTED )?CERTIFICATE-----/g;

const BASE64_RE = /^[A-Za-z0-9+/=\s]+$/;

const ID_SIGNED_DATA = '1.2.840.113549.1.7.2';

export function dedupe(certs: x509.X509Certificate[]): x509.X509Certificate[] {
	const seen = new Set<string>();
	return certs.filter((c) => {
		const key = c.toString('base64');
		if (seen.has(key)) return false;
		seen.add(key);
		return true;
	});
}

/** Parse PEM text (one or more blocks) or a bare base64 DER blob. */
export function parseCertificates(input: string): x509.X509Certificate[] {
	const certs: x509.X509Certificate[] = [];
	const blocks = input.match(PEM_RE);
	if (blocks) {
		for (const block of blocks) certs.push(new x509.X509Certificate(block));
	} else {
		const cleaned = input.replace(/\s+/g, '');
		if (cleaned) certs.push(new x509.X509Certificate(cleaned));
	}
	return dedupe(certs);
}

/**
 * Extract the certificates from a DER-encoded PKCS#7 / CMS SignedData blob.
 * Several CAs publish their issuer certificate as a `.p7c` at the AIA URL
 * instead of a bare DER certificate. Returns [] when the input is not PKCS#7.
 */
export function parsePkcs7(buf: ArrayBuffer): x509.X509Certificate[] {
	try {
		const info = AsnConvert.parse(buf, ContentInfo);
		if (info.contentType !== ID_SIGNED_DATA) return [];
		const signedData = AsnConvert.parse(info.content, SignedData);
		const certs: x509.X509Certificate[] = [];
		for (const choice of signedData.certificates ?? []) {
			if (choice.certificate) {
				certs.push(new x509.X509Certificate(AsnConvert.serialize(choice.certificate)));
			}
		}
		return dedupe(certs);
	} catch {
		return [];
	}
}

/** Parse an uploaded or downloaded certificate: PEM text, base64, binary DER or PKCS#7. */
export function parseCertificateFile(buf: ArrayBuffer): x509.X509Certificate[] {
	const text = new TextDecoder('utf-8', { fatal: false }).decode(buf);
	if (text.includes('-----BEGIN')) return parseCertificates(text);

	const p7 = parsePkcs7(buf);
	if (p7.length) return p7;

	// some servers hand out base64 DER with no PEM armor
	const trimmed = text.trim();
	if (trimmed.length > 64 && BASE64_RE.test(trimmed)) {
		try {
			return parseCertificates(trimmed);
		} catch {
			// not base64 DER after all; fall through to the binary path
		}
	}

	return [new x509.X509Certificate(buf)];
}
