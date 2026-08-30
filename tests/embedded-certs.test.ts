import { expect, test } from 'bun:test';
import { composeChain, parseCertificates } from '../src/lib/cert';
import { EMBEDDED_CERTS } from '../src/lib/embedded-certs';

const SECTIGO_DV = 'http://crt.sectigo.com/SectigoRSADomainValidationSecureServerCA.crt';

test('generated cache contains the well-known Sectigo intermediate', () => {
	const pem = EMBEDDED_CERTS[SECTIGO_DV];
	expect(pem).toBeDefined();
	const [cert] = parseCertificates(pem);
	expect(cert.subject).toContain('Sectigo RSA Domain Validation Secure Server CA');
});

test('embedded cache completes a chain without any network fetch', async () => {
	// the Sectigo intermediate's issuer (USERTrust RSA) must come from the cache
	const certs = parseCertificates(EMBEDDED_CERTS[SECTIGO_DV]);
	const result = await composeChain(certs);

	expect(result.ordered.length).toBeGreaterThan(1);
	expect(result.embeddedFrom.length).toBeGreaterThan(0);
	expect(result.fetchedFrom).toEqual([]);
	expect(result.fetchFailedUrl).toBeNull();
	expect(result.links.every(Boolean)).toBe(true);
});
