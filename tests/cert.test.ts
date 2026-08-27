import { beforeAll, describe, expect, test } from 'bun:test';
import 'reflect-metadata';
import * as x509 from '@peculiar/x509';
import {
	composeChain,
	daysUntil,
	describeCert,
	matchesHostname,
	parseCertificateFile,
	parseCertificates,
	validityStatus
} from '../src/lib/cert';

const KEY_ALG = { name: 'ECDSA', namedCurve: 'P-256' };
const SIGN_ALG = { name: 'ECDSA', hash: 'SHA-256' };
const KEY_USAGES: KeyUsage[] = ['sign', 'verify'];

const YEAR = 365 * 86_400_000;
const now = new Date();

let rootKeys: CryptoKeyPair;
let intKeys: CryptoKeyPair;
let leafKeys: CryptoKeyPair;
let root: x509.X509Certificate;
let intermediate: x509.X509Certificate;
let leaf: x509.X509Certificate;

async function generateKeys(): Promise<CryptoKeyPair> {
	return (await crypto.subtle.generateKey(KEY_ALG, true, KEY_USAGES)) as CryptoKeyPair;
}

beforeAll(async () => {
	rootKeys = await generateKeys();
	intKeys = await generateKeys();
	leafKeys = await generateKeys();

	root = await x509.X509CertificateGenerator.createSelfSigned({
		serialNumber: '01',
		name: 'CN=Test Root CA, O=Test Org',
		notBefore: new Date(now.getTime() - YEAR),
		notAfter: new Date(now.getTime() + 10 * YEAR),
		signingAlgorithm: SIGN_ALG,
		keys: rootKeys,
		extensions: [new x509.BasicConstraintsExtension(true, undefined, true)]
	});

	intermediate = await x509.X509CertificateGenerator.create({
		serialNumber: '02',
		subject: 'CN=Test Intermediate CA, O=Test Org',
		issuer: root.subject,
		notBefore: new Date(now.getTime() - YEAR),
		notAfter: new Date(now.getTime() + 5 * YEAR),
		signingAlgorithm: SIGN_ALG,
		publicKey: intKeys.publicKey,
		signingKey: rootKeys.privateKey,
		extensions: [new x509.BasicConstraintsExtension(true, 0, true)]
	});

	leaf = await x509.X509CertificateGenerator.create({
		serialNumber: '03',
		subject: 'CN=example.com',
		issuer: intermediate.subject,
		notBefore: new Date(now.getTime() - 86_400_000),
		notAfter: new Date(now.getTime() + 90 * 86_400_000),
		signingAlgorithm: SIGN_ALG,
		publicKey: leafKeys.publicKey,
		signingKey: intKeys.privateKey,
		extensions: [
			new x509.BasicConstraintsExtension(false, undefined, true),
			new x509.SubjectAlternativeNameExtension([
				{ type: 'dns', value: 'example.com' },
				{ type: 'dns', value: '*.wild.example.com' }
			])
		]
	});
});

describe('parseCertificates', () => {
	test('parses a single PEM block', () => {
		const certs = parseCertificates(leaf.toString('pem'));
		expect(certs).toHaveLength(1);
		expect(certs[0].subject).toBe(leaf.subject);
	});

	test('parses multiple PEM blocks with surrounding noise', () => {
		const input = `garbage before\n${leaf.toString('pem')}\nsome text\n${intermediate.toString('pem')}\n`;
		const certs = parseCertificates(input);
		expect(certs).toHaveLength(2);
	});

	test('deduplicates identical certificates', () => {
		const input = `${leaf.toString('pem')}\n${leaf.toString('pem')}`;
		expect(parseCertificates(input)).toHaveLength(1);
	});

	test('parses bare base64 DER', () => {
		const certs = parseCertificates(root.toString('base64'));
		expect(certs).toHaveLength(1);
		expect(certs[0].subject).toBe(root.subject);
	});

	test('returns empty array for empty input', () => {
		expect(parseCertificates('')).toHaveLength(0);
	});

	test('throws on garbage input', () => {
		expect(() => parseCertificates('not a certificate')).toThrow();
	});
});

describe('parseCertificateFile', () => {
	test('parses a binary DER buffer', () => {
		const certs = parseCertificateFile(root.rawData);
		expect(certs).toHaveLength(1);
		expect(certs[0].subject).toBe(root.subject);
	});

	test('parses a PEM text buffer', () => {
		const buf = new TextEncoder().encode(leaf.toString('pem')).buffer as ArrayBuffer;
		const certs = parseCertificateFile(buf);
		expect(certs).toHaveLength(1);
		expect(certs[0].subject).toBe(leaf.subject);
	});
});

describe('describeCert', () => {
	test('extracts leaf certificate details', async () => {
		const info = await describeCert(leaf);
		expect(info.subjectCN).toBe('example.com');
		expect(info.issuerCN).toBe('Test Intermediate CA');
		expect(info.isCA).toBe(false);
		expect(info.selfSigned).toBe(false);
		expect(info.sans).toEqual(['example.com', '*.wild.example.com']);
		expect(info.keyAlg).toContain('P-256');
		expect(info.serial).toBe('03');
		expect(info.sha256).toMatch(/^([0-9A-F]{2}:){31}[0-9A-F]{2}$/);
	});

	test('detects a self-signed CA root', async () => {
		const info = await describeCert(root);
		expect(info.isCA).toBe(true);
		expect(info.selfSigned).toBe(true);
		expect(info.subjectCN).toBe('Test Root CA');
	});
});

describe('validityStatus / daysUntil', () => {
	test('reports a currently valid certificate', async () => {
		const info = await describeCert(leaf);
		expect(validityStatus(info)).toBe('valid');
		expect(daysUntil(info.notAfter)).toBeGreaterThan(80);
	});

	test('reports an expired certificate', async () => {
		const expired = await x509.X509CertificateGenerator.createSelfSigned({
			serialNumber: '0a',
			name: 'CN=Expired',
			notBefore: new Date(now.getTime() - 2 * YEAR),
			notAfter: new Date(now.getTime() - YEAR),
			signingAlgorithm: SIGN_ALG,
			keys: rootKeys
		});
		const info = await describeCert(expired);
		expect(validityStatus(info)).toBe('expired');
		expect(daysUntil(info.notAfter)).toBeLessThan(0);
	});

	test('reports a not-yet-valid certificate', async () => {
		const future = await x509.X509CertificateGenerator.createSelfSigned({
			serialNumber: '0b',
			name: 'CN=Future',
			notBefore: new Date(now.getTime() + YEAR),
			notAfter: new Date(now.getTime() + 2 * YEAR),
			signingAlgorithm: SIGN_ALG,
			keys: rootKeys
		});
		const info = await describeCert(future);
		expect(validityStatus(info)).toBe('not_yet_valid');
	});
});

describe('matchesHostname', () => {
	test('matches exact SAN entries', async () => {
		const info = await describeCert(leaf);
		expect(matchesHostname(info, 'example.com')).toBe(true);
		expect(matchesHostname(info, 'EXAMPLE.COM')).toBe(true);
		expect(matchesHostname(info, 'other.com')).toBe(false);
	});

	test('matches wildcards for a single label only', async () => {
		const info = await describeCert(leaf);
		expect(matchesHostname(info, 'app.wild.example.com')).toBe(true);
		expect(matchesHostname(info, 'wild.example.com')).toBe(false);
		expect(matchesHostname(info, 'a.b.wild.example.com')).toBe(false);
		expect(matchesHostname(info, 'www.example.com')).toBe(false);
	});

	test('falls back to CN when there is no SAN', async () => {
		const info = await describeCert(root);
		expect(matchesHostname(info, 'test root ca')).toBe(true);
		expect(matchesHostname(info, '')).toBe(false);
	});
});

describe('composeChain', () => {
	test('orders a shuffled full chain leaf-first and verifies links', async () => {
		const result = await composeChain([intermediate, root, leaf]);
		expect(result.ordered.map((c) => c.subjectCN)).toEqual([
			'example.com',
			'Test Intermediate CA',
			'Test Root CA'
		]);
		expect(result.links).toEqual([true, true]);
		expect(result.rootIncluded).toBe(true);
		expect(result.missingIssuer).toBeNull();
		expect(result.extras).toHaveLength(0);
	});

	test('reports a missing intermediate', async () => {
		const result = await composeChain([leaf, root]);
		expect(result.ordered.map((c) => c.subjectCN)).toEqual(['example.com']);
		expect(result.missingIssuer).toBe('Test Intermediate CA');
		expect(result.rootIncluded).toBe(false);
		expect(result.extras.map((c) => c.subjectCN)).toEqual(['Test Root CA']);
	});

	test('flags an issuer whose signature does not verify', async () => {
		// same subject as the real intermediate, but a different key pair
		const fakeKeys = await generateKeys();
		const fakeIntermediate = await x509.X509CertificateGenerator.createSelfSigned({
			serialNumber: '0c',
			name: intermediate.subject,
			notBefore: new Date(now.getTime() - YEAR),
			notAfter: new Date(now.getTime() + YEAR),
			signingAlgorithm: SIGN_ALG,
			keys: fakeKeys,
			extensions: [new x509.BasicConstraintsExtension(true, 0, true)]
		});
		const result = await composeChain([leaf, fakeIntermediate]);
		expect(result.ordered).toHaveLength(2);
		expect(result.links[0]).toBe(false);
	});

	test('handles a single self-signed certificate', async () => {
		const result = await composeChain([root]);
		expect(result.ordered).toHaveLength(1);
		expect(result.rootIncluded).toBe(true);
		expect(result.missingIssuer).toBeNull();
		expect(result.links).toHaveLength(0);
	});
});
