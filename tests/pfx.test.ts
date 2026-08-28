import { beforeAll, describe, expect, test } from 'bun:test';
import 'reflect-metadata';
import * as x509 from '@peculiar/x509';
import { extractPfx, isPfxFile, PfxError, PfxPasswordError } from '../src/lib/pfx';
import { runOpenSSL } from './openssl-runner';

const PASSWORD = 's3cret';

let cert: x509.X509Certificate;
let modern: Uint8Array;
let noPassword: Uint8Array;
let legacy: Uint8Array;
let certsOnly: Uint8Array;

function pem(label: string, der: ArrayBuffer): string {
	const b64 = Buffer.from(der).toString('base64').replace(/(.{64})/g, '$1\n');
	return `-----BEGIN ${label}-----\n${b64}\n-----END ${label}-----\n`;
}

/** Build a .p12 with the WASM OpenSSL so the fixtures need no system openssl. */
async function exportPfx(args: string[], inputs: Record<string, string>): Promise<Uint8Array> {
	const encoder = new TextEncoder();
	const files = Object.fromEntries(
		Object.entries(inputs).map(([name, text]) => [name, encoder.encode(text)])
	);
	const result = await runOpenSSL(['pkcs12', '-export', '-out', 'out.p12', ...args], files, [
		'out.p12'
	]);
	const p12 = result.files['out.p12'];
	if (!p12) throw new Error(`could not build fixture: ${result.stderr}`);
	return p12;
}

beforeAll(async () => {
	const keys = (await crypto.subtle.generateKey(
		{
			name: 'RSASSA-PKCS1-v1_5',
			modulusLength: 2048,
			publicExponent: new Uint8Array([1, 0, 1]),
			hash: 'SHA-256'
		},
		true,
		['sign', 'verify']
	)) as CryptoKeyPair;

	cert = await x509.X509CertificateGenerator.createSelfSigned({
		serialNumber: '01',
		name: 'CN=pfx.test, O=Test Org',
		notBefore: new Date(Date.now() - 86_400_000),
		notAfter: new Date(Date.now() + 30 * 86_400_000),
		signingAlgorithm: { name: 'RSASSA-PKCS1-v1_5', hash: 'SHA-256' },
		keys
	});

	const inputs = {
		'key.pem': pem('PRIVATE KEY', await crypto.subtle.exportKey('pkcs8', keys.privateKey)),
		'cert.pem': cert.toString('pem')
	};
	const base = ['-inkey', 'key.pem', '-in', 'cert.pem'];

	[modern, noPassword, legacy, certsOnly] = await Promise.all([
		exportPfx([...base, '-passout', `pass:${PASSWORD}`], inputs),
		exportPfx([...base, '-passout', 'pass:'], inputs),
		exportPfx([...base, '-legacy', '-passout', `pass:${PASSWORD}`], inputs),
		exportPfx(['-nokeys', '-in', 'cert.pem', '-passout', `pass:${PASSWORD}`], inputs)
	]);
});

describe('extractPfx', () => {
	test('extracts the private key and certificate with the right password', async () => {
		const result = await extractPfx(modern, PASSWORD, runOpenSSL);

		expect(result.privateKeyPem).toStartWith('-----BEGIN PRIVATE KEY-----');
		expect(result.privateKeyPem).toEndWith('-----END PRIVATE KEY-----');
		expect(result.certificates).toHaveLength(1);
		expect(result.certificates[0].subject).toBe(cert.subject);
		expect(result.certificates[0].serialNumber).toBe(cert.serialNumber);
		expect(result.legacy).toBe(false);
	});

	test('rejects a wrong password without falling back to the legacy provider', async () => {
		expect(extractPfx(modern, 'wrong', runOpenSSL)).rejects.toBeInstanceOf(PfxPasswordError);
	});

	test('opens a PFX that has no password', async () => {
		const result = await extractPfx(noPassword, '', runOpenSSL);

		expect(result.privateKeyPem).toBeTruthy();
		expect(result.certificates).toHaveLength(1);
	});

	test('opens a legacy RC2-encrypted PFX and reports it as legacy', async () => {
		const result = await extractPfx(legacy, PASSWORD, runOpenSSL);

		expect(result.privateKeyPem).toBeTruthy();
		expect(result.certificates[0].subject).toBe(cert.subject);
		expect(result.legacy).toBe(true);
	});

	test('handles a certificate-only PFX', async () => {
		const result = await extractPfx(certsOnly, PASSWORD, runOpenSSL);

		expect(result.privateKeyPem).toBeNull();
		expect(result.certificates).toHaveLength(1);
	});

	test('accepts an ArrayBuffer as well as a Uint8Array', async () => {
		const buffer = modern.buffer.slice(
			modern.byteOffset,
			modern.byteOffset + modern.byteLength
		) as ArrayBuffer;
		const result = await extractPfx(buffer, PASSWORD, runOpenSSL);

		expect(result.certificates).toHaveLength(1);
	});

	test('reports a non-PKCS#12 file as unreadable rather than a password problem', async () => {
		const garbage = new TextEncoder().encode('this is not a pfx file');

		expect(extractPfx(garbage, '', runOpenSSL)).rejects.toBeInstanceOf(PfxError);
	});
});

describe('isPfxFile', () => {
	test.each([
		['cert.pfx', true],
		['cert.p12', true],
		['CERT.PFX', true],
		['cert.pem', false],
		['cert.p12.pem', false],
		['pfx', false]
	])('%s -> %p', (name, expected) => {
		expect(isPfxFile(name as string)).toBe(expected);
	});
});
