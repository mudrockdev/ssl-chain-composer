import { describe, expect, test } from 'bun:test';
import 'reflect-metadata';
import forge from 'node-forge';
import { extractPfx, isPfxFile, PfxError, PfxPasswordError } from '../src/lib/pfx';

const PASSWORD = 's3cret';

/**
 * Fixtures were produced by the real `openssl pkcs12 -export` CLI:
 *   modern — AES-256/PBES2, password protected, leaf + CA
 *   nopass — no password
 *   legacy — `-legacy`, i.e. 40-bit RC2 as written by older Windows/Java tooling
 *   ec     — an EC (prime256v1) key and certificate
 *
 * The expected hashes below are the output of the reference commands, so these tests fail
 * if extraction ever stops matching the CLI:
 *   openssl pkcs12 -in modern.p12 -nocerts -nodes  -out k.key && openssl rsa  -noout -modulus -in k.key | openssl md5
 *   openssl pkcs12 -in modern.p12 -clcerts -nokeys -out c.crt && openssl x509 -noout -modulus -in c.crt | openssl md5
 */
const RSA_MODULUS_MD5 = 'e324106bab4eec40853fb131b495060a';

/** `openssl x509 -noout -fingerprint -sha256`, to prove the DER survives extraction intact. */
const LEAF_SHA256 =
	'8C:45:BB:78:D2:41:F3:B3:4D:3B:6D:EF:64:33:F9:85:08:F2:04:8C:7E:63:94:AC:C0:9B:0C:3E:E1:86:2F:6C';
const CA_SHA256 =
	'1E:54:2A:02:98:82:CA:A0:C8:A6:5E:07:FA:B7:49:79:49:9E:E0:01:6C:6D:09:6B:EB:AF:0F:A7:FC:A6:B9:E8';

function fixture(name: string): Uint8Array {
	return new Uint8Array(require('node:fs').readFileSync(`${__dirname}/fixtures/${name}`));
}

/** Reproduces `openssl <x509|rsa> -noout -modulus -in file | openssl md5` exactly. */
function modulusMd5(modulus: forge.jsbn.BigInteger): string {
	const line = `Modulus=${modulus.toString(16).toUpperCase()}\n`;
	return forge.md.md5.create().update(line).digest().toHex();
}

function keyModulusMd5(pem: string): string {
	return modulusMd5(forge.pki.privateKeyFromPem(pem).n);
}

function certModulusMd5(pem: string): string {
	const key = forge.pki.certificateFromPem(pem).publicKey as forge.pki.rsa.PublicKey;
	return modulusMd5(key.n);
}

describe('extractPfx', () => {
	test('extracted key and certificate match the openssl CLI modulus hashes', async () => {
		const { privateKeyPem, clientCertificate } = await extractPfx(fixture('modern.p12'), PASSWORD);

		expect(keyModulusMd5(privateKeyPem!)).toBe(RSA_MODULUS_MD5);
		expect(certModulusMd5(clientCertificate!.toString('pem'))).toBe(RSA_MODULUS_MD5);
	});

	test('the key and its certificate belong together', async () => {
		const { privateKeyPem, clientCertificate } = await extractPfx(fixture('modern.p12'), PASSWORD);

		expect(keyModulusMd5(privateKeyPem!)).toBe(certModulusMd5(clientCertificate!.toString('pem')));
	});

	test('emits a complete PKCS#8 key, not a truncated one', async () => {
		const { privateKeyPem } = await extractPfx(fixture('modern.p12'), PASSWORD);

		expect(privateKeyPem).toStartWith('-----BEGIN PRIVATE KEY-----');
		expect(privateKeyPem).toEndWith('-----END PRIVATE KEY-----');
		// a zero-modulus key (the openssl-wasm bug) is ~1.2 kB; a real RSA-2048 key is ~1.7 kB
		expect(privateKeyPem!.length).toBeGreaterThan(1600);
		expect(forge.pki.privateKeyFromPem(privateKeyPem!).n.bitLength()).toBe(2048);
	});

	test('splits client and CA certificates like -clcerts / -cacerts', async () => {
		const result = await extractPfx(fixture('modern.p12'), PASSWORD);

		expect(result.clientCertificate?.subject).toBe('CN=pfx.test, O=Test');
		expect(result.caCertificates.map((c) => c.subject)).toEqual(['CN=Test PFX CA, O=Test']);
		// the composed list always leads with the client certificate
		expect(result.certificates[0].subject).toBe('CN=pfx.test, O=Test');
		expect(result.certificates).toHaveLength(2);
	});

	test('preserves certificate bytes exactly', async () => {
		const { clientCertificate, caCertificates } = await extractPfx(fixture('modern.p12'), PASSWORD);
		const hex = (buf: ArrayBuffer) =>
			[...new Uint8Array(buf)]
				.map((b) => b.toString(16).padStart(2, '0'))
				.join(':')
				.toUpperCase();

		expect(hex(await clientCertificate!.getThumbprint('SHA-256'))).toBe(LEAF_SHA256);
		expect(hex(await caCertificates[0].getThumbprint('SHA-256'))).toBe(CA_SHA256);
	});

	test('the extracted chain still verifies', async () => {
		const { clientCertificate, caCertificates } = await extractPfx(fixture('modern.p12'), PASSWORD);

		expect(
			await clientCertificate!.verify({ publicKey: caCertificates[0], signatureOnly: true })
		).toBe(true);
	});

	test('rejects a wrong password', async () => {
		expect(extractPfx(fixture('modern.p12'), 'wrong')).rejects.toBeInstanceOf(PfxPasswordError);
	});

	test('opens a PFX that has no password', async () => {
		const { privateKeyPem, clientCertificate } = await extractPfx(fixture('nopass.p12'), '');

		expect(keyModulusMd5(privateKeyPem!)).toBe(RSA_MODULUS_MD5);
		expect(clientCertificate?.subject).toBe('CN=pfx.test, O=Test');
	});

	test('opens a legacy 40-bit RC2 PFX', async () => {
		const { privateKeyPem, clientCertificate } = await extractPfx(fixture('legacy.p12'), PASSWORD);

		expect(keyModulusMd5(privateKeyPem!)).toBe(RSA_MODULUS_MD5);
		expect(clientCertificate?.subject).toBe('CN=pfx.test, O=Test');
	});

	test('opens an EC PFX', async () => {
		const { privateKeyPem, clientCertificate } = await extractPfx(fixture('ec.p12'), PASSWORD);

		expect(privateKeyPem).toStartWith('-----BEGIN PRIVATE KEY-----');
		expect(clientCertificate?.subject).toBe('CN=ec.test');
		expect(clientCertificate?.publicKey.algorithm.name).toBe('ECDSA');
	});

	test('accepts an ArrayBuffer as well as a Uint8Array', async () => {
		const bytes = fixture('modern.p12');
		const buffer = bytes.buffer.slice(
			bytes.byteOffset,
			bytes.byteOffset + bytes.byteLength
		) as ArrayBuffer;

		expect((await extractPfx(buffer, PASSWORD)).certificates).toHaveLength(2);
	});

	test('reports a non-PKCS#12 file as unreadable rather than a password problem', async () => {
		const garbage = new TextEncoder().encode('this is not a pfx file');

		expect(extractPfx(garbage, '')).rejects.toBeInstanceOf(PfxError);
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
