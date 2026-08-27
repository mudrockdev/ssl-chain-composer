import { beforeAll, describe, expect, test } from 'bun:test';
import { ContentInfo, SignedData } from '@peculiar/asn1-cms';
import { AsnConvert } from '@peculiar/asn1-schema';
import { strFromU8, unzipSync } from 'fflate';
import {
	buildBundle,
	bundleDomain,
	bundleFileName,
	caddyfileFor,
	toPkcs7,
	zipBundle,
	type BundleFile
} from '../src/lib/bundle';
import { composeChain, parseCertificates, type ChainResult } from '../src/lib/cert';
import { generateChain, type TestChain } from './testchain';

let chain: TestChain;
let result: ChainResult;
let bundle: BundleFile[];

beforeAll(async () => {
	chain = await generateChain('example.com', {
		sans: [
			{ type: 'dns', value: 'example.com' },
			{ type: 'dns', value: '*.wild.example.com' }
		]
	});
	// shuffled on purpose — the composer must reorder
	result = await composeChain([chain.intermediate, chain.root, chain.leaf]);
	bundle = buildBundle(result);
});

function fileStr(name: string): string {
	const found = bundle.find((f) => f.name === name);
	if (!found || typeof found.content !== 'string') throw new Error(`missing text file: ${name}`);
	return found.content;
}

describe('buildBundle', () => {
	test('mirrors the ssl-bundles folder structure', () => {
		const names = bundle.map((f) => f.name);
		for (const expected of [
			'README.txt',
			'apache/certificate.crt',
			'apache/ca_bundle.crt',
			'apache/README.txt',
			'nginx/fullchain.crt',
			'nginx/README.txt',
			'iis/certificate.p7b',
			'iis/README.txt',
			'exchange/example.com.crt',
			'exchange/Test Intermediate CA.crt',
			'exchange/Test Root CA.crt',
			'exchange/certificate.p7b',
			'exchange/README.txt',
			'pem/example.com.pem',
			'pem/chain.pem',
			'pem/fullchain.pem',
			'pem/root.pem',
			'pem/ca-bundle.pem',
			'pem/README.txt',
			'caddy/fullchain.pem',
			'caddy/Caddyfile',
			'caddy/README.txt'
		]) {
			expect(names).toContain(expected);
		}
	});

	test('pem files carry the right certificates in the right order', () => {
		expect(parseCertificates(fileStr('pem/example.com.pem')).map((c) => c.subject)).toEqual([
			chain.leaf.subject
		]);
		expect(parseCertificates(fileStr('pem/chain.pem')).map((c) => c.subject)).toEqual([
			chain.intermediate.subject
		]);
		expect(parseCertificates(fileStr('pem/fullchain.pem')).map((c) => c.subject)).toEqual([
			chain.leaf.subject,
			chain.intermediate.subject
		]);
		expect(parseCertificates(fileStr('pem/ca-bundle.pem')).map((c) => c.subject)).toEqual([
			chain.intermediate.subject,
			chain.root.subject
		]);
	});

	test('apache and nginx files match their README descriptions', () => {
		expect(parseCertificates(fileStr('apache/certificate.crt'))).toHaveLength(1);
		expect(parseCertificates(fileStr('apache/ca_bundle.crt')).map((c) => c.subject)).toEqual([
			chain.intermediate.subject
		]);
		expect(parseCertificates(fileStr('nginx/fullchain.crt'))).toHaveLength(2);
	});

	test('p7b is a DER PKCS#7 SignedData carrying the whole chain', () => {
		const p7b = bundle.find((f) => f.name === 'iis/certificate.p7b')!.content as Uint8Array;
		expect(p7b[0]).toBe(0x30); // DER SEQUENCE
		const info = AsnConvert.parse(p7b, ContentInfo);
		expect(info.contentType).toBe('1.2.840.113549.1.7.2');
		const signed = AsnConvert.parse(info.content, SignedData);
		expect(signed.certificates).toHaveLength(3);
	});

	test('Caddyfile serves the leaf domain with fullchain.pem', () => {
		const caddy = fileStr('caddy/Caddyfile');
		expect(caddy).toContain('example.com {');
		expect(caddy).toContain('tls fullchain.pem privkey.pem');
	});

	test('omits root-dependent files when the chain has no root', async () => {
		const withoutRoot = await composeChain([chain.leaf, chain.intermediate]);
		const names = buildBundle(withoutRoot).map((f) => f.name);
		expect(names).not.toContain('pem/root.pem');
		expect(names).toContain('pem/fullchain.pem');
	});
});

describe('bundleDomain / bundleFileName / toPkcs7', () => {
	test('uses the first DNS SAN as the domain', () => {
		expect(bundleDomain(result)).toBe('example.com');
	});

	test('sanitizes wildcards in the zip file name', () => {
		expect(bundleFileName('*.wild.example.com')).toBe('ssl-bundle-_.wild.example.com.zip');
	});

	test('caddyfileFor embeds the site address', () => {
		expect(caddyfileFor('test.local')).toContain('test.local {');
	});

	test('toPkcs7 round-trips a single certificate', async () => {
		const single = await composeChain([chain.root]);
		const info = AsnConvert.parse(toPkcs7(single.ordered), ContentInfo);
		const signed = AsnConvert.parse(info.content, SignedData);
		expect(signed.certificates).toHaveLength(1);
	});
});

describe('zipBundle', () => {
	test('produces a valid zip that round-trips every file', () => {
		const zipped = zipBundle(bundle);
		// zip local file header magic
		expect([...zipped.slice(0, 4)]).toEqual([0x50, 0x4b, 0x03, 0x04]);

		const unzipped = unzipSync(zipped);
		expect(Object.keys(unzipped).sort()).toEqual(bundle.map((f) => f.name).sort());
		for (const f of bundle) {
			if (typeof f.content === 'string') {
				expect(strFromU8(unzipped[f.name])).toBe(f.content);
			} else {
				expect([...unzipped[f.name]]).toEqual([...f.content]);
			}
		}
	});
});
