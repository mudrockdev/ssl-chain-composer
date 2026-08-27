import 'reflect-metadata';
import * as x509 from '@peculiar/x509';

const KEY_ALG = { name: 'ECDSA', namedCurve: 'P-256' };
const SIGN_ALG = { name: 'ECDSA', hash: 'SHA-256' };
const KEY_USAGES: KeyUsage[] = ['sign', 'verify'];

export interface TestChain {
	root: x509.X509Certificate;
	intermediate: x509.X509Certificate;
	leaf: x509.X509Certificate;
	leafKeys: CryptoKeyPair;
}

export async function generateKeys(): Promise<CryptoKeyPair> {
	return (await crypto.subtle.generateKey(KEY_ALG, true, KEY_USAGES)) as CryptoKeyPair;
}

function toDate(zdt: Temporal.ZonedDateTime): Date {
	return new Date(zdt.epochMilliseconds);
}

export interface ChainOptions {
	/** SAN entries for the leaf; defaults to a single DNS entry for the domain */
	sans?: x509.JsonGeneralName[];
	/** generate an already-expired leaf */
	expired?: boolean;
}

/** Generate a fresh root → intermediate → leaf chain for tests and fixtures. */
export async function generateChain(domain: string, opts: ChainOptions = {}): Promise<TestChain> {
	const now = Temporal.Now.zonedDateTimeISO();
	const [rootKeys, intKeys, leafKeys] = await Promise.all([
		generateKeys(),
		generateKeys(),
		generateKeys()
	]);

	const root = await x509.X509CertificateGenerator.createSelfSigned({
		serialNumber: '01',
		name: 'CN=Test Root CA, O=Test Org',
		notBefore: toDate(now.subtract({ years: 1 })),
		notAfter: toDate(now.add({ years: 10 })),
		signingAlgorithm: SIGN_ALG,
		keys: rootKeys,
		extensions: [new x509.BasicConstraintsExtension(true, undefined, true)]
	});

	const intermediate = await x509.X509CertificateGenerator.create({
		serialNumber: '02',
		subject: 'CN=Test Intermediate CA, O=Test Org',
		issuer: root.subject,
		notBefore: toDate(now.subtract({ years: 1 })),
		notAfter: toDate(now.add({ years: 5 })),
		signingAlgorithm: SIGN_ALG,
		publicKey: intKeys.publicKey,
		signingKey: rootKeys.privateKey,
		extensions: [new x509.BasicConstraintsExtension(true, 0, true)]
	});

	const leaf = await x509.X509CertificateGenerator.create({
		serialNumber: '03',
		subject: `CN=${domain}`,
		issuer: intermediate.subject,
		notBefore: toDate(now.subtract(opts.expired ? { years: 2 } : { days: 1 })),
		notAfter: toDate(opts.expired ? now.subtract({ years: 1 }) : now.add({ days: 90 })),
		signingAlgorithm: SIGN_ALG,
		publicKey: leafKeys.publicKey,
		signingKey: intKeys.privateKey,
		extensions: [
			new x509.BasicConstraintsExtension(false, undefined, true),
			new x509.ExtendedKeyUsageExtension(['1.3.6.1.5.5.7.3.1']),
			new x509.SubjectAlternativeNameExtension(opts.sans ?? [{ type: 'dns', value: domain }])
		]
	});

	return { root, intermediate, leaf, leafKeys };
}

/** Export a private key as PKCS#8 PEM. */
export async function privateKeyPem(key: CryptoKey): Promise<string> {
	const pkcs8 = await crypto.subtle.exportKey('pkcs8', key);
	return x509.PemConverter.encode(pkcs8, 'PRIVATE KEY') + '\n';
}
