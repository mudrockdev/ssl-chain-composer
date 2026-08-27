import { CertificateChoices, CertificateSet, ContentInfo, SignedData } from '@peculiar/asn1-cms';
import { AsnConvert } from '@peculiar/asn1-schema';
import { Certificate } from '@peculiar/asn1-x509';
import { strToU8, zipSync } from 'fflate';
import type { CertInfo, ChainResult } from './cert.js';

export interface BundleFile {
	name: string;
	content: string | Uint8Array;
}

const ID_DATA = '1.2.840.113549.1.7.1';
const ID_SIGNED_DATA = '1.2.840.113549.1.7.2';

/** Primary domain of the composed chain: first DNS SAN, falling back to the leaf CN. */
export function bundleDomain(result: ChainResult): string {
	const leaf = result.ordered[0];
	return leaf.sans.find((s) => !s.includes(':')) ?? leaf.subjectCN;
}

/** Safe zip file name for a domain (wildcards become underscores). */
export function bundleFileName(domain: string): string {
	return `ssl-bundle-${safeName(domain)}.zip`;
}

function safeName(name: string): string {
	return name.replace(/[^a-zA-Z0-9 ._-]/g, '_');
}

function joinPem(certs: CertInfo[]): string {
	return certs.map((c) => c.pem).join('\n') + '\n';
}

/** DER-encoded PKCS#7 (CMS SignedData) bundle carrying the certificate chain. */
export function toPkcs7(certs: CertInfo[]): Uint8Array {
	const signedData = new SignedData({
		version: 1,
		certificates: new CertificateSet(
			certs.map(
				(c) =>
					new CertificateChoices({ certificate: AsnConvert.parse(c.cert.rawData, Certificate) })
			)
		)
	});
	signedData.encapContentInfo.eContentType = ID_DATA;
	const contentInfo = new ContentInfo({
		contentType: ID_SIGNED_DATA,
		content: AsnConvert.serialize(signedData)
	});
	return new Uint8Array(AsnConvert.serialize(contentInfo));
}

export function caddyfileFor(domain: string): string {
	return `# Caddyfile for ${domain}
# Place your private key next to this file as privkey.pem, then run:
#   caddy run --config Caddyfile
#
# fullchain.pem (leaf + intermediates) ships in this folder.

${domain} {
	tls fullchain.pem privkey.pem

	respond "Hello from ${domain}" 200
	# ...or proxy your app instead:
	# reverse_proxy localhost:8080
}
`;
}

const VERIFY = (domain: string) =>
	`Verify installation:\n  openssl s_client -connect ${domain}:443 -servername ${domain}`;

/** Build the downloadable per-server bundle for a composed chain. */
export function buildBundle(result: ChainResult): BundleFile[] {
	const leaf = result.ordered[0];
	const intermediates = result.ordered.slice(1).filter((c) => !c.selfSigned);
	const root = result.ordered.find((c) => c.selfSigned && c !== leaf);
	const caCerts = [...intermediates, ...(root ? [root] : [])];
	const domain = bundleDomain(result);
	const leafFile = safeName(leaf.subjectCN);
	const p7b = toPkcs7(result.ordered);

	const files: BundleFile[] = [];

	// pem/ — individual PEM files
	files.push(
		{ name: `pem/${leafFile}.pem`, content: joinPem([leaf]) },
		{ name: 'pem/chain.pem', content: joinPem(intermediates) },
		{ name: 'pem/fullchain.pem', content: joinPem([leaf, ...intermediates]) }
	);
	if (root) files.push({ name: 'pem/root.pem', content: joinPem([root]) });
	if (caCerts.length) files.push({ name: 'pem/ca-bundle.pem', content: joinPem(caCerts) });
	files.push({
		name: 'pem/README.txt',
		content: `PEM Certificate Files
=====================

This directory contains individual PEM certificate files:

  ${leafFile}.pem - Your server certificate
  chain.pem       - Intermediate CA certificate chain
  fullchain.pem   - Certificate + intermediate chain (for most servers)
${root ? '  root.pem        - Root CA certificate\n' : ''}${caCerts.length ? '  ca-bundle.pem   - Intermediate chain + root CA (for Java/OCSP)\n' : ''}
Use these files with any web server or application that requires
separate certificate files in PEM format.

Verify your certificate:
  openssl x509 -in "${leafFile}.pem" -text -noout
${root ? `\nVerify the chain:\n  openssl verify -CAfile root.pem -untrusted chain.pem "${leafFile}.pem"\n` : ''}`
	});

	// apache/
	files.push(
		{ name: 'apache/certificate.crt', content: joinPem([leaf]) },
		{ name: 'apache/ca_bundle.crt', content: joinPem(intermediates) },
		{
			name: 'apache/README.txt',
			content: `Apache SSL Configuration
========================

Place both files on your server and configure Apache:

  <VirtualHost *:443>
      SSLEngine on
      SSLCertificateFile    /etc/apache2/ssl/certificate.crt
      SSLCertificateKeyFile /etc/apache2/ssl/private.key
      SSLCACertificateFile  /etc/apache2/ssl/ca_bundle.crt
  </VirtualHost>

${VERIFY(domain)}

certificate.crt - Your server certificate
ca_bundle.crt   - Intermediate CA certificate chain
`
		}
	);

	// nginx/
	files.push(
		{ name: 'nginx/fullchain.crt', content: joinPem([leaf, ...intermediates]) },
		{
			name: 'nginx/README.txt',
			content: `nginx SSL Configuration
=======================

Place fullchain.crt on your server and configure nginx:

  server {
      listen 443 ssl;
      ssl_certificate     /etc/nginx/ssl/fullchain.crt;
      ssl_certificate_key /etc/nginx/ssl/private.key;
  }

${VERIFY(domain)}

fullchain.crt contains your certificate followed by intermediate CA certificates.
`
		}
	);

	// iis/
	files.push(
		{ name: 'iis/certificate.p7b', content: p7b },
		{
			name: 'iis/README.txt',
			content: `IIS SSL Configuration
=====================

Import certificate.p7b into IIS:

1. Open IIS Manager
2. Select your server in the Connections pane
3. Double-click "Server Certificates"
4. Click "Complete Certificate Request..." in the Actions pane
5. Browse to certificate.p7b
6. Enter a friendly name and click OK
7. Bind the certificate to your HTTPS site

${VERIFY(domain)}

certificate.p7b - PKCS#7 bundle containing full certificate chain
`
		}
	);

	// exchange/ — individual .crt per certificate + p7b
	for (const cert of result.ordered) {
		files.push({ name: `exchange/${safeName(cert.subjectCN)}.crt`, content: joinPem([cert]) });
	}
	files.push(
		{ name: 'exchange/certificate.p7b', content: p7b },
		{
			name: 'exchange/README.txt',
			content: `Microsoft Exchange SSL Certificate Installation
=================================================

This folder contains individual certificate files for Microsoft Exchange.

Import order (important):
1. Root CA certificate (.crt) import into Trusted Root Certification Authorities
2. Intermediate CA certificate(s) (.crt) import into Intermediate Certification Authorities
3. Leaf/server certificate (.crt) assign to Exchange services

Alternative: Use the .p7b file (PKCS#7) for one-step import via MMC.
`
		}
	);

	// caddy/
	files.push(
		{ name: 'caddy/fullchain.pem', content: joinPem([leaf, ...intermediates]) },
		{ name: 'caddy/Caddyfile', content: caddyfileFor(domain) },
		{
			name: 'caddy/README.txt',
			content: `Caddy SSL Configuration
=======================

1. Copy your private key into this folder as privkey.pem
2. Run:  caddy run --config Caddyfile

${VERIFY(domain)}

fullchain.pem - Your certificate followed by intermediate CA certificates
Caddyfile     - Ready-to-use Caddy configuration
`
		}
	);

	// top-level overview
	files.push({
		name: 'README.txt',
		content: `SSL bundle for ${domain}
==============================

apache/    certificate + CA bundle with Apache configuration
nginx/     fullchain certificate with nginx configuration
caddy/     fullchain certificate with ready-to-run Caddyfile
iis/       PKCS#7 (.p7b) bundle with IIS import steps
exchange/  individual certificates + .p7b for Microsoft Exchange
pem/       individual PEM files for any other server

The private key is NOT included this tool never sees it. Keep it safe
and place it where each server's README points.

Note: servers should send the leaf + intermediates (fullchain); clients
already have the root certificate in their trust store.
`
	});

	return files;
}

/** Zip the bundle files in the browser (or bun) — returns the raw zip bytes. */
export function zipBundle(files: BundleFile[]): Uint8Array {
	return zipSync(
		Object.fromEntries(
			files.map((f) => [f.name, typeof f.content === 'string' ? strToU8(f.content) : f.content])
		),
		{ level: 6 }
	);
}
