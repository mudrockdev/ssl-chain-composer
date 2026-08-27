/**
 * Generates test SSL bundles into tests/ssl-bundles/ for manual testing of the
 * web UI (and of Caddy, using the caddy/ folder which includes the private key).
 *
 * Run with:  bun run gen:bundles
 */
import { buildBundle, bundleFileName, zipBundle } from '../src/lib/bundle';
import { composeChain } from '../src/lib/cert';
import { generateChain, privateKeyPem } from './testchain';

const OUT = new URL('./ssl-bundles/', import.meta.url).pathname;

// --- localhost bundle: the exact structure the web UI's zip download produces
const localhost = await generateChain('localhost', {
	sans: [
		{ type: 'dns', value: 'localhost' },
		{ type: 'ip', value: '127.0.0.1' }
	]
});
const chain = await composeChain([localhost.intermediate, localhost.root, localhost.leaf]);
const bundle = buildBundle(chain);

for (const f of bundle) {
	await Bun.write(OUT + f.name, f.content);
}
// private key so the caddy/ folder is actually runnable (test cert only!)
await Bun.write(`${OUT}caddy/privkey.pem`, await privateKeyPem(localhost.leafKeys.privateKey));
// the same bundle as a zip — exactly what the web UI's "Download bundle" produces
await Bun.write(OUT + bundleFileName('localhost'), zipBundle(bundle));

// --- paste-into-the-UI fixtures ----------------------------------------------
const example = await generateChain('example.com', {
	sans: [
		{ type: 'dns', value: 'example.com' },
		{ type: 'dns', value: '*.wild.example.com' }
	]
});
const pem = (c: { toString(format: 'pem'): string }) => c.toString('pem');

// shuffled full chain — the composer must reorder it
await Bun.write(
	`${OUT}fixtures/shuffled-chain.pem`,
	[pem(example.intermediate), pem(example.root), pem(example.leaf)].join('\n') + '\n'
);
// missing intermediate — the composer must report it
await Bun.write(
	`${OUT}fixtures/missing-intermediate.pem`,
	[pem(example.leaf), pem(example.root)].join('\n') + '\n'
);
// leaf only — for the checker (hostname: example.com / app.wild.example.com)
await Bun.write(`${OUT}fixtures/leaf-only.pem`, pem(example.leaf) + '\n');

// expired leaf — the checker must show "expired"
const expired = await generateChain('expired.example.com', { expired: true });
await Bun.write(`${OUT}fixtures/expired-leaf.pem`, pem(expired.leaf) + '\n');

await Bun.write(
	`${OUT}fixtures/README.txt`,
	`Paste-into-the-UI fixtures — regenerate everything with: bun run gen:bundles

shuffled-chain.pem        Chain Composer: gets reordered, chain complete
missing-intermediate.pem  Chain Composer: reports the missing intermediate
leaf-only.pem             Checker; try hostname example.com / app.wild.example.com
expired-leaf.pem          Checker: shows expired

To test a real HTTPS server with the localhost bundle:
  cd tests/ssl-bundles/caddy
  caddy run --config Caddyfile
  curl --cacert ../pem/root.pem https://localhost
`
);

console.log(`wrote ${bundle.length + 7} files to ${OUT}`);
