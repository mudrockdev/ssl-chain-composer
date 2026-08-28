import { createRequire } from 'node:module';
import { readFileSync } from 'node:fs';
import type { OpenSslRunner } from '../src/lib/openssl.ts';

/**
 * Node/bun equivalent of src/lib/openssl.ts, for tests. The browser build loads the
 * Emscripten glue with a script tag and fetches the binary; here both come off disk.
 * The WASM module itself — the part under test — is identical.
 */
const require = createRequire(import.meta.url);
const gluePath = require.resolve('openssl-wasm/bin/openssl-3.1.0/openssl.js');
const wasmPath = gluePath.replace(/openssl\.js$/, 'openssl.wasm');

/* eslint-disable @typescript-eslint/no-explicit-any */
const factory = require(gluePath) as (options: Record<string, unknown>) => Promise<any>;
const wasmBinary = readFileSync(wasmPath);

export const runOpenSSL: OpenSslRunner = async (args, inputs = {}, outputs = []) => {
	let stdout = '';
	let stderr = '';
	const mod = await factory({
		wasmBinary,
		noInitialRun: true,
		print: (line: string) => (stdout += line + '\n'),
		printErr: (line: string) => (stderr += line + '\n'),
		quit: () => {}
	});

	for (const [name, data] of Object.entries(inputs)) mod.FS.writeFile(name, data);

	try {
		mod.callMain(args);
	} catch (err) {
		if (!(err && typeof err === 'object' && 'status' in err)) throw err;
	}

	const files: Record<string, Uint8Array> = {};
	for (const name of outputs) {
		try {
			const data = mod.FS.readFile(name) as Uint8Array;
			if (data.length) files[name] = data;
		} catch {
			// not produced
		}
	}

	return { stdout, stderr, files };
};
