import glueUrl from 'openssl-wasm/bin/openssl-3.1.0/openssl.js?url';
import wasmUrl from 'openssl-wasm/bin/openssl-3.1.0/openssl.wasm?url';

/**
 * OpenSSL 3.1 compiled to WebAssembly, used for the formats @peculiar/x509 cannot read —
 * currently PKCS#12 (.pfx/.p12), including password-protected and legacy RC2-encrypted files.
 *
 * Everything runs inside the page: input files are written to the module's in-memory
 * filesystem and nothing is ever uploaded. The ~2.6 MB binary is loaded lazily on first use.
 */

/** Emscripten module instance — only the parts used here. */
interface OpenSslModule {
	FS: {
		writeFile(path: string, data: Uint8Array | string): void;
		readFile(path: string, opts?: { encoding?: 'utf8' | 'binary' }): Uint8Array;
		unlink(path: string): void;
	};
	callMain(args: string[]): number | undefined;
}

type OpenSslFactory = (options: Record<string, unknown>) => Promise<OpenSslModule>;

export interface OpenSslResult {
	stdout: string;
	stderr: string;
	/** files named in `outputs` that the command actually produced */
	files: Record<string, Uint8Array>;
}

export type OpenSslRunner = (
	args: string[],
	inputs?: Record<string, Uint8Array>,
	outputs?: string[]
) => Promise<OpenSslResult>;

let factoryPromise: Promise<OpenSslFactory> | null = null;
let wasmPromise: Promise<ArrayBuffer> | null = null;

function loadScript(src: string): Promise<void> {
	return new Promise((resolve, reject) => {
		const script = document.createElement('script');
		script.src = src;
		script.onload = () => resolve();
		script.onerror = () => reject(new Error(`failed to load ${src}`));
		document.head.append(script);
	});
}

/**
 * The Emscripten glue is a classic script that publishes a global `Module` factory.
 * Load it once, take the factory, and put any pre-existing global back.
 */
async function loadFactory(): Promise<OpenSslFactory> {
	const globals = globalThis as { Module?: OpenSslFactory };
	const previous = globals.Module;
	await loadScript(glueUrl);
	const factory = globals.Module;
	globals.Module = previous;
	if (!factory) throw new Error('openssl-wasm did not expose its module factory');
	return factory;
}

function loadWasm(): Promise<ArrayBuffer> {
	return fetch(wasmUrl).then((res) => {
		if (!res.ok) throw new Error(`failed to load ${wasmUrl}`);
		return res.arrayBuffer();
	});
}

/**
 * Run one OpenSSL command against an in-memory filesystem.
 *
 * A fresh module instance is created per call: OpenSSL's `main` is not written to be
 * re-entered, so reusing an instance leaks state between commands. The compiled binary
 * itself is fetched only once and reused.
 */
export const runOpenSSL: OpenSslRunner = async (args, inputs = {}, outputs = []) => {
	factoryPromise ??= loadFactory();
	wasmPromise ??= loadWasm();
	const [factory, wasmBinary] = await Promise.all([factoryPromise, wasmPromise]);

	let stdout = '';
	let stderr = '';
	const mod = await factory({
		wasmBinary,
		noInitialRun: true,
		print: (line: string) => (stdout += line + '\n'),
		printErr: (line: string) => (stderr += line + '\n'),
		// the CLI calls exit(); swallow it so it does not tear down the page
		quit: () => {}
	});

	for (const [name, data] of Object.entries(inputs)) mod.FS.writeFile(name, data);

	try {
		mod.callMain(args);
	} catch (err) {
		// a non-zero exit is reported through stderr, which the caller inspects
		if (!(err && typeof err === 'object' && 'status' in err)) throw err;
	}

	const files: Record<string, Uint8Array> = {};
	for (const name of outputs) {
		try {
			const data = mod.FS.readFile(name);
			if (data.length) files[name] = data;
		} catch {
			// the command did not produce this file
		}
	}

	return { stdout, stderr, files };
};
