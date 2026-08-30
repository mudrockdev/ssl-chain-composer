import { paraglideVitePlugin } from '@inlang/paraglide-js';
import tailwindcss from '@tailwindcss/vite';
import adapter from '@sveltejs/adapter-static';
import { sveltekit } from '@sveltejs/kit/vite';
import { defineConfig, type Plugin } from 'vite';
import { spawnSync } from 'node:child_process';

let certsGenerated = false;

/** Refresh src/lib/embedded-certs.ts before production builds (offline-safe: the
 *  generator keeps the committed file when the CA repositories are unreachable). */
function embeddedCertsPlugin(): Plugin {
	return {
		name: 'generate-embedded-certs',
		apply: 'build',
		buildStart() {
			// SvelteKit builds client and server in the same process — run once
			if (certsGenerated) return;
			certsGenerated = true;
			const result = spawnSync('bun', ['scripts/generate-embedded-certs.ts'], {
				stdio: 'inherit'
			});
			if (result.status !== 0) {
				throw new Error('scripts/generate-embedded-certs.ts failed');
			}
		}
	};
}

export default defineConfig({
	plugins: [
		embeddedCertsPlugin(),
		tailwindcss(),
		sveltekit({
			compilerOptions: {
				// Force runes mode for the project, except for libraries. Can be removed in svelte 6.
				runes: ({ filename }) =>
					filename.split(/[/\\]/).includes('node_modules') ? undefined : true,
				experimental: { async: true }
			},
			adapter: adapter()
		}),

		paraglideVitePlugin({
			project: './project.inlang',
			outdir: './src/lib/paraglide',
			emitTsDeclarations: true,
			// static site: the locale comes from the URL, no server middleware involved
			strategy: ['url', 'baseLocale']
		})
	]
});
