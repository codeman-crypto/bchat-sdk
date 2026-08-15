import { defineConfig, configDefaults } from 'vitest/config';

export default defineConfig({
  test: {
    environment: 'node',
    globals: true,
    // Vitest 4 dropped '**/dist/**' from its default excludes, so build output
    // gets picked up as a test suite. Scope collection to the TypeScript
    // sources explicitly rather than relying on the defaults.
    include: ['src/**/*.{test,spec}.ts'],
    exclude: [...configDefaults.exclude, 'dist/**', 'examples/**'],
    server: {
      deps: {
        // libsodium-wrappers-sumo ships an ESM entry whose relative imports omit
        // file extensions, so Vite's native ESM resolver fails on it
        // (ERR_MODULE_NOT_FOUND for libsodium-sumo.mjs) and every suite that
        // touches crypto refuses to collect. Inlining routes it through Vite.
        inline: ['libsodium-wrappers-sumo'],
      },
    },
  },
});
