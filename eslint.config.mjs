import js from '@eslint/js';
import tsPlugin from '@typescript-eslint/eslint-plugin';
import tsParser from '@typescript-eslint/parser';
import importPlugin from 'eslint-plugin-import';
import prettier from 'eslint-config-prettier/flat';

// ESLint 9 flat config. The previous .eslintrc.json format is no longer read by
// default, and ESLint 8 is end-of-life (it pulls vulnerable js-yaml/flatted).
export default [
  { ignores: ['dist/**', 'node_modules/**', 'scripts/**', 'coverage/**'] },
  js.configs.recommended,
  {
    files: ['**/*.ts'],
    languageOptions: {
      parser: tsParser,
      ecmaVersion: 2022,
      sourceType: 'module',
      globals: {
        console: 'readonly',
        process: 'readonly',
        Buffer: 'readonly',
        setTimeout: 'readonly',
        clearTimeout: 'readonly',
        AbortController: 'readonly',
        URL: 'readonly',
        globalThis: 'readonly',
      },
    },
    plugins: {
      '@typescript-eslint': tsPlugin,
      import: importPlugin,
    },
    settings: {
      'import/resolver': { typescript: {} },
    },
    rules: {
      ...tsPlugin.configs.recommended.rules,
      ...importPlugin.flatConfigs.recommended.rules,
      'import/no-default-export': 'error',
      'import/no-unresolved': 'error',
      '@typescript-eslint/no-explicit-any': 'off',
      'no-unused-vars': 'off',
      '@typescript-eslint/no-unused-vars': ['error', { argsIgnorePattern: '^_' }],
    },
  },
  {
    files: ['**/*.d.ts'],
    rules: {
      'import/no-default-export': 'off',
      '@typescript-eslint/no-unused-vars': 'off',
      'no-var': 'off',
    },
  },
  {
    files: ['**/__tests__/**/*.ts'],
    rules: { '@typescript-eslint/no-non-null-assertion': 'off' },
  },
  prettier,
];
