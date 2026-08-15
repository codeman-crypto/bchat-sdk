import { writeFileSync } from 'fs';

// Node decides CJS-vs-ESM from the nearest package.json. Without these markers
// the ESM build under dist/esm is loaded as CommonJS (SyntaxError: Cannot use
// import statement outside a module) and dist/cjs would break for any consumer
// that later adds "type": "module" to the root package.
writeFileSync('dist/esm/package.json', `${JSON.stringify({ type: 'module' }, null, 2)}\n`);
writeFileSync('dist/cjs/package.json', `${JSON.stringify({ type: 'commonjs' }, null, 2)}\n`);
console.log('postbuild: wrote dist/esm/package.json and dist/cjs/package.json');
