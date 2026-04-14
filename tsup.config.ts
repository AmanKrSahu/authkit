import { defineConfig } from 'tsup';

export default defineConfig({
  entry: ['src/api/index.ts', 'src/core/database/seed.ts', 'src/swagger/*.swagger.ts'],
  format: ['esm'],
  clean: true,
  sourcemap: true,
  splitting: false,
  outDir: 'dist',
  target: 'es2022',
});
