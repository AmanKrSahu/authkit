import { defineConfig } from 'tsup';

export default defineConfig({
  entry: ['src/api/index.ts', 'src/core/database/seed.ts', 'src/swagger/*.swagger.ts'],
  format: ['esm'],
  clean: true,
  sourcemap: process.env.NODE_ENV !== 'production',
  minify: process.env.NODE_ENV === 'production',
  splitting: false,
  outDir: 'dist',
  target: 'es2022',
});
