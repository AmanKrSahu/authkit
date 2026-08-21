import 'dotenv/config';

import fs from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

import { swaggerSpec } from '../src/core/config/swagger.config';

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);

const distDir = path.join(__dirname, '../dist');
const apiSpecsDir = path.join(__dirname, '../docs/api-specs');

const distSwaggerPath = path.join(distDir, 'swagger.json');
const docsOpenApiPath = path.join(apiSpecsDir, 'openapi.json');

if (!fs.existsSync(distDir)) {
  fs.mkdirSync(distDir, { recursive: true });
}

if (!fs.existsSync(apiSpecsDir)) {
  fs.mkdirSync(apiSpecsDir, { recursive: true });
}

fs.writeFileSync(distSwaggerPath, JSON.stringify(swaggerSpec, null, 2), 'utf8');
fs.writeFileSync(docsOpenApiPath, JSON.stringify(swaggerSpec, null, 2), 'utf8');
