import 'dotenv/config';

import fs from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

import { swaggerSpec } from '../src/core/config/swagger.config';

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);

const distDir = path.join(__dirname, '../dist');
const swaggerPath = path.join(distDir, 'swagger.json');

if (!fs.existsSync(distDir)) {
  fs.mkdirSync(distDir, { recursive: true });
}

fs.writeFileSync(swaggerPath, JSON.stringify(swaggerSpec, null, 2), 'utf8');
