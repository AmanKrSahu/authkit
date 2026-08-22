import { config } from '@core/config/app.config';
import { PrismaPg } from '@prisma/adapter-pg';
import { PrismaClient } from '@prisma/client';
import { createInMemoryPrismaClient } from '@tests/mocks/prisma';
import { Pool } from 'pg';

const isTest = config.NODE_ENV === 'test' || process.env.VITEST === 'true';

declare global {
  var prisma: PrismaClient | undefined;
}

let prisma: PrismaClient;

if (isTest) {
  prisma = createInMemoryPrismaClient();
} else {
  const connectionString = `${config.DATABASE_URL}`;
  const pool = new Pool({
    connectionString,
    max: 20,
    connectionTimeoutMillis: 5000,
    idleTimeoutMillis: 30_000,
    maxUses: 7500,
  });
  const adapter = new PrismaPg(pool);
  prisma = globalThis.prisma ?? new PrismaClient({ adapter });
  if (config.NODE_ENV === 'development') globalThis.prisma = prisma;
}

export default prisma;
