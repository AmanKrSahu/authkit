import { config } from '@core/config/app.config';
import { PrismaClient } from '@prisma/client';

declare global {
  var prisma: PrismaClient | undefined;
}

const prisma = globalThis.prisma ?? new PrismaClient();

if (config.NODE_ENV === 'development') globalThis.prisma = prisma;

export default prisma;
