/**
 * Helper to clean (purge) all database model records.
 * Used between integration and E2E test runs to maintain test isolation.
 */
import prisma from '@core/database/prisma';

export const cleanDb = async (): Promise<void> => {
  const models = ['session', 'account', 'user', 'oidcClient'];
  for (const model of models) {
    try {
      if ((prisma as any)[model]?.deleteMany) {
        await (prisma as any)[model].deleteMany();
      }
    } catch {
      // Ignore cleanup errors for non-existent records
    }
  }
};
