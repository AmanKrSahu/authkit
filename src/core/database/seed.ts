import prisma from '@core/database/prisma';

import { logger } from '../common/utils/logger';

// =====================================================
// SEEDING FUNCTIONS
// =====================================================

// Add your custom seeding functions here

// =====================================================
// MAIN SEEDING FUNCTION
// =====================================================

async function main() {
  logger.info('Starting database seeding...');

  try {
    // Run all seed functions sequentially
    // Add your custom seeding functions here

    logger.info('All seeding completed successfully!');
  } catch (error) {
    logger.error('Seeding failed:', error as Error);
    throw error;
  }
}

// =====================================================
// EXECUTION WITH PROPER ERROR HANDLING
// =====================================================

async function runSeed() {
  try {
    await main();
  } catch (error) {
    logger.error('Fatal error during seeding:', error as Error);
    throw error;
  } finally {
    await prisma.$disconnect();
  }
}

// Execute the seed script
await runSeed();
