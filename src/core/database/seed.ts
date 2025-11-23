/* eslint-disable no-console */
import prisma from '@core/database/prisma';

// =====================================================
// SEEDING FUNCTIONS
// =====================================================

// Add your custom seeding functions here

// =====================================================
// MAIN SEEDING FUNCTION
// =====================================================

async function main() {
  console.log('Starting database seeding...');

  try {
    // Run all seed functions sequentially
    // Add your custom seeding functions here

    console.log('All seeding completed successfully!');
  } catch (error) {
    console.error('Seeding failed:', error);
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
    console.error('Fatal error during seeding:', error);
    throw error;
  } finally {
    await prisma.$disconnect();
  }
}

// Execute the seed script
await runSeed();
