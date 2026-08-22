/**
 * In-memory Database Lifecycle Manager for AuthKit Test Suite.
 * Completely eliminates dependencies on Docker, PostgreSQL services, and network ports.
 */
import { logger } from '@core/common/utils/logger';

export const startTestContainer = async (): Promise<null> => {
  logger.info('In-memory database lifecycle active for test suite execution.');
  return null;
};

export const stopTestContainer = async (): Promise<void> => {
  // No-op for in-memory execution
};
