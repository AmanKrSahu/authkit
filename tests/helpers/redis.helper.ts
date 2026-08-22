/**
 * Helper to clear (flush) all Redis keys between test runs.
 */
import redis from '@core/database/redis';
import { logger } from '@core/common/utils/logger';

export const cleanRedis = async (): Promise<void> => {
  try {
    await redis.flushall();
  } catch (error) {
    logger.error(`[RedisHelper] Failed to flush Redis cache: ${error}`);
  }
};
