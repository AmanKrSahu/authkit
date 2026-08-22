import 'dotenv/config';

import { logger } from '@core/common/utils/logger';
import { config } from '@core/config/app.config';
import redis from '@core/database/redis';

import { app } from './app';

app.listen(config.PORT, async () => {
  logger.info(`Server listening on port ${config.PORT} in ${config.NODE_ENV}`);

  try {
    await redis.ping();
    logger.info(`Redis connected on port ${config.REDIS.PORT} in ${config.NODE_ENV}`);
  } catch (error) {
    logger.error('Redis connection failed:', error as Error);
  }
});
