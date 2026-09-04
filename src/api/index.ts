import 'dotenv/config';

import { logger } from '@core/common/utils/logger';
import { config } from '@core/config/app.config';
import redis from '@core/database/redis';

import { app } from './app';
import { WebhookQueueWorker } from './v1/services/webhook-queue.worker';

const webhookWorker = new WebhookQueueWorker();

const server = app.listen(config.PORT, async () => {
  logger.info(`Server listening on port ${config.PORT} in ${config.NODE_ENV}`);

  try {
    await redis.ping();
    logger.info(`Redis connected on port ${config.REDIS.PORT} in ${config.NODE_ENV}`);
  } catch (error) {
    logger.error('Redis connection failed:', error as Error);
  }

  // Start background webhook delivery queue worker
  webhookWorker.start();
});

process.on('SIGTERM', () => {
  webhookWorker.stop();
  server.close();
});

process.on('SIGINT', () => {
  webhookWorker.stop();
  server.close();
});
