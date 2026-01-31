import { logger } from '@core/common/utils/logger';
import { config } from '@core/config/app.config';
import Redis from 'ioredis';

const redisConfig = {
  host: config.REDIS.HOST,
  port: Number(config.REDIS.PORT),
};

const redisClient = new Redis(redisConfig);

redisClient.on('connect', () => {
  logger.info('Redis client connected successfully');
});

redisClient.on('error', error => {
  logger.error('Redis connection error:', error as Error);
});

export default redisClient;
