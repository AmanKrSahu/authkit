import { logger } from '@core/common/utils/logger';
import { config } from '@core/config/app.config';
import { createInMemoryRedisClient } from '@tests/mocks/redis';
import Redis, { type RedisOptions } from 'ioredis';

const isTest = config.NODE_ENV === 'test' || process.env.VITEST === 'true';

let redisClient: Redis;

if (isTest) {
  redisClient = createInMemoryRedisClient();
} else {
  const redisConfig: RedisOptions = {
    host: config.REDIS.HOST,
    port: Number(config.REDIS.PORT),
    maxRetriesPerRequest: null,
    enableReadyCheck: true,
    connectTimeout: 10_000,
    retryStrategy(times) {
      const delay = Math.min(times * 50, 2000);
      return delay;
    },
  };

  if (config.REDIS.PASSWORD) {
    redisConfig.password = config.REDIS.PASSWORD;
  }

  if (config.REDIS.TLS === 'true') {
    redisConfig.tls = {};
  }

  redisClient = new Redis(redisConfig);

  redisClient.on('connect', () => {
    logger.info('Redis client connected successfully');
  });

  redisClient.on('error', error => {
    logger.error('Redis connection error:', error as Error);
  });
}

export default redisClient;
