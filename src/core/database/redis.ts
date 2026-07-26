import { logger } from '@core/common/utils/logger';
import { config } from '@core/config/app.config';
import Redis, { type RedisOptions } from 'ioredis';

const redisConfig: RedisOptions = {
  host: config.REDIS.HOST,
  port: Number(config.REDIS.PORT),
};

if (config.REDIS.PASSWORD) {
  redisConfig.password = config.REDIS.PASSWORD;
}

if (config.REDIS.TLS === 'true') {
  redisConfig.tls = {};
}

const redisClient = new Redis(redisConfig);

redisClient.on('connect', () => {
  logger.info('Redis client connected successfully');
});

redisClient.on('error', error => {
  logger.error('Redis connection error:', error as Error);
});

export default redisClient;
