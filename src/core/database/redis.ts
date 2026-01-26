/* eslint-disable no-console */
import { config } from '@core/config/app.config';
import Redis from 'ioredis';

const redisConfig = {
  host: config.REDIS.HOST,
  port: Number(config.REDIS.PORT),
};

const redisClient = new Redis(redisConfig);

redisClient.on('connect', () => {
  console.log('Redis client connected successfully');
});

redisClient.on('error', error => {
  console.error('Redis connection error:', error);
});

export default redisClient;
