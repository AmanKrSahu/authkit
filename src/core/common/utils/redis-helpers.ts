/* eslint-disable no-console */
import { AppError } from '@core/common/utils/app-error';
import { FIVE_MINUTES } from '@core/common/utils/date-time';
import redis from '@core/database/redis';

/**
 * Set a key with an expiration time
 */
export const setCache = async (key: string, value: string, ttl: number = FIVE_MINUTES) => {
  try {
    await redis.set(key, value, 'EX', ttl);
  } catch (error) {
    console.error(`Redis Set Error for key ${key}:`, error);
    // Non-blocking error for cache setting failure?
    // Usually better to throw if strict, but for cache often we log and proceed.
    // Given we are replacing DB for OTPs, this MUST succeed.
    throw new AppError('Internal Cache Error');
  }
};

/**
 * Get a value by key
 */
export const getCache = async (key: string): Promise<string | null> => {
  try {
    return await redis.get(key);
  } catch (error) {
    console.error(`Redis Get Error for key ${key}:`, error);
    return null;
  }
};

/**
 * Delete a key
 */
export const deleteCache = async (key: string) => {
  try {
    await redis.del(key);
  } catch (error) {
    console.error(`Redis Delete Error for key ${key}:`, error);
  }
};

/**
 * Increment a key atomically.
 * Returns the new value.
 * If key doesn't exist, it starts at 1.
 * Optional TTL to set expiry on first increment.
 */
export const incrementCache = async (key: string, ttl?: number): Promise<number> => {
  try {
    const value = await redis.incr(key);
    if (value === 1 && ttl) {
      await redis.expire(key, ttl);
    }
    return value;
  } catch (error) {
    console.error(`Redis Incr Error for key ${key}:`, error);
    throw new AppError('Internal Cache Error');
  }
};
