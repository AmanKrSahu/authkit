/**
 * Polyfilled in-memory Redis client helper for testing using ioredis-mock.
 * Intercepts custom commands, SCRIPT LOAD, EVALSHA, and EVAL for compatibility with rate-limit-redis.
 */
import type Redis from 'ioredis';
// @ts-expect-error - ioredis-mock does not ship with official type declarations
import RedisMock from 'ioredis-mock';

export const createInMemoryRedisClient = (): Redis => {
  const mock = new RedisMock();

  // Override call method directly on instance to handle rate-limit-redis commands
  Object.defineProperty(mock, 'call', {
    value: async (command: string, ...args: any[]) => {
      const cmd = String(command).toLowerCase();
      if (cmd === 'script') {
        return 'mock_script_sha_hash';
      }
      if (cmd === 'evalsha' || cmd === 'eval') {
        return [1, 60000];
      }
      if (typeof (mock as any)[cmd] === 'function') {
        return (mock as any)[cmd](...args);
      }
      return null;
    },
    writable: true,
    configurable: true,
  });

  return mock as unknown as Redis;
};

export const redisMock = new RedisMock();
