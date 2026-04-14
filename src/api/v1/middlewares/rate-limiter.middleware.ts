import redisClient from '@core/database/redis';
import type { Request, Response } from 'express';
import { rateLimit } from 'express-rate-limit';
import { RedisStore } from 'rate-limit-redis';

import { RATE_LIMIT } from '../../../core/common/constants/rate-limit.constant';

/**
 * ============================================================================
 * Global Rate Limiter
 * ============================================================================
 * General protection for the entire API surface.
 */
export const globalRateLimiter = rateLimit({
  windowMs: RATE_LIMIT.GLOBAL.WINDOW_MS,
  limit: RATE_LIMIT.GLOBAL.MAX_REQUESTS,
  message: {
    message: `Too many requests from this IP, please try again after ${
      RATE_LIMIT.GLOBAL.WINDOW_MS / 60 / 1000
    } minutes`,
  },
  standardHeaders: true,
  legacyHeaders: false,
  store: new RedisStore({
    // @ts-expect-error - ioredis and rate-limit-redis compatibility
    sendCommand: (...args: string[]) => redisClient.call(...args),
    prefix: 'rate-limit:global:',
  }),
  handler: (_req: Request, res: Response, _next, options) => {
    res.status(options.statusCode).json({
      success: false,
      message: options.message.message,
    });
  },
});

/**
 * ============================================================================
 * Authentication Rate Limiter
 * ============================================================================
 * Specific protection for Login and Registration to prevent brute-force attacks.
 * Only unsuccessful requests are counted.
 */
export const authRateLimiter = rateLimit({
  windowMs: RATE_LIMIT.AUTH.WINDOW_MS,
  limit: RATE_LIMIT.AUTH.MAX_REQUESTS,
  message: {
    message: `Too many login attempts from this IP, please try again after ${
      RATE_LIMIT.AUTH.WINDOW_MS / 60 / 1000
    } minutes`,
  },
  standardHeaders: true,
  legacyHeaders: false,
  store: new RedisStore({
    // @ts-expect-error - ioredis and rate-limit-redis compatibility
    sendCommand: (...args: string[]) => redisClient.call(...args),
    prefix: 'rate-limit:auth:',
  }),
  handler: (_req: Request, res: Response, _next, options) => {
    res.status(options.statusCode).json({
      success: false,
      message: options.message.message,
    });
  },
  skipSuccessfulRequests: true,
});

/**
 * ============================================================================
 * OIDC Identity Provider Rate Limiter
 * ============================================================================
 * Handles the systematic testing and legitimate IdP handshakes.
 * Set significantly higher than Auth to allow for the multi-step OIDC flow.
 */
export const oidcRateLimiter = rateLimit({
  windowMs: RATE_LIMIT.OIDC.WINDOW_MS,
  limit: RATE_LIMIT.OIDC.MAX_REQUESTS,
  message: {
    message: `Too many OIDC requests from this IP, please try again after ${
      RATE_LIMIT.OIDC.WINDOW_MS / 60 / 1000
    } minutes`,
  },
  standardHeaders: true,
  legacyHeaders: false,
  store: new RedisStore({
    // @ts-expect-error - ioredis and rate-limit-redis compatibility
    sendCommand: (...args: string[]) => redisClient.call(...args),
    prefix: 'rate-limit:oidc:',
  }),
  handler: (_req: Request, res: Response, _next, options) => {
    res.status(options.statusCode).json({
      success: false,
      message: options.message.message,
    });
  },
});
