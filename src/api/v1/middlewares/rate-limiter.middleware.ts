import { FIFTEEN_MINUTES_IN_MS } from '@core/common/utils/date-time';
import type { Request, Response } from 'express';
import rateLimit from 'express-rate-limit';

export const globalRateLimiter = rateLimit({
  windowMs: FIFTEEN_MINUTES_IN_MS,
  max: 100,
  message: {
    message: 'Too many requests from this IP, please try again after 15 minutes',
  },
  standardHeaders: true,
  legacyHeaders: false,

  handler: (_req: Request, res: Response, _next, options) => {
    res.status(options.statusCode).json({
      success: false,
      message: options.message.message,
    });
  },
});

export const authRateLimiter = rateLimit({
  windowMs: FIFTEEN_MINUTES_IN_MS,
  max: 5,
  message: {
    message: 'Too many login attempts from this IP, please try again after 15 minutes',
  },
  standardHeaders: true,
  legacyHeaders: false,

  handler: (_req: Request, res: Response, _next, options) => {
    res.status(options.statusCode).json({
      success: false,
      message: options.message.message,
    });
  },

  skipSuccessfulRequests: true,
});
