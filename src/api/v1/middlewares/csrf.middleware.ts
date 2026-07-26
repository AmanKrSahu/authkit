import { AppError, UnauthorizedException } from '@core/common/utils/app-error';
import { isAllowedOrigin } from '@core/common/utils/url.util';
import { config } from '@core/config/app.config';
import { HTTPSTATUS } from '@core/config/http.config';
import type { NextFunction, Request, Response } from 'express';

export const requireAuthAction = (req: Request, _res: Response, next: NextFunction) => {
  // 1. Origin Check (Defense in Depth)
  const origin = req.headers.origin;

  if (config.NODE_ENV === 'production' && (!origin || !isAllowedOrigin(origin))) {
    return next(new UnauthorizedException('Invalid Origin for auth action'));
  }

  // 2. Double-Submit Cookie Check
  const csrfCookie = req.cookies.csrfToken;
  const csrfHeader = req.headers['x-csrf-token'];

  if (!csrfCookie || !csrfHeader || csrfCookie !== csrfHeader) {
    return next(new AppError('Invalid or missing CSRF token', HTTPSTATUS.FORBIDDEN));
  }

  next();
};
