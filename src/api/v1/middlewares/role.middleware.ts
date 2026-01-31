import { AppError, UnauthorizedException } from '@core/common/utils/app-error';
import { HTTPSTATUS } from '@core/config/http.config';
import type { Role, User } from '@prisma/client';
import type { NextFunction, Request, Response } from 'express';

export const roleGuard = (requiredRole: Role) => {
  return async (req: Request, _res: Response, next: NextFunction) => {
    try {
      const user = req.user as User;

      if (!user) {
        throw new UnauthorizedException('User not authenticated');
      }

      if (user.role !== requiredRole) {
        throw new AppError(
          'You do not have permission to perform this action',
          HTTPSTATUS.FORBIDDEN
        );
      }

      next();
    } catch (error) {
      next(error);
    }
  };
};
