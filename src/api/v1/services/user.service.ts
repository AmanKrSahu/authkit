import type { CurrentUserData } from '@core/common/interface/user.interface';
import { AppError, NotFoundException } from '@core/common/utils/app-error';
import { HTTPSTATUS } from '@core/config/http.config';
import prisma from '@core/database/prisma';

export class UserService {
  public async currentUser(currentUserData: CurrentUserData) {
    try {
      const { userId } = currentUserData;

      const user = await prisma.user.findUnique({
        where: { id: userId },
      });

      if (!user) {
        throw new NotFoundException('User not found');
      }

      return user;
    } catch (error) {
      if (error instanceof AppError) {
        throw error;
      }
      throw new AppError('Failed to fetch user', HTTPSTATUS.INTERNAL_SERVER_ERROR);
    }
  }
}
