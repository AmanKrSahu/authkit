import type {
  DeleteUserData,
  PromoteUserToAdminData,
  RevokeSessionByIdData,
  RevokeSessionsByUserIdData,
} from '@core/common/interface/admin.interface';
import { AppError, NotFoundException } from '@core/common/utils/app-error';
import { deleteCache } from '@core/common/utils/redis-helpers';
import { sanitizeUser } from '@core/common/utils/sanitize';
import { HTTPSTATUS } from '@core/config/http.config';
import prisma from '@core/database/prisma';
import { Role } from '@prisma/client';

export class AdminService {
  public async promoteUserToAdmin(promoteUserToAdminData: PromoteUserToAdminData) {
    try {
      const { userId } = promoteUserToAdminData;

      const user = await prisma.user.findUnique({ where: { id: userId } });

      if (!user) {
        throw new NotFoundException('User not found');
      }

      const updatedUser = await prisma.user.update({
        where: { id: userId },
        data: {
          role: Role.ADMIN,
        },
      });

      return sanitizeUser(updatedUser);
    } catch (error) {
      if (error instanceof AppError) {
        throw error;
      }
      throw new AppError('Failed to promote user to admin', HTTPSTATUS.INTERNAL_SERVER_ERROR);
    }
  }

  public async deleteUser(deleteUserData: DeleteUserData) {
    try {
      const { userId } = deleteUserData;

      const user = await prisma.user.findUnique({ where: { id: userId } });

      if (!user) {
        throw new NotFoundException('User not found');
      }

      // Revoke sessions first to clear cache
      await this.revokeSessionsByUserId({ userId });

      await prisma.user.delete({
        where: { id: userId },
      });

      return null;
    } catch (error) {
      if (error instanceof AppError) {
        throw error;
      }
      throw new AppError('Failed to delete user', HTTPSTATUS.INTERNAL_SERVER_ERROR);
    }
  }

  public async revokeSessionById(revokeSessionByIdData: RevokeSessionByIdData) {
    try {
      const { sessionId } = revokeSessionByIdData;

      const session = await prisma.session.findUnique({
        where: { id: sessionId },
      });

      if (!session) {
        throw new NotFoundException('Session not found');
      }

      await prisma.session.update({
        where: { id: sessionId },
        data: {
          isRevoked: true,
          revokedAt: new Date(),
        },
      });

      await deleteCache(`session:${sessionId}`);

      return null;
    } catch (error) {
      if (error instanceof AppError) {
        throw error;
      }
      throw new AppError('Failed to revoke session', HTTPSTATUS.INTERNAL_SERVER_ERROR);
    }
  }

  public async revokeSessionsByUserId(revokeSessionsByUserIdData: RevokeSessionsByUserIdData) {
    try {
      const { userId } = revokeSessionsByUserIdData;

      const sessions = await prisma.session.findMany({
        where: {
          userId,
          isRevoked: false,
        },
        select: { id: true },
      });

      if (sessions.length === 0) {
        return null;
      }

      await prisma.session.updateMany({
        where: {
          userId,
          isRevoked: false,
        },
        data: {
          isRevoked: true,
          revokedAt: new Date(),
        },
      });

      for (const session of sessions) {
        await deleteCache(`session:${session.id}`);
      }

      return null;
    } catch (error) {
      if (error instanceof AppError) {
        throw error;
      }
      throw new AppError('Failed to revoke user sessions', HTTPSTATUS.INTERNAL_SERVER_ERROR);
    }
  }
}
