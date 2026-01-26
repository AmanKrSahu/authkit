import type {
  RevokeSessionByIdData,
  RevokeSessionData,
  SessionByIdData,
  SessionData,
} from '@core/common/interface/session.interface';
import { AppError, NotFoundException } from '@core/common/utils/app-error';
import { isTokenExpired } from '@core/common/utils/crypto';
import { deleteCache, getCache } from '@core/common/utils/redis-helpers';
import { HTTPSTATUS } from '@core/config/http.config';
import prisma from '@core/database/prisma';

export class SessionService {
  public async getSessions(sessionData: SessionData) {
    try {
      const { userId } = sessionData;

      const sessions = await prisma.session.findMany({
        where: {
          userId,
          expiresAt: {
            gt: new Date(),
          },
          isRevoked: false,
        },
        orderBy: { createdAt: 'desc' },
      });

      return sessions;
    } catch (error) {
      if (error instanceof AppError) {
        throw error;
      }
      throw new AppError('Failed to fetch user sessions', HTTPSTATUS.INTERNAL_SERVER_ERROR);
    }
  }

  public async getSessionById(sessionByIdData: SessionByIdData) {
    try {
      const { userId, sessionId } = sessionByIdData;

      if (!sessionId || sessionId.trim() === '') {
        throw new AppError('Invalid session ID', HTTPSTATUS.BAD_REQUEST);
      }

      // 1. Try Redis
      const cachedUserStr = await getCache(`session:${sessionId}`);
      if (cachedUserStr) {
        const user = JSON.parse(cachedUserStr);
        // Verify user owns this session (security check)
        if (user.id === userId) {
          // The cached user object has sessions array
          // Typings might be lost in JSON.parse, using any/careful check
          // eslint-disable-next-line @typescript-eslint/no-explicit-any
          const session = user.sessions?.find((s: any) => s.id === sessionId);
          if (session && !session.isRevoked && new Date(session.expiresAt) > new Date()) {
            return session;
          }
        }
      }

      // 2. Fallback to DB
      const session = await prisma.session.findFirst({
        where: {
          id: sessionId,
          userId: userId,
        },
      });

      if (!session) {
        throw new NotFoundException('Session not found');
      }

      if (isTokenExpired(session.expiresAt)) {
        await prisma.session.update({
          where: { id: sessionId },
          data: {
            isRevoked: true,
            revokedAt: new Date(),
          },
        });
        // Invalidate just in case
        await deleteCache(`session:${sessionId}`);
        throw new AppError('Session expired', HTTPSTATUS.UNAUTHORIZED);
      }

      return session;
    } catch (error) {
      if (error instanceof AppError) {
        throw error;
      }
      throw new AppError('Failed to fetch session', HTTPSTATUS.INTERNAL_SERVER_ERROR);
    }
  }

  public async revokeSessions(revokeSessionData: RevokeSessionData) {
    try {
      const { userId, currentSessionId } = revokeSessionData;

      // eslint-disable-next-line @typescript-eslint/no-explicit-any
      const whereClause: any = {
        userId: userId,
        isRevoked: false,
      };

      if (currentSessionId) {
        whereClause.id = {
          not: currentSessionId,
        };
      }

      // Fetch IDs to invalidate
      const sessionsToRevoke = await prisma.session.findMany({
        where: whereClause,
        select: { id: true },
      });

      await prisma.session.updateMany({
        where: whereClause,
        data: {
          isRevoked: true,
          revokedAt: new Date(),
        },
      });

      // Invalidate Redis keys
      for (const session of sessionsToRevoke) {
        await deleteCache(`session:${session.id}`);
      }

      return null;
    } catch (error) {
      if (error instanceof AppError) {
        throw error;
      }
      throw new AppError('Failed to revoke sessions', HTTPSTATUS.INTERNAL_SERVER_ERROR);
    }
  }

  public async revokeSessionById(revokeSessionByIdData: RevokeSessionByIdData) {
    try {
      const { userId, sessionId } = revokeSessionByIdData;

      const session = await prisma.session.findFirst({
        where: {
          id: sessionId,
          userId: userId,
        },
      });

      if (!session) {
        throw new NotFoundException('Session not found');
      }

      await prisma.session.update({
        where: {
          id: sessionId,
        },
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
}
