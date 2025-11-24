import type {
  RevokeSessionByIdData,
  RevokeSessionData,
  SessionByIdData,
  SessionData,
} from '@core/common/interface/session.interface';
import { AppError, NotFoundException } from '@core/common/utils/app-error';
import { isTokenExpired } from '@core/common/utils/crypto';
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

      await prisma.session.updateMany({
        where: whereClause,
        data: {
          isRevoked: true,
          revokedAt: new Date(),
        },
      });

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

      return null;
    } catch (error) {
      if (error instanceof AppError) {
        throw error;
      }
      throw new AppError('Failed to revoke session', HTTPSTATUS.INTERNAL_SERVER_ERROR);
    }
  }
}
