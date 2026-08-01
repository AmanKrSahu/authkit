import type {
  RevokeSessionByIdData,
  RevokeSessionData,
  SessionByIdData,
  SessionData,
} from '@core/common/interface/session.interface';
import { AppError, NotFoundException } from '@core/common/utils/app-error';
import { hashToken, isTokenExpired } from '@core/common/utils/crypto';
import type { RefreshTPayload } from '@core/common/utils/jwt';
import { refreshTokenSignOptions, verifyJwtToken } from '@core/common/utils/jwt';
import { paginateWithCursor } from '@core/common/utils/pagination';
import { deleteCache, deleteCacheMany, getCache } from '@core/common/utils/redis-helpers';
import { sanitizeUser } from '@core/common/utils/sanitize';
import { HTTPSTATUS } from '@core/config/http.config';
import prisma from '@core/database/prisma';

export class SessionService {
  public async getSessions(sessionData: SessionData) {
    try {
      const { userId, cursor, limit } = sessionData;

      const result = await paginateWithCursor(
        args =>
          prisma.session.findMany({
            where: {
              userId,
              expiresAt: {
                gt: new Date(),
              },
              isRevoked: false,
            },
            orderBy: [{ createdAt: 'desc' }, { id: 'desc' }],
            ...args,
          }),
        () =>
          prisma.session.count({
            where: {
              userId,
              expiresAt: {
                gt: new Date(),
              },
              isRevoked: false,
            },
          }),
        { cursor, limit }
      );

      return {
        sessions: result.data,
        pagination: result.pagination,
      };
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

      // Query DB directly (on primary key id, extremely fast and indexed)
      const session = await prisma.session.findUnique({
        where: { id: sessionId },
      });

      if (session?.userId !== userId) {
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
        // Invalidate hot-path JWT token cache and active RTR token hash cache
        await deleteCache(`session:${sessionId}`);
        await deleteCache(`active_refresh_token:${sessionId}`);
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

      // Invalidate Redis keys in a single command
      const cacheKeys = sessionsToRevoke.flatMap(session => [
        `session:${session.id}`,
        `active_refresh_token:${session.id}`,
      ]);
      await deleteCacheMany(cacheKeys);

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

      // Update target session directly and check count to avoid pre-fetch query
      const result = await prisma.session.updateMany({
        where: {
          id: sessionId,
          userId: userId,
        },
        data: {
          isRevoked: true,
          revokedAt: new Date(),
        },
      });

      if (result.count === 0) {
        throw new NotFoundException('Session not found');
      }

      await deleteCache(`session:${sessionId}`);
      await deleteCache(`active_refresh_token:${sessionId}`);

      return null;
    } catch (error) {
      if (error instanceof AppError) {
        throw error;
      }
      throw new AppError('Failed to revoke session', HTTPSTATUS.INTERNAL_SERVER_ERROR);
    }
  }

  public async validateSession(refreshToken: string) {
    try {
      const { payload } = verifyJwtToken<RefreshTPayload>(refreshToken, {
        secret: refreshTokenSignOptions.secret,
      });

      if (!payload) {
        return null; // Invalid token signature
      }

      const session = await prisma.session.findUnique({
        where: { id: payload.sessionId },
        include: { user: true },
      });

      if (!session || session.isRevoked || isTokenExpired(session.expiresAt)) {
        return null; // Session invalid or expired
      }

      // Check for token reuse / replay attacks
      const incomingHash = hashToken(refreshToken);
      const cachedHash = await getCache(`active_refresh_token:${session.id}`);

      if (cachedHash && cachedHash !== incomingHash) {
        // Reuse detected! Immediately revoke the session
        await prisma.session.update({
          where: { id: session.id },
          data: { isRevoked: true, revokedAt: new Date() },
        });
        await deleteCache(`session:${session.id}`);
        await deleteCache(`active_refresh_token:${session.id}`);
        return null;
      }

      const { ...userInfo } = session.user;
      return sanitizeUser(userInfo);
    } catch {
      return null; // Any error (token malformed, etc) means invalid session
    }
  }
}
