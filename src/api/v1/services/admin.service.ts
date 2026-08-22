import crypto from 'node:crypto';

import type {
  CreateOidcClientData,
  DeleteUserData,
  GetAllUsersData,
  GetUserByIdData,
  GetUserSessionsData,
  PromoteUserToAdminData,
  RevokeSessionByIdData,
  RevokeSessionsByUserIdData,
} from '@core/common/interface/admin.interface';
import { AppError, NotFoundException } from '@core/common/utils/app-error';
import { hashPassword } from '@core/common/utils/bcrypt';
import { paginateWithCursor } from '@core/common/utils/pagination';
import { deleteCache, deleteCacheMany } from '@core/common/utils/redis-helpers';
import { sanitizeUser } from '@core/common/utils/sanitize';
import { HTTPSTATUS } from '@core/config/http.config';
import prisma from '@core/database/prisma';
import { AuditAction, AuditStatus, Prisma, Role } from '@prisma/client';

import { AuditService } from './audit.service';

export class AdminService {
  private auditService: AuditService;

  constructor(auditService: AuditService = new AuditService()) {
    this.auditService = auditService;
  }

  public async promoteUserToAdmin(promoteUserToAdminData: PromoteUserToAdminData) {
    try {
      const { userId } = promoteUserToAdminData;

      const updatedUser = await prisma.user.update({
        where: { id: userId },
        data: {
          role: Role.ADMIN,
        },
      });

      const activeSessions = await prisma.session.findMany({
        where: { userId, isRevoked: false },
        select: { id: true },
      });

      // Invalidate active session caches in a single round-trip
      const cacheKeys = activeSessions.flatMap(session => [
        `session:${session.id}`,
        `active_refresh_token:${session.id}`,
      ]);
      await deleteCacheMany(cacheKeys);

      await this.auditService.log({
        action: AuditAction.ROLE_CHANGE,
        entityType: 'User',
        entityId: userId,
        description: `User ${updatedUser.email} promoted to ADMIN`,
        status: AuditStatus.SUCCESS,
        metadata: { newRole: 'ADMIN' },
      });

      return sanitizeUser(updatedUser);
    } catch (error) {
      if (error instanceof Prisma.PrismaClientKnownRequestError) {
        throw new NotFoundException('User not found');
      }
      if (error instanceof AppError) {
        throw error;
      }
      throw new AppError('Failed to promote user to admin', HTTPSTATUS.INTERNAL_SERVER_ERROR);
    }
  }

  public async deleteUser(deleteUserData: DeleteUserData) {
    try {
      const { userId } = deleteUserData;

      // Fetch active sessions to clear cache before cascade delete
      const sessions = await prisma.session.findMany({
        where: { userId, isRevoked: false },
        select: { id: true },
      });

      // Cascade delete user in database and verify match count
      const result = await prisma.user.deleteMany({
        where: { id: userId },
      });

      if (result.count === 0) {
        throw new NotFoundException('User not found');
      }

      // Invalidate Redis caches in a single round-trip
      const cacheKeys = sessions.flatMap(session => [
        `session:${session.id}`,
        `active_refresh_token:${session.id}`,
      ]);
      await deleteCacheMany(cacheKeys);

      await this.auditService.log({
        action: AuditAction.USER_DELETE,
        entityType: 'User',
        entityId: userId,
        description: `User account ${userId} deleted by admin`,
        status: AuditStatus.SUCCESS,
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

      // Update database directly and check count
      const result = await prisma.session.updateMany({
        where: { id: sessionId },
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

      await this.auditService.log({
        action: AuditAction.SESSION_REVOKE,
        entityType: 'Session',
        entityId: sessionId,
        description: `Session ${sessionId} revoked by admin`,
        status: AuditStatus.SUCCESS,
      });

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

      // Invalidate all user sessions and their rotation tokens in a single command
      const cacheKeys = sessions.flatMap(session => [
        `session:${session.id}`,
        `active_refresh_token:${session.id}`,
      ]);
      await deleteCacheMany(cacheKeys);

      await this.auditService.log({
        action: AuditAction.SESSION_REVOKE,
        entityType: 'Session',
        description: `All active sessions for user ${userId} revoked by admin`,
        status: AuditStatus.SUCCESS,
        metadata: { userId },
      });

      return null;
    } catch (error) {
      if (error instanceof AppError) {
        throw error;
      }
      throw new AppError('Failed to revoke user sessions', HTTPSTATUS.INTERNAL_SERVER_ERROR);
    }
  }

  public async createOidcClient(createOidcClientData: CreateOidcClientData) {
    try {
      const { clientName, redirectUrls, grantTypes, scope } = createOidcClientData;

      const clientId = crypto.randomBytes(32).toString('hex');
      const clientSecret = crypto.randomBytes(32).toString('hex');
      const hashedSecret = await hashPassword(clientSecret);

      const oidcClient = await prisma.oidcClient.create({
        data: {
          clientId,
          clientName,
          clientSecret: hashedSecret,
          redirectUrls,
          grantTypes,
          scope,
        },
      });

      await this.auditService.log({
        action: AuditAction.OIDC_CLIENT_CREATE,
        entityType: 'OidcClient',
        entityId: oidcClient.id,
        description: `OIDC Client registered: ${oidcClient.clientName}`,
        status: AuditStatus.SUCCESS,
        metadata: { clientId: oidcClient.clientId, clientName: oidcClient.clientName },
      });

      return {
        id: oidcClient.id,
        clientId,
        clientName: oidcClient.clientName,
        clientSecret,
        redirectUrls: oidcClient.redirectUrls,
        grantTypes: oidcClient.grantTypes,
        scope: oidcClient.scope,
      };
    } catch (error) {
      if (error instanceof AppError) {
        throw error;
      }
      throw new AppError('Failed to create OIDC client', HTTPSTATUS.INTERNAL_SERVER_ERROR);
    }
  }

  public async getAllUsers(getAllUsersData: GetAllUsersData) {
    try {
      const { cursor, limit } = getAllUsersData;

      const result = await paginateWithCursor(
        args =>
          prisma.user.findMany({
            orderBy: [{ createdAt: 'desc' }, { id: 'desc' }],
            ...args,
          }),
        () => prisma.user.count(),
        { cursor, limit }
      );

      return {
        users: result.data.map(user => sanitizeUser(user)),
        pagination: result.pagination,
      };
    } catch (error) {
      if (error instanceof AppError) {
        throw error;
      }

      throw new AppError('Failed to fetch users', HTTPSTATUS.INTERNAL_SERVER_ERROR);
    }
  }

  public async getUserById(getUserByIdData: GetUserByIdData) {
    try {
      const { userId } = getUserByIdData;
      const user = await prisma.user.findUnique({
        where: { id: userId },
      });

      if (!user) {
        throw new NotFoundException('User not found');
      }

      return sanitizeUser(user);
    } catch (error) {
      if (error instanceof AppError) {
        throw error;
      }

      throw new AppError('Failed to fetch user', HTTPSTATUS.INTERNAL_SERVER_ERROR);
    }
  }

  public async getUserSessions(getUserSessionsData: GetUserSessionsData) {
    try {
      const { userId, cursor, limit } = getUserSessionsData;

      const user = await prisma.user.findUnique({ where: { id: userId } });
      if (!user) {
        throw new NotFoundException('User not found');
      }

      const result = await paginateWithCursor(
        args =>
          prisma.session.findMany({
            where: {
              userId,
              isRevoked: false,
              expiresAt: {
                gt: new Date(),
              },
            },
            orderBy: [{ createdAt: 'desc' }, { id: 'desc' }],
            ...args,
          }),
        () =>
          prisma.session.count({
            where: {
              userId,
              isRevoked: false,
              expiresAt: {
                gt: new Date(),
              },
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
}
