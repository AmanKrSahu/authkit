/**
 * Unit tests for SessionService.
 * Target: SessionService (session listings, pagination, token validation, reuse detection, and revocations)
 * Mocks: PrismaClient (db lookups), RedisClient (token hash cache)
 */
import { describe, expect, it, vi, beforeEach } from 'vitest';
import { prismaMock } from '@tests/mocks/prisma';
import { redisMock } from '@tests/mocks/redis';
import { SessionService } from '@api/v1/services/session.service';
import { MockAuditService } from '@tests/mocks/audit';
import { NotFoundException, AppError } from '@core/common/utils/app-error';
import { signJwtToken, refreshTokenSignOptions } from '@core/common/utils/jwt';

// Import redis cache helper module to check spies if needed
import * as redisHelpers from '@core/common/utils/redis-helpers';

// Mock Prisma adapter globally
vi.mock('@core/database/prisma', () => ({
  default: prismaMock,
}));

describe('SessionService Unit Tests', () => {
  const mockAuditService = new MockAuditService();
  const sessionService = new SessionService(mockAuditService as any);

  beforeEach(() => {
    redisMock.flushall();
  });

  describe('getSessions', () => {
    it('should fetch and paginate active sessions of a user', async () => {
      // Given: A user ID and a mocked database query returning sessions
      const userId = 'user-123';
      const mockSessions = [
        {
          id: 'sess-1',
          userId,
          expiresAt: new Date(Date.now() + 100000),
          ipAddress: '127.0.0.1',
          userAgent: 'Mozilla',
          deviceFingerprint: 'fp-1',
          isRevoked: false,
          revokedAt: null,
          isNewDevice: false,
          createdAt: new Date(),
          updatedAt: new Date(),
        },
        {
          id: 'sess-2',
          userId,
          expiresAt: new Date(Date.now() + 100000),
          ipAddress: '127.0.0.1',
          userAgent: 'Mozilla',
          deviceFingerprint: 'fp-2',
          isRevoked: false,
          revokedAt: null,
          isNewDevice: false,
          createdAt: new Date(),
          updatedAt: new Date(),
        },
      ];

      prismaMock.session.findMany.mockResolvedValue(mockSessions);
      prismaMock.session.count.mockResolvedValue(2);

      // When: Querying user sessions with limit and cursor
      const result = await sessionService.getSessions({ userId, limit: 10 });

      // Then: The paginated sessions list should be returned
      expect(result.sessions).toHaveLength(2);
      expect(result.pagination.totalCount).toBe(2);
      expect(prismaMock.session.findMany).toHaveBeenCalled();
    });
  });

  describe('getSessionById', () => {
    it('should retrieve a session if it matches the userId and is not expired', async () => {
      // Given: A valid session record in the database
      const userId = 'user-123';
      const sessionId = 'sess-1';
      const mockSession = {
        id: sessionId,
        userId,
        expiresAt: new Date(Date.now() + 500000), // Active
        ipAddress: '127.0.0.1',
        userAgent: 'Mozilla',
        deviceFingerprint: 'fp-1',
        isRevoked: false,
        revokedAt: null,
        isNewDevice: false,
        createdAt: new Date(),
        updatedAt: new Date(),
      };

      prismaMock.session.findUnique.mockResolvedValue(mockSession);

      // When: Querying the session by ID
      const result = await sessionService.getSessionById({ userId, sessionId });

      // Then: The session should be returned
      expect(result).toEqual(mockSession);
    });

    it('should throw NotFoundException if session does not belong to user', async () => {
      // Given: A session that belongs to a different user
      const userId = 'user-123';
      const sessionId = 'sess-1';
      const mockSession = {
        id: sessionId,
        userId: 'user-other', // Mismatch
        expiresAt: new Date(Date.now() + 500000),
        ipAddress: '127.0.0.1',
        userAgent: 'Mozilla',
        deviceFingerprint: 'fp-1',
        isRevoked: false,
        revokedAt: null,
        isNewDevice: false,
        createdAt: new Date(),
        updatedAt: new Date(),
      };

      prismaMock.session.findUnique.mockResolvedValue(mockSession);

      // When & Then: Querying should throw NotFoundException
      await expect(sessionService.getSessionById({ userId, sessionId })).rejects.toThrow(
        NotFoundException
      );
    });

    it('should revoke session and throw AppError if session is expired', async () => {
      // Given: An expired session in the database
      const userId = 'user-123';
      const sessionId = 'sess-1';
      const mockSession = {
        id: sessionId,
        userId,
        expiresAt: new Date(Date.now() - 50000), // Expired
        ipAddress: '127.0.0.1',
        userAgent: 'Mozilla',
        deviceFingerprint: 'fp-1',
        isRevoked: false,
        revokedAt: null,
        isNewDevice: false,
        createdAt: new Date(),
        updatedAt: new Date(),
      };

      prismaMock.session.findUnique.mockResolvedValue(mockSession);

      // When & Then: Querying should update database to revoked, delete cache, and throw unauthorized AppError
      await expect(sessionService.getSessionById({ userId, sessionId })).rejects.toThrow(AppError);
      expect(prismaMock.session.update).toHaveBeenCalledWith({
        where: { id: sessionId },
        data: expect.objectContaining({ isRevoked: true }),
      });
    });
  });

  describe('revokeSessions', () => {
    it('should revoke all other active sessions for a user and clear caches', async () => {
      // Given: A list of sessions to revoke
      const userId = 'user-123';
      const currentSessionId = 'sess-current';
      const mockSessionsToRevoke = [{ id: 'sess-old-1' }, { id: 'sess-old-2' }];

      prismaMock.session.findMany.mockResolvedValue(mockSessionsToRevoke as any);
      prismaMock.session.updateMany.mockResolvedValue({ count: 2 });

      const deleteCacheManySpy = vi.spyOn(redisHelpers, 'deleteCacheMany');

      // When: Triggering batch session revocation
      await sessionService.revokeSessions({ userId, currentSessionId });

      // Then: The DB should update all records, and key caches should be cleared
      expect(prismaMock.session.updateMany).toHaveBeenCalledWith({
        where: {
          userId,
          isRevoked: false,
          id: { not: currentSessionId },
        },
        data: expect.objectContaining({ isRevoked: true }),
      });
      expect(deleteCacheManySpy).toHaveBeenCalledWith([
        'session:sess-old-1',
        'active_refresh_token:sess-old-1',
        'session:sess-old-2',
        'active_refresh_token:sess-old-2',
      ]);
    });
  });

  describe('revokeSessionById', () => {
    it('should revoke a specific session and delete caches', async () => {
      // Given: A valid session to delete
      const userId = 'user-123';
      const sessionId = 'sess-target';
      prismaMock.session.updateMany.mockResolvedValue({ count: 1 });

      const deleteCacheSpy = vi.spyOn(redisHelpers, 'deleteCache');

      // When: Revoking the session
      await sessionService.revokeSessionById({ userId, sessionId });

      // Then: DB should update and delete cache keys
      expect(prismaMock.session.updateMany).toHaveBeenCalledWith({
        where: { id: sessionId, userId },
        data: expect.objectContaining({ isRevoked: true }),
      });
      expect(deleteCacheSpy).toHaveBeenCalledWith(`session:${sessionId}`);
    });

    it('should throw NotFoundException if session to revoke does not exist', async () => {
      // Given: Database update returns count = 0
      const userId = 'user-123';
      const sessionId = 'sess-missing';
      prismaMock.session.updateMany.mockResolvedValue({ count: 0 });

      // When & Then: Revoking session should throw NotFoundException
      await expect(sessionService.revokeSessionById({ userId, sessionId })).rejects.toThrow(
        NotFoundException
      );
    });
  });

  describe('validateSession', () => {
    it('should return null if refresh token verification fails', async () => {
      // Given: An invalid refresh token signature
      const invalidToken = 'malformed-jwt-token';

      // When: Validating session
      const result = await sessionService.validateSession(invalidToken);

      // Then: Verification should return null
      expect(result).toBeNull();
    });

    it('should detect token reuse / replay attacks and immediately revoke session', async () => {
      // Given: A valid signed token, but cached active token hash mismatches the incoming token hash
      const sessionId = 'sess-1';
      const userId = 'user-123';
      const secret = 'refresh-secret-must-be-very-long-32-chars-long';

      // Override signature configuration for the test scope
      vi.stubEnv('JWT_REFRESH_SECRET', secret);

      const token = signJwtToken({ sessionId }, refreshTokenSignOptions);

      const mockDbSession = {
        id: sessionId,
        userId,
        expiresAt: new Date(Date.now() + 500000),
        isRevoked: false,
        user: {
          id: userId,
          name: 'John Doe',
          email: 'john@example.com',
          role: 'USER' as const,
        },
      };

      prismaMock.session.findUnique.mockResolvedValue(mockDbSession as any);

      // Cache active refresh token with a DIFFERENT hash (meaning this token was already rotated/reused)
      await redisMock.set(`active_refresh_token:${sessionId}`, 'different-token-hash');

      // When: Validating the reused token
      const result = await sessionService.validateSession(token);

      // Then: Validation should return null, and the session must be revoked in DB and cache
      expect(result).toBeNull();
      expect(prismaMock.session.update).toHaveBeenCalledWith({
        where: { id: sessionId },
        data: expect.objectContaining({ isRevoked: true }),
      });

      vi.unstubAllEnvs();
    });
  });
});
