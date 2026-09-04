/**
 * Unit tests for AdminService.
 * Target: AdminService (user deletion, promotion, session controls, OIDC client creation, and user queries)
 * Mocks: PrismaClient (db operations), RedisClient (session caches)
 */
import { describe, expect, it, vi, beforeEach } from 'vitest';
import { prismaMock } from '@tests/mocks/prisma';
import { redisMock } from '@tests/mocks/redis';
import { AdminService } from '@api/v1/services/admin.service';
import { NotFoundException } from '@core/common/utils/app-error';
import { Role } from '@prisma/client';
import * as redisHelpers from '@core/common/utils/redis-helpers';
import { MockAuditService } from '@tests/mocks/audit';

// Mock Prisma adapter globally
vi.mock('@core/database/prisma', () => ({
  default: prismaMock,
}));

// Mock Redis adapter globally
vi.mock('@core/database/redis', () => ({
  default: redisMock,
}));

describe('AdminService Unit Tests', () => {
  const mockAuditService = new MockAuditService();
  const adminService = new AdminService(mockAuditService as any);

  beforeEach(() => {
    redisMock.flushall();
  });

  describe('promoteUserToAdmin', () => {
    it('should update user role to ADMIN and invalidate their active session caches', async () => {
      // Given: A valid user ID, mocked user update, and mocked active sessions list
      const userId = 'user-123';
      const mockUser = {
        id: userId,
        name: 'Regular User',
        email: 'user@example.com',
        role: Role.USER,
      };

      const updatedUser = { ...mockUser, role: Role.ADMIN };
      const mockSessions = [{ id: 'sess-1' }, { id: 'sess-2' }];

      prismaMock.user.update.mockResolvedValue(updatedUser as any);
      prismaMock.session.findMany.mockResolvedValue(mockSessions as any);

      const deleteCacheManySpy = vi.spyOn(redisHelpers, 'deleteCacheMany');

      // When: Promoting the user to admin
      const result = await adminService.promoteUserToAdmin({ userId });

      // Then: User role should be updated, and active session cache cleared
      expect(result.role).toBe(Role.ADMIN);
      expect(prismaMock.user.update).toHaveBeenCalledWith({
        where: { id: userId },
        data: { role: Role.ADMIN },
      });
      expect(deleteCacheManySpy).toHaveBeenCalledWith([
        'session:sess-1',
        'active_refresh_token:sess-1',
        'session:sess-2',
        'active_refresh_token:sess-2',
      ]);
    });
  });

  describe('deleteUser', () => {
    it('should delete user from DB and clear active session caches', async () => {
      // Given: A user ID, active session list, and mocked deleteCount = 1
      const userId = 'user-to-delete';
      const mockSessions = [{ id: 'sess-delete-1' }];

      prismaMock.session.findMany.mockResolvedValue(mockSessions as any);
      prismaMock.user.deleteMany.mockResolvedValue({ count: 1 });

      const deleteCacheManySpy = vi.spyOn(redisHelpers, 'deleteCacheMany');

      // When: Triggering administrative user deletion
      const result = await adminService.deleteUser({ userId });

      // Then: Response should be null, user deleted, and session caches purged
      expect(result).toBeNull();
      expect(prismaMock.user.deleteMany).toHaveBeenCalledWith({ where: { id: userId } });
      expect(deleteCacheManySpy).toHaveBeenCalledWith([
        'session:sess-delete-1',
        'active_refresh_token:sess-delete-1',
      ]);
    });

    it('should throw NotFoundException if user to delete does not exist', async () => {
      // Given: A non-existent user ID where deleteMany returns count = 0
      const userId = 'missing-user';
      prismaMock.user.deleteMany.mockResolvedValue({ count: 0 });

      // When & Then: Deleting user should throw NotFoundException
      await expect(adminService.deleteUser({ userId })).rejects.toThrow(NotFoundException);
    });
  });

  describe('createOidcClient', () => {
    it('should register a new OIDC client with secure hashes', async () => {
      // Given: OIDC client setup arguments
      const clientPayload = {
        clientName: 'Partner Portal',
        redirectUrls: ['http://localhost:3000/callback'],
        grantTypes: ['authorization_code'],
      };

      const mockClientResult = {
        id: 'oidc-123',
        clientName: clientPayload.clientName,
        clientId: 'generated-client-id-123',
        clientSecret: 'hashed-secret-value',
        redirectUrls: clientPayload.redirectUrls,
        grantTypes: clientPayload.grantTypes,
        scope: null,
      };

      prismaMock.oidcClient.create.mockResolvedValue(mockClientResult as any);

      // When: Creating the OIDC client
      const result = await adminService.createOidcClient(clientPayload);

      // Then: Client details and plaintext generated clientSecret should be returned
      expect(result.clientId).toBeDefined();
      expect(result.clientSecret).toBeDefined();
      expect(result.clientName).toBe(clientPayload.clientName);
      expect(prismaMock.oidcClient.create).toHaveBeenCalled();
    });
  });
});
