/**
 * Unit tests for UserService.
 * Target: UserService (user profile lookups and formatting)
 * Mocks: PrismaClient (db lookups)
 */
import { describe, expect, it, vi } from 'vitest';
import { prismaMock } from '@tests/mocks/prisma';
import { UserService } from '@api/v1/services/user.service';
import { NotFoundException } from '@core/common/utils/app-error';

// Mock Prisma adapter globally
vi.mock('@core/database/prisma', () => ({
  default: prismaMock,
}));

describe('UserService Unit Tests', () => {
  const userService = new UserService();

  describe('currentUser', () => {
    it('should retrieve and sanitize the current user profile', async () => {
      // Given: A valid user ID and a mocked database record
      const userId = 'user-123';
      const mockDbUser = {
        id: userId,
        name: 'John Doe',
        email: 'john@example.com',
        role: 'USER' as const,
        createdAt: new Date(),
        updatedAt: new Date(),
        twoFactorSecret: 'secret123',
        enable2FA: false,
        backupCodes: ['code1'],
        emailVerified: false,
        image: null,
      };

      prismaMock.user.findUnique.mockResolvedValue(mockDbUser);

      // When: Querying the current user profile
      const result = await userService.currentUser({ userId });

      // Then: The profile should be returned and sensitive values (twoFactorSecret, backupCodes) sanitized
      expect(prismaMock.user.findUnique).toHaveBeenCalledWith({
        where: { id: userId },
      });
      expect(result).toEqual({
        id: userId,
        name: 'John Doe',
        email: 'john@example.com',
        role: 'USER',
        createdAt: mockDbUser.createdAt,
        updatedAt: mockDbUser.updatedAt,
        image: null,
        enable2FA: false,
        emailVerified: false,
      });
      expect(result).not.toHaveProperty('twoFactorSecret');
      expect(result).not.toHaveProperty('backupCodes');
    });

    it('should throw NotFoundException if user is not found in the database', async () => {
      // Given: A user ID of a non-existent user
      const userId = 'user-missing';
      prismaMock.user.findUnique.mockResolvedValue(null);

      // When & Then: Querying the profile should reject with a NotFoundException
      await expect(userService.currentUser({ userId })).rejects.toThrow(NotFoundException);
    });
  });
});
