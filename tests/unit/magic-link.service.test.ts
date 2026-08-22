/**
 * Unit tests for MagicLinkService.
 * Target: MagicLinkService (magic link requests, validation, token exchange, and notifications)
 * Mocks: PrismaClient (db lookups), RedisClient (cache tokens), MockEmailService (outbound emails)
 */
import { describe, expect, it, beforeEach, vi } from 'vitest';
import { prismaMock } from '@tests/mocks/prisma';
import { redisMock } from '@tests/mocks/redis';
import { MockEmailService } from '@tests/mocks/resend';
import { MagicLinkService } from '@api/v1/services/magic-link.service';
import { BadRequestException } from '@core/common/utils/app-error';

// Mock Prisma adapter globally
vi.mock('@core/database/prisma', () => ({
  default: prismaMock,
}));

describe('MagicLinkService Unit Tests', () => {
  let mockEmailService: MockEmailService;
  let magicLinkService: MagicLinkService;

  beforeEach(() => {
    redisMock.flushall();
    mockEmailService = new MockEmailService();
    magicLinkService = new MagicLinkService(mockEmailService as any);
  });

  describe('login', () => {
    it('should generate a token, save to cache, and send a magic link email', async () => {
      // Given: A registered user in the database
      const email = 'user@example.com';
      const mockUser = {
        id: 'user-123',
        name: 'Jane Doe',
        email,
        emailVerified: false,
        image: null,
        role: 'USER' as const,
        createdAt: new Date(),
        updatedAt: new Date(),
        twoFactorSecret: null,
        enable2FA: false,
        backupCodes: [],
      };

      prismaMock.user.findUnique.mockResolvedValue(mockUser);

      // When: Requesting a magic link login
      const result = await magicLinkService.login({
        email,
        ipAddress: '127.0.0.1',
      });

      // Then: The response should be null (uniform output) and the email sent
      expect(result).toBeNull();
      expect(prismaMock.user.findUnique).toHaveBeenCalledWith({ where: { email } });
      expect(mockEmailService.sendMagicLink).toHaveBeenCalledWith(
        email,
        expect.stringContaining('/auth/magic-link/verify?token='),
        'Jane Doe'
      );
    });

    it('should return null (indistinguishable response) if user email is not found', async () => {
      // Given: A non-registered email address
      const email = 'nonexistent@example.com';
      prismaMock.user.findUnique.mockResolvedValue(null);

      // When: Requesting a magic link login
      const result = await magicLinkService.login({
        email,
        ipAddress: '127.0.0.1',
      });

      // Then: The response should still be null to prevent account enumeration, and no email sent
      expect(result).toBeNull();
      expect(mockEmailService.sendMagicLink).not.toHaveBeenCalled();
    });
  });

  describe('verify', () => {
    it('should throw BadRequestException if token is missing or expired in cache', async () => {
      // Given: An invalid/expired magic link token
      const token = 'expired-token-value';

      // When & Then: Verifying token should throw BadRequestException
      await expect(
        magicLinkService.verify({
          token,
          ipAddress: '127.0.0.1',
          userAgent: 'Mozilla',
        })
      ).rejects.toThrow(BadRequestException);
    });

    it('should verify user, update emailVerified status, and establish a new session', async () => {
      // Given: A valid active token cached in Redis
      const token = 'valid-token';
      const email = 'user@example.com';
      await redisMock.set(`magic_link:${token}`, JSON.stringify({ email }));

      const mockUser = {
        id: 'user-123',
        name: 'Jane Doe',
        email,
        emailVerified: false, // Unverified initially
        image: null,
        role: 'USER' as const,
        createdAt: new Date(),
        updatedAt: new Date(),
        twoFactorSecret: null,
        enable2FA: false,
        backupCodes: [],
      };

      const mockSession = {
        id: 'sess-123',
        userId: 'user-123',
        expiresAt: new Date(),
        ipAddress: '127.0.0.1',
        userAgent: 'Mozilla',
        deviceFingerprint: 'fp-123',
        isRevoked: false,
      };

      prismaMock.user.findUnique.mockResolvedValue(mockUser);
      prismaMock.user.update.mockResolvedValue({ ...mockUser, emailVerified: true });
      prismaMock.session.create.mockResolvedValue(mockSession as any);

      // When: Verifying the magic link token
      const result = await magicLinkService.verify({
        token,
        ipAddress: '127.0.0.1',
        userAgent: 'Mozilla',
      });

      // Then: User should be implicitly verified, session created, and tokens issued
      expect(result.mfaRequired).toBe(false);
      expect(result.accessToken).toBeDefined();
      expect(result.refreshToken).toBeDefined();
      expect(prismaMock.user.update).toHaveBeenCalledWith({
        where: { id: mockUser.id },
        data: { emailVerified: true },
      });
      // Verification token should be deleted from cache
      const cachedToken = await redisMock.get(`magic_link:${token}`);
      expect(cachedToken).toBeNull();
    });

    it('should redirect user to MFA if 2FA is enabled', async () => {
      // Given: A valid token in cache for a user with enable2FA set to true
      const token = 'valid-mfa-token';
      const email = 'mfa-user@example.com';
      await redisMock.set(`magic_link:${token}`, JSON.stringify({ email }));

      const mockUser = {
        id: 'user-123',
        name: 'MFA User',
        email,
        emailVerified: true,
        image: null,
        role: 'USER' as const,
        createdAt: new Date(),
        updatedAt: new Date(),
        twoFactorSecret: 'totp-secret',
        enable2FA: true, // MFA active
        backupCodes: [],
      };

      prismaMock.user.findUnique.mockResolvedValue(mockUser);

      // When: Verifying the token
      const result = await magicLinkService.verify({
        token,
        ipAddress: '127.0.0.1',
        userAgent: 'Mozilla',
      });

      // Then: MFA redirect response should be returned, and a temporary mfaLoginToken issued
      expect(result.mfaRequired).toBe(true);
      expect(result.mfaLoginToken).toBeDefined();
      expect(result.accessToken).toBe('');
      expect(result.refreshToken).toBe('');
    });
  });
});
