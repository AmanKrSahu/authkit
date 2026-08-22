/**
 * Unit tests for OAuthService.
 * Target: OAuthService (Google OAuth callbacks, user registration, and auto-linking)
 * Mocks: PrismaClient (db lookups), RedisClient (session token cache), MockEmailService (outbound emails)
 */
import { describe, expect, it, beforeEach, vi } from 'vitest';
import { prismaMock } from '@tests/mocks/prisma';
import { redisMock } from '@tests/mocks/redis';
import { OAuthService } from '@api/v1/services/oauth.service';
import { MockAuditService } from '@tests/mocks/audit';
import { MockEmailService } from '@tests/mocks/resend';
import { BadRequestException } from '@core/common/utils/app-error';

// Mock Prisma adapter globally
vi.mock('@core/database/prisma', () => ({
  default: prismaMock,
}));

describe('OAuthService Unit Tests', () => {
  let mockEmailService: MockEmailService;
  let mockAuditService: MockAuditService;
  let oauthService: OAuthService;

  beforeEach(() => {
    redisMock.flushall();
    mockEmailService = new MockEmailService();
    mockAuditService = new MockAuditService();
    oauthService = new OAuthService(mockEmailService as any, mockAuditService as any);
  });

  describe('loginWithGoogle', () => {
    it('should throw BadRequestException if Google profile contains no email address', async () => {
      // Given: An OAuth profile missing emails list
      const loginData = {
        profile: {
          id: 'google-123',
          displayName: 'Test User',
        } as any,
        ipAddress: '127.0.0.1',
        userAgent: 'Mozilla',
      };

      // When & Then: loginWithGoogle should throw BadRequestException
      await expect(oauthService.loginWithGoogle(loginData)).rejects.toThrow(BadRequestException);
    });

    it('should prevent auto-linking and throw pending verification exception if matching user email exists but is not verified', async () => {
      // Given: An unverified local credentials user and a matching Google profile login attempt
      const email = 'victim@example.com';
      const googleId = 'google-id-123';

      const mockUser = {
        id: 'user-123',
        email,
        emailVerified: false, // Unverified!
        accounts: [],
      };

      prismaMock.user.findUnique.mockResolvedValue(mockUser as any);

      const loginData = {
        profile: {
          id: googleId,
          displayName: 'Victim User',
          emails: [{ value: email }],
        } as any,
        ipAddress: '127.0.0.1',
        userAgent: 'Mozilla',
      };

      // When & Then: It must block login and reject with pending verification exception to block pre-account takeover
      await expect(oauthService.loginWithGoogle(loginData)).rejects.toThrow(BadRequestException);
    });

    it('should auto-link account if matching user exists and is verified', async () => {
      // Given: A verified local credentials user, and a matching Google profile login attempt
      const email = 'user@example.com';
      const googleId = 'google-id-123';

      const mockUser = {
        id: 'user-123',
        email,
        emailVerified: true, // Verified!
        accounts: [], // No Google account linked yet
      };

      prismaMock.user.findUnique.mockResolvedValue(mockUser as any);
      prismaMock.account.create.mockResolvedValue({ id: 'acc-google' } as any);
      prismaMock.session.create.mockResolvedValue({ id: 'sess-123', userId: 'user-123' } as any);

      const loginData = {
        profile: {
          id: googleId,
          displayName: 'User',
          emails: [{ value: email }],
        } as any,
        ipAddress: '127.0.0.1',
        userAgent: 'Mozilla',
      };

      // When: Logging in with Google
      const result = await oauthService.loginWithGoogle(loginData);

      // Then: The profile should be auto-linked, session created, and tokens issued
      expect(result.accessToken).toBeDefined();
      expect(result.refreshToken).toBeDefined();
      expect(prismaMock.account.create).toHaveBeenCalledWith({
        data: {
          userId: 'user-123',
          providerId: 'google',
          accountId: googleId,
        },
      });
    });
  });
});
