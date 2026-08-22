/**
 * Unit tests for MfaService.
 * Target: MfaService (MFA enrollment, TOTP verification, backup code consumption, and login verification)
 * Mocks: PrismaClient (db lookups), RedisClient (MFA setup cache and nonces), MockEmailService (outbound emails)
 */
import { describe, expect, it, vi, beforeEach } from 'vitest';
import { prismaMock } from '@tests/mocks/prisma';
import { redisMock } from '@tests/mocks/redis';
import { MfaService } from '@api/v1/services/mfa.service';
import { MockAuditService } from '@tests/mocks/audit';
import { MockEmailService } from '@tests/mocks/resend';
import { BadRequestException, UnauthorizedException } from '@core/common/utils/app-error';
import { encrypt } from '@core/common/utils/crypto';
import { signJwtToken, mfaTokenSignOptions } from '@core/common/utils/jwt';
import bcrypt from 'bcrypt';
import speakeasy from 'speakeasy';

// Mock Prisma adapter globally
vi.mock('@core/database/prisma', () => ({
  default: prismaMock,
}));

// Mock EmailService globally so that MfaService instantiates the mock
vi.mock('@core/mailers/resend', async () => {
  const { MockEmailService } = await import('@tests/mocks/resend');
  return {
    EmailService: MockEmailService,
  };
});

describe('MfaService Unit Tests', () => {
  let mockEmailService: MockEmailService;
  let mockAuditService: MockAuditService;
  let mfaService: MfaService;

  beforeEach(() => {
    redisMock.flushall();
    mockEmailService = new MockEmailService();
    mockAuditService = new MockAuditService();
    mfaService = new MfaService(mockEmailService as any, mockAuditService as any);
  });

  describe('generateMFASetup', () => {
    it('should generate a secret key, QR code, and cache the secret key in Redis', async () => {
      // Given: A registered user in the database without 2FA enabled
      const userId = 'user-123';
      const mockUser = {
        id: userId,
        name: 'John Doe',
        email: 'john@example.com',
        emailVerified: true,
        enable2FA: false,
      };

      prismaMock.user.findUnique.mockResolvedValue(mockUser as any);

      // When: Initiating MFA setup
      const result = await mfaService.generateMFASetup({ userId });

      // Then: A base64 QR image URL should be returned, and the secret key cached in Redis (encrypted)
      expect(result.qrImageUrl).toContain('data:image/png;base64,');
      expect(prismaMock.user.findUnique).toHaveBeenCalledWith({ where: { id: userId } });

      const cachedSecret = await redisMock.get(`mfa_setup:${userId}`);
      expect(cachedSecret).toBeDefined();
      expect(cachedSecret).not.toBeNull();
    });

    it('should throw BadRequestException if user already has 2FA enabled', async () => {
      // Given: A user who has 2FA enabled
      const userId = 'user-123';
      const mockUser = {
        id: userId,
        enable2FA: true,
      };

      prismaMock.user.findUnique.mockResolvedValue(mockUser as any);

      // When & Then: Initiating setup should throw BadRequestException
      await expect(mfaService.generateMFASetup({ userId })).rejects.toThrow(BadRequestException);
    });
  });

  describe('verifyMFASetup', () => {
    it('should throw BadRequestException if setup was not initiated or expired', async () => {
      // Given: Verification code without initiating setup
      const userId = 'user-123';
      const mockUser = { id: userId, enable2FA: false };
      prismaMock.user.findUnique.mockResolvedValue(mockUser as any);

      // When & Then: Verifying code should throw BadRequestException
      await expect(mfaService.verifyMFASetup({ userId, code: '123456' })).rejects.toThrow(
        BadRequestException
      );
    });

    it('should verify code, activate 2FA in DB, generate backup codes, and purge cache', async () => {
      // Given: Initiated setup in cache, and a valid TOTP code
      const userId = 'user-123';
      const mockUser = { id: userId, enable2FA: false };
      const secret = speakeasy.generateSecret({ length: 20 });
      const secretKey = secret.base32;

      await redisMock.set(`mfa_setup:${userId}`, encrypt(secretKey));

      const validCode = speakeasy.totp({
        secret: secretKey,
        encoding: 'base32',
      });

      prismaMock.user.findUnique.mockResolvedValue(mockUser as any);
      prismaMock.user.update.mockResolvedValue({ ...mockUser, enable2FA: true } as any);

      // When: Verifying setup code
      const result = await mfaService.verifyMFASetup({ userId, code: validCode });

      // Then: MFA should be enabled, 5 backup codes returned, and cache setup key deleted
      expect(result.message).toBe('MFA setup completed successfully');
      expect(result.backupCodes).toHaveLength(5);
      expect(prismaMock.user.update).toHaveBeenCalledWith({
        where: { id: userId },
        data: expect.objectContaining({
          enable2FA: true,
          twoFactorSecret: expect.any(String),
          backupCodes: expect.any(Array),
        }),
      });

      const cachedSetup = await redisMock.get(`mfa_setup:${userId}`);
      expect(cachedSetup).toBeNull();
    });

    it('should throw BadRequestException for incorrect TOTP codes during verification', async () => {
      // Given: Initiated setup in cache, but an invalid/incorrect code
      const userId = 'user-123';
      const mockUser = { id: userId, enable2FA: false };
      const secretKey = 'testsecretkey';

      await redisMock.set(`mfa_setup:${userId}`, encrypt(secretKey));
      prismaMock.user.findUnique.mockResolvedValue(mockUser as any);

      // When & Then: Verifying incorrect code should throw BadRequestException
      await expect(mfaService.verifyMFASetup({ userId, code: '000000' })).rejects.toThrow(
        BadRequestException
      );
    });
  });

  describe('verifyMFAForLogin', () => {
    it('should throw UnauthorizedException if mfaLoginToken is invalid or expired', async () => {
      // Given: An invalid/expired login token
      const mfaLoginToken = 'invalid-token-sig';

      // When & Then: Validating login should throw UnauthorizedException
      await expect(
        mfaService.verifyMFAForLogin({
          code: '123456',
          mfaLoginToken,
          userAgent: 'Mozilla',
          ipAddress: '127.0.0.1',
        })
      ).rejects.toThrow(UnauthorizedException);
    });

    it('should verify login with backup codes and update remaining backup codes list', async () => {
      // Given: Valid mfaLoginToken, active login nonce, and a valid plaintext backup code
      const userId = 'user-123';
      const nonce = 'nonce-token-123';

      const mfaLoginToken = signJwtToken(
        { userId, purpose: 'MFA_LOGIN', nonce },
        mfaTokenSignOptions
      );

      // Cache active nonce in Redis
      await redisMock.set(`mfa_login_nonce:${userId}:${nonce}`, 'active');

      const rawBackupCode = 'abcd-1234';
      const hashedBackupCode = await bcrypt.hash(rawBackupCode, 10);

      const mockUser = {
        id: userId,
        email: 'user@example.com',
        name: 'John Doe',
        enable2FA: true,
        twoFactorSecret: encrypt('totpsecret'),
        backupCodes: [hashedBackupCode, 'other-hashed-code'],
      };

      prismaMock.user.findUnique.mockResolvedValue(mockUser as any);
      prismaMock.session.create.mockResolvedValue({ id: 'sess-123', userId } as any);
      prismaMock.$transaction.mockImplementation(async (callback: any) => {
        return callback(prismaMock);
      });

      // When: Submitting the plaintext backup code to authenticate
      const result = await mfaService.verifyMFAForLogin({
        code: rawBackupCode,
        mfaLoginToken,
        userAgent: 'Mozilla',
        ipAddress: '127.0.0.1',
      });

      // Then: Login should succeed, session created, and remaining backup codes updated in user table
      expect(result.accessToken).toBeDefined();
      expect(result.refreshToken).toBeDefined();
      expect(prismaMock.user.update).toHaveBeenCalledWith({
        where: { id: userId },
        data: {
          backupCodes: ['other-hashed-code'], // 'abcd-1234' is consumed and removed
        },
      });

      // Verify nonce is deleted
      const cachedNonce = await redisMock.get(`mfa_login_nonce:${userId}:${nonce}`);
      expect(cachedNonce).toBeNull();
    });
  });
});
