/**
 * Unit tests for AuthService.
 * Target: AuthService (user registration, email verification, credentials login, lockouts, password resets, and changes)
 * Mocks: PrismaClient (db operations), RedisClient (lockout and token caches), MockEmailService (outbound emails)
 */
import { describe, expect, it, vi, beforeEach } from 'vitest';
import { prismaMock } from '@tests/mocks/prisma';
import { redisMock } from '@tests/mocks/redis';
import { MockAuditService } from '@tests/mocks/audit';
import { MockEmailService } from '@tests/mocks/resend';
import { AuthService } from '@api/v1/services/auth.service';
import { BadRequestException, UnauthorizedException } from '@core/common/utils/app-error';
import { hashPassword } from '@core/common/utils/bcrypt';
import { signJwtToken, resetTokenSignOptions } from '@core/common/utils/jwt';

// Mock Prisma adapter globally
vi.mock('@core/database/prisma', () => ({
  default: prismaMock,
}));

// Mock EmailService globally
vi.mock('@core/mailers/resend', async () => {
  const { MockEmailService } = await import('@tests/mocks/resend');
  return {
    EmailService: MockEmailService,
  };
});

describe('AuthService Unit Tests', () => {
  let mockEmailService: MockEmailService;
  let mockAuditService: MockAuditService;
  let authService: AuthService;

  beforeEach(() => {
    redisMock.flushall();
    mockEmailService = new MockEmailService();
    mockAuditService = new MockAuditService();
    authService = new AuthService(mockEmailService as any, mockAuditService as any);
  });

  describe('register', () => {
    it('should register a new user, create their credentials account, cache verification token, and dispatch welcome/verification emails', async () => {
      // Given: Registration payload and database mocks
      const registerData = {
        email: 'register@example.com',
        password: 'Password123!',
        confirmPassword: 'Password123!',
        name: 'New User',
        redirectUrl: 'http://localhost:3000',
      };

      prismaMock.user.findUnique.mockResolvedValue(null); // Email is free
      prismaMock.$transaction.mockImplementation(async (callback: any) => {
        return callback(prismaMock);
      });
      prismaMock.user.create.mockResolvedValue({
        id: 'user-123',
        email: registerData.email,
        name: registerData.name,
        emailVerified: false,
      } as any);

      // When: Registering the user
      const result = await authService.register(registerData);

      // Then: User profile should be returned, token cached in Redis, and both emails dispatched concurrently
      expect(result.user.email).toBe(registerData.email);
      expect(prismaMock.user.create).toHaveBeenCalledWith({
        data: expect.objectContaining({ email: registerData.email }),
      });
      expect(prismaMock.account.create).toHaveBeenCalled();
      expect(mockEmailService.sendEmailVerification).toHaveBeenCalled();
      expect(mockEmailService.sendWelcomeEmail).toHaveBeenCalled();
    });

    it('should throw BadRequestException if the user email is already registered', async () => {
      // Given: Existing user in the database
      const registerData = {
        email: 'existing@example.com',
        password: 'Password123!',
        confirmPassword: 'Password123!',
        name: 'Existing',
      };

      prismaMock.user.findUnique.mockResolvedValue({ id: 'user-1' } as any);

      // When & Then: Registering should throw BadRequestException
      await expect(authService.register(registerData)).rejects.toThrow(BadRequestException);
    });
  });

  describe('verifyEmail', () => {
    it('should verify email status in DB and clear verification token from cache', async () => {
      // Given: Valid cached verification token
      const token = 'verify-token-123';
      const email = 'user@example.com';
      await redisMock.set(`verify_email:${token}`, email);

      prismaMock.user.update.mockResolvedValue({ id: 'user-123', emailVerified: true } as any);

      // When: Verifying the email using the token
      const result = await authService.verifyEmail({ token });

      // Then: Email verification should succeed, DB update user status, and token deleted from cache
      expect(result).toBeNull();
      expect(prismaMock.user.update).toHaveBeenCalledWith({
        where: { email },
        data: { emailVerified: true },
      });
      const cachedToken = await redisMock.get(`verify_email:${token}`);
      expect(cachedToken).toBeNull();
    });

    it('should throw BadRequestException if token is missing or expired in cache', async () => {
      // Given: An invalid/expired verification token
      const token = 'expired-token';

      // When & Then: Verification should throw BadRequestException
      await expect(authService.verifyEmail({ token })).rejects.toThrow(BadRequestException);
    });
  });

  describe('login', () => {
    it('should verify credentials, clear lockouts, create session, and issue auth tokens', async () => {
      // Given: Hashed password, verified database user, and active account login payload
      const email = 'user@example.com';
      const password = 'Password123!';
      const passwordHash = await hashPassword(password);

      const mockUser = {
        id: 'user-123',
        name: 'John Doe',
        email,
        emailVerified: true,
        enable2FA: false,
        accounts: [
          {
            providerId: 'credentials',
            accountId: email,
            password: passwordHash,
          },
        ],
      };

      prismaMock.user.findUnique.mockResolvedValue(mockUser as any);
      prismaMock.session.create.mockResolvedValue({ id: 'sess-123', userId: 'user-123' } as any);

      // Set some initial failed attempts to verify successful login clears them
      await redisMock.set(`failed_attempts:${email}`, '3');

      // When: User logs in
      const result = await authService.login({
        email,
        password,
        ipAddress: '127.0.0.1',
        userAgent: 'Mozilla',
      });

      // Then: Login should succeed, session created, token counters cleared, and auth tokens returned
      expect(result.mfaRequired).toBe(false);
      expect(result.accessToken).toBeDefined();
      expect(result.refreshToken).toBeDefined();

      const failedAttempts = await redisMock.get(`failed_attempts:${email}`);
      expect(failedAttempts).toBeNull(); // Lockout counter cleared
    });

    it('should increment failed attempts counter and throw BadRequestException for invalid passwords', async () => {
      // Given: Matching user, but incorrect password parameter
      const email = 'user@example.com';
      const password = 'Password123!';
      const passwordHash = await hashPassword(password);

      const mockUser = {
        id: 'user-123',
        email,
        emailVerified: true,
        accounts: [
          {
            providerId: 'credentials',
            password: passwordHash,
          },
        ],
      };

      prismaMock.user.findUnique.mockResolvedValue(mockUser as any);

      // When & Then: Logging in with incorrect password should increment failed login counters and throw BadRequestException
      await expect(
        authService.login({
          email,
          password: 'wrongpassword',
          ipAddress: '127.0.0.1',
          userAgent: 'Mozilla',
        })
      ).rejects.toThrow(BadRequestException);

      const failedAttempts = await redisMock.get(`failed_attempts:${email}`);
      expect(failedAttempts).toBe('1');
    });

    it('should throw BadRequestException if the user has not verified their email address', async () => {
      // Given: Unverified user in the database
      const email = 'unverified@example.com';
      const password = 'Password123!';
      const passwordHash = await hashPassword(password);

      const mockUser = {
        id: 'user-123',
        email,
        emailVerified: false, // Pending verification
        accounts: [
          {
            providerId: 'credentials',
            password: passwordHash,
          },
        ],
      };

      prismaMock.user.findUnique.mockResolvedValue(mockUser as any);

      // When & Then: Logging in should throw pending verification BadRequestException
      await expect(
        authService.login({
          email,
          password,
          ipAddress: '127.0.0.1',
          userAgent: 'Mozilla',
        })
      ).rejects.toThrow(BadRequestException);
    });
  });

  describe('resetPassword', () => {
    it('should update password and revoke all active sessions for the user', async () => {
      // Given: Valid signed password reset token, matching user, and session list
      const email = 'user@example.com';
      const secret = 'reset-secret-must-be-32-chars-long';

      vi.stubEnv('JWT_RESET_SECRET', secret);

      const resetToken = signJwtToken({ email, purpose: 'PASSWORD_RESET' }, resetTokenSignOptions);

      const mockUser = {
        id: 'user-123',
        name: 'John Doe',
      };

      prismaMock.$transaction.mockImplementation(async (callback: any) => {
        return callback(prismaMock);
      });
      prismaMock.user.update.mockResolvedValue(mockUser as any);
      prismaMock.session.findMany.mockResolvedValue([{ id: 'sess-1' }] as any);

      // When: Resetting the password using the token
      const result = await authService.resetPassword({
        password: 'NewPassword123!',
        confirmPassword: 'NewPassword123!',
        resetToken,
      });

      // Then: DB should update account credentials, revoke all user sessions, and purge active caches
      expect(result).toBeNull();
      expect(prismaMock.user.update).toHaveBeenCalled();
      expect(prismaMock.session.updateMany).toHaveBeenCalledWith({
        where: { userId: mockUser.id },
        data: expect.objectContaining({ isRevoked: true }),
      });
      expect(mockEmailService.sendPasswordChangeConfirmation).toHaveBeenCalledWith(
        email,
        mockUser.name
      );

      vi.unstubAllEnvs();
    });

    it('should throw UnauthorizedException for invalid token purposes', async () => {
      // Given: A token signed with a different purpose (e.g. EMAIL_VERIFY)
      const email = 'user@example.com';
      const secret = 'reset-secret-must-be-32-chars-long';

      vi.stubEnv('JWT_RESET_SECRET', secret);

      const resetToken = signJwtToken(
        { email, purpose: 'EMAIL_VERIFICATION' } as any,
        resetTokenSignOptions
      );

      // When & Then: Resetting password should throw UnauthorizedException
      await expect(
        authService.resetPassword({
          password: 'NewPassword123!',
          confirmPassword: 'NewPassword123!',
          resetToken,
        })
      ).rejects.toThrow(UnauthorizedException);

      vi.unstubAllEnvs();
    });
  });
});
