import { JWT_CONFIG } from '@core/common/constants/jwt.constant';
import { ErrorCodeEnum } from '@core/common/enums/error-code.enum';
import type {
  ChangePasswordData,
  ForgotPasswordData,
  LoginData,
  LogoutData,
  refreshAccessTokenData,
  RegisterData,
  ResendVerificationData,
  ResetPasswordData,
  VerifyEmailData,
  VerifyOtpData,
} from '@core/common/interface/auth.interface';
import {
  AppError,
  BadRequestException,
  NotFoundException,
  UnauthorizedException,
} from '@core/common/utils/app-error';
import { comparePassword, hashPassword } from '@core/common/utils/bcrypt';
import {
  generateDeviceFingerprint,
  generateOTP,
  generateRandomToken,
  hashToken,
  isTokenExpired,
  timingSafeCompare,
} from '@core/common/utils/crypto';
import { calculateExpirationDate, ONE_DAY } from '@core/common/utils/date-time';
import type { RefreshTPayload, ResetTPayload } from '@core/common/utils/jwt';
import {
  mfaTokenSignOptions,
  refreshTokenSignOptions,
  resetTokenSignOptions,
  signJwtToken,
  verifyJwtToken,
} from '@core/common/utils/jwt';
import {
  checkForNewDevice,
  checkLoginLockout,
  checkRateLimit,
  clearLoginLockout,
  incrementLoginFailedAttempts,
} from '@core/common/utils/metadata';
import {
  deleteCache,
  deleteCacheMany,
  getCache,
  incrementCache,
  setCache,
} from '@core/common/utils/redis-helpers';
import { sanitizeUser } from '@core/common/utils/sanitize';
import { getValidRedirectUrl } from '@core/common/utils/url.util';
import { HTTPSTATUS } from '@core/config/http.config';
import prisma from '@core/database/prisma';
import type { EmailService } from '@core/mailers/resend';
import { Prisma } from '@prisma/client';

import { RATE_LIMIT } from '../../../core/common/constants/rate-limit.constant';

export class AuthService {
  private emailService: EmailService;

  constructor(emailService: EmailService) {
    this.emailService = emailService;
  }

  public async register(registerData: RegisterData) {
    try {
      const { email, password, name, redirectUrl } = registerData;

      const existingUser = await prisma.user.findUnique({
        where: { email },
      });

      if (existingUser) {
        throw new BadRequestException(
          'User already exists with this email',
          ErrorCodeEnum.AUTH_EMAIL_ALREADY_EXISTS
        );
      }

      // Compute bcrypt hash outside database transaction to keep connections/locks free
      const hashedPassword = await hashPassword(password);

      const newUser = await prisma.$transaction(async tx => {
        const newUser = await tx.user.create({
          data: {
            email,
            name,
            emailVerified: false,
          },
        });

        await tx.account.create({
          data: {
            userId: newUser.id,
            providerId: 'credential',
            accountId: newUser.id,
            password: hashedPassword,
          },
        });

        return newUser;
      });

      const verificationToken = generateRandomToken();

      // Store verification token in Redis: key="verify_email:<token>", value=email
      await setCache(`verify_email:${verificationToken}`, email, ONE_DAY);

      const baseUrl = getValidRedirectUrl(redirectUrl);
      const verificationUrl = `${baseUrl}/auth/verify-email?token=${verificationToken}`;

      // Dispatch verification and welcome emails concurrently
      await Promise.all([
        this.emailService.sendEmailVerification(email, verificationUrl, name),
        this.emailService.sendWelcomeEmail(email, name),
      ]);

      return {
        user: sanitizeUser(newUser),
      };
    } catch (error) {
      if (error instanceof AppError) {
        throw error;
      }
      throw new AppError('Failed to create user', HTTPSTATUS.INTERNAL_SERVER_ERROR);
    }
  }

  public async verifyEmail(verifyEmailData: VerifyEmailData) {
    try {
      const { token } = verifyEmailData;

      // Check Redis for token
      const email = await getCache(`verify_email:${token}`);

      if (!email) {
        throw new BadRequestException('Invalid or expired verification token');
      }

      await prisma.user.update({
        where: { email },
        data: { emailVerified: true },
      });

      // Delete token from Redis
      await deleteCache(`verify_email:${token}`);

      return null;
    } catch (error) {
      if (error instanceof AppError) {
        throw error;
      }
      throw new AppError('Email verification failed', HTTPSTATUS.INTERNAL_SERVER_ERROR);
    }
  }

  public async resendVerification(resendVerificationData: ResendVerificationData) {
    try {
      const { email, redirectUrl, ipAddress } = resendVerificationData;

      if (ipAddress) {
        await checkRateLimit(email, ipAddress, RATE_LIMIT.OTP.MAX_REQUESTS, 'RESEND_VERIFICATION');
      }

      const user = await prisma.user.findUnique({
        where: { email },
      });

      if (!user) {
        // Return generic success to prevent account enumeration
        return null;
      }

      if (user.emailVerified) {
        // Return generic success to prevent account enumeration
        return null;
      }

      const verificationToken = generateRandomToken();

      // Store in Redis (overwrites if collision, but tokens are random so unlikely)
      await setCache(`verify_email:${verificationToken}`, email, ONE_DAY);

      const baseUrl = getValidRedirectUrl(redirectUrl);
      const verificationUrl = `${baseUrl}/auth/verify-email?token=${verificationToken}`;

      await this.emailService.sendEmailVerification(email, verificationUrl, user.name);

      return null;
    } catch (error) {
      if (error instanceof AppError) {
        throw error;
      }
      throw new AppError('Failed to send verification email', HTTPSTATUS.INTERNAL_SERVER_ERROR);
    }
  }

  public async login(loginData: LoginData) {
    try {
      const { email, password, ipAddress, userAgent } = loginData;

      await checkLoginLockout(email);

      const user = await prisma.user.findUnique({
        where: { email },
        include: {
          accounts: {
            where: { providerId: 'credential' },
          },
        },
      });

      if (!user) {
        await incrementLoginFailedAttempts(email);
        throw new BadRequestException(
          'Invalid email or password provided',
          ErrorCodeEnum.AUTH_USER_NOT_FOUND
        );
      }

      const credentialAccount = user.accounts[0];
      if (!credentialAccount?.password) {
        await incrementLoginFailedAttempts(email);
        throw new BadRequestException(
          'Invalid email or password provided',
          ErrorCodeEnum.AUTH_USER_NOT_FOUND
        );
      }

      const isValidPassword = await comparePassword(password, credentialAccount.password);
      if (!isValidPassword) {
        await incrementLoginFailedAttempts(email);
        throw new BadRequestException(
          'Invalid email or password provided',
          ErrorCodeEnum.AUTH_USER_NOT_FOUND
        );
      }

      if (!user.emailVerified) {
        throw new BadRequestException(
          'Please verify your email address before logging in.',
          ErrorCodeEnum.AUTH_ACCOUNT_PENDING_VERIFICATION
        );
      }

      // Clear lockout counters upon successful login
      await clearLoginLockout(email);

      if (user.enable2FA) {
        const { ...userInfo } = user;
        const nonce = generateRandomToken();
        await setCache(`mfa_login_nonce:${user.id}:${nonce}`, 'active', 300);

        const mfaLoginToken = signJwtToken(
          { userId: user.id, purpose: 'MFA_LOGIN', nonce },
          mfaTokenSignOptions
        );

        return {
          user: sanitizeUser(userInfo),
          mfaRequired: true,
          accessToken: '',
          refreshToken: '',
          mfaLoginToken,
        };
      }

      const deviceFingerprint = generateDeviceFingerprint(userAgent, ipAddress);
      const isNewDevice = await checkForNewDevice(user.id, deviceFingerprint);

      const expiresAt = calculateExpirationDate(JWT_CONFIG.REFRESH_EXPIRES_IN);

      const session = await prisma.session.create({
        data: {
          userId: user.id,
          expiresAt: expiresAt,
          ipAddress: ipAddress,
          userAgent: userAgent,
          deviceFingerprint,
          isNewDevice,
        },
      });

      if (isNewDevice) {
        await this.emailService.sendNewDeviceNotification(
          email,
          {
            deviceInfo: userAgent,
            ipAddress,
            loginTime: new Date(),
          },
          user.name
        );
      }

      const accessToken = signJwtToken({ userId: user.id, sessionId: session.id });
      const refreshToken = signJwtToken({ sessionId: session.id }, refreshTokenSignOptions);

      // Store refresh token hash in Redis
      const refreshTokenHash = hashToken(refreshToken);
      await setCache(
        `active_refresh_token:${session.id}`,
        refreshTokenHash,
        JWT_CONFIG.REFRESH_EXPIRES_IN
      );

      const { ...userInfo } = user;

      return {
        user: sanitizeUser(userInfo),
        mfaRequired: false,
        accessToken,
        refreshToken,
      };
    } catch (error) {
      if (error instanceof AppError) {
        throw error;
      }
      throw new AppError('Failed to sign in user', HTTPSTATUS.INTERNAL_SERVER_ERROR);
    }
  }

  public async logout(logoutData: LogoutData) {
    try {
      const { sessionId } = logoutData;

      await prisma.session.update({
        where: { id: sessionId },
        data: {
          isRevoked: true,
          revokedAt: new Date(),
        },
      });

      // Invalidate cache
      await deleteCache(`session:${sessionId}`);
      await deleteCache(`active_refresh_token:${sessionId}`);

      return null;
    } catch (error) {
      if (error instanceof AppError) {
        throw error;
      }
      throw new AppError('Failed to logout', HTTPSTATUS.INTERNAL_SERVER_ERROR);
    }
  }

  public async refreshAccessToken(refreshAccessTokenData: refreshAccessTokenData) {
    try {
      const { refreshToken } = refreshAccessTokenData;

      const { payload } = verifyJwtToken<RefreshTPayload>(refreshToken, {
        secret: refreshTokenSignOptions.secret,
      });

      if (!payload) {
        throw new UnauthorizedException('Invalid refresh token');
      }

      const session = await prisma.session.findUnique({
        where: { id: payload.sessionId },
        include: { user: true },
      });

      if (!session || session.isRevoked || isTokenExpired(session.expiresAt)) {
        throw new UnauthorizedException('Session expired or invalid');
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
        throw new UnauthorizedException('Refresh token reuse detected. Session revoked.');
      }

      const newAccessToken = signJwtToken({
        userId: session.userId,
        sessionId: session.id,
      });

      const newRefreshToken = signJwtToken({ sessionId: session.id }, refreshTokenSignOptions);

      // Store new refresh token hash in Redis
      const newRefreshTokenHash = hashToken(newRefreshToken);
      await setCache(
        `active_refresh_token:${session.id}`,
        newRefreshTokenHash,
        JWT_CONFIG.REFRESH_EXPIRES_IN
      );

      await prisma.session.update({
        where: { id: session.id },
        data: { expiresAt: calculateExpirationDate(JWT_CONFIG.REFRESH_EXPIRES_IN) },
      });

      // Invalidate cache to force update of expiry
      await deleteCache(`session:${session.id}`);

      return {
        newAccessToken,
        newRefreshToken,
      };
    } catch (error) {
      if (error instanceof AppError) {
        throw error;
      }
      throw new AppError('Failed to refresh token', HTTPSTATUS.INTERNAL_SERVER_ERROR);
    }
  }

  public async forgotPassword(forgotPasswordData: ForgotPasswordData) {
    try {
      const { email, ipAddress } = forgotPasswordData;

      await checkRateLimit(email, ipAddress, RATE_LIMIT.OTP.MAX_REQUESTS);

      const user = await prisma.user.findUnique({
        where: { email },
      });

      if (!user) {
        // Return generic success to prevent account enumeration
        return null;
      }

      const otp = generateOTP();

      // Store OTP in Redis with expiry: key="password_reset:<email>"
      await setCache(`password_reset:${email}`, otp, RATE_LIMIT.OTP.EXPIRY_MS / 1000);

      await this.emailService.sendPasswordResetOTP(email, otp, user.name);

      return null;
    } catch (error) {
      if (error instanceof AppError) {
        throw error;
      }
      throw new AppError('Failed to send password reset email', HTTPSTATUS.INTERNAL_SERVER_ERROR);
    }
  }

  public async verifyOtp(verifyOtpData: VerifyOtpData) {
    try {
      const { email, otp } = verifyOtpData;

      const key = `password_reset:${email}`;
      const storedOtp = await getCache(key);

      if (!storedOtp) {
        throw new BadRequestException('No active OTP found or expired. Please request a new one.');
      }

      // Check attempts
      const attemptsKey = `password_reset_attempts:${email}`;
      const previousAttempts = await incrementCache(attemptsKey, RATE_LIMIT.OTP.WINDOW_MS / 1000);

      if (previousAttempts > RATE_LIMIT.OTP.MAX_VERIFICATION_ATTEMPTS) {
        await deleteCache(key); // Invalidate OTP
        await deleteCache(attemptsKey);
        throw new BadRequestException('Too many failed attempts. Please request a new OTP.');
      }

      if (!timingSafeCompare(storedOtp, otp)) {
        const remainingAttempts = RATE_LIMIT.OTP.MAX_VERIFICATION_ATTEMPTS - previousAttempts;
        throw new BadRequestException(`Invalid OTP. ${remainingAttempts} attempt(s) remaining.`);
      }

      // Cleanup
      await deleteCache(key);
      await deleteCache(attemptsKey);

      const resetToken = signJwtToken({ email, purpose: 'PASSWORD_RESET' }, resetTokenSignOptions);

      return { resetToken };
    } catch (error) {
      if (error instanceof AppError) {
        throw error;
      }
      throw new AppError('Failed to verify OTP', HTTPSTATUS.INTERNAL_SERVER_ERROR);
    }
  }

  public async resetPassword(resetPasswordData: ResetPasswordData) {
    try {
      const { password, resetToken } = resetPasswordData;

      const { payload } = verifyJwtToken<ResetTPayload>(resetToken, {
        secret: resetTokenSignOptions.secret,
      });

      if (payload?.purpose !== 'PASSWORD_RESET') {
        throw new UnauthorizedException('Invalid reset token');
      }

      const email = payload.email;

      const hashedPassword = await hashPassword(password);

      // Execute password write, session revocation, and fetch profile atomically
      const updatedUser = await prisma.$transaction(async tx => {
        const u = await tx.user.update({
          where: { email },
          data: {
            accounts: {
              updateMany: {
                where: { providerId: 'credential' },
                data: { password: hashedPassword },
              },
            },
          },
          select: {
            id: true,
            name: true,
          },
        });

        await tx.session.updateMany({
          where: { userId: u.id },
          data: {
            isRevoked: true,
            revokedAt: new Date(),
          },
        });

        return u;
      });

      // Fetch active sessions to invalidate cache
      const activeSessions = await prisma.session.findMany({
        where: { userId: updatedUser.id, isRevoked: false },
        select: { id: true },
      });

      // Invalidate Redis keys in a single round-trip
      const cacheKeys = activeSessions.flatMap(session => [
        `session:${session.id}`,
        `active_refresh_token:${session.id}`,
      ]);
      await deleteCacheMany(cacheKeys);

      await this.emailService.sendPasswordChangeConfirmation(email, updatedUser.name);

      return null;
    } catch (error) {
      if (error instanceof Prisma.PrismaClientKnownRequestError) {
        throw new UnauthorizedException('Invalid reset token');
      }
      if (error instanceof AppError) {
        throw error;
      }
      throw new AppError('Failed to reset password', HTTPSTATUS.INTERNAL_SERVER_ERROR);
    }
  }

  public async changePassword(changePasswordData: ChangePasswordData) {
    try {
      const { userId, currentPassword, newPassword } = changePasswordData;

      const user = await prisma.user.findUnique({
        where: { id: userId },
        include: {
          accounts: {
            where: { providerId: 'credential' },
          },
        },
      });

      if (!user) {
        throw new NotFoundException('User not found');
      }

      const credentialAccount = user.accounts[0];
      if (!credentialAccount?.password) {
        throw new BadRequestException(
          'Invalid email or password provided',
          ErrorCodeEnum.AUTH_USER_NOT_FOUND
        );
      }

      const isValidPassword = await comparePassword(currentPassword, credentialAccount.password);
      if (!isValidPassword) {
        throw new BadRequestException(
          'Invalid email or password provided',
          ErrorCodeEnum.AUTH_USER_NOT_FOUND
        );
      }

      if (currentPassword === newPassword) {
        throw new BadRequestException('New password cannot be the same as the old one');
      }

      // Fetch active sessions to invalidate cache
      const activeSessions = await prisma.session.findMany({
        where: { userId: userId, isRevoked: false },
        select: { id: true },
      });

      const hashedPassword = await hashPassword(newPassword);

      await prisma.$transaction(async tx => {
        await tx.account.updateMany({
          where: {
            userId: userId,
            providerId: 'credential',
          },
          data: {
            password: hashedPassword,
          },
        });

        await tx.session.updateMany({
          where: { userId: userId },
          data: {
            isRevoked: true,
            revokedAt: new Date(),
          },
        });
      });

      // Invalidate Redis keys in a single round-trip
      const cacheKeys = activeSessions.flatMap(session => [
        `session:${session.id}`,
        `active_refresh_token:${session.id}`,
      ]);
      await deleteCacheMany(cacheKeys);

      await this.emailService.sendPasswordChangeConfirmation(user.email, user.name);

      return null;
    } catch (error) {
      if (error instanceof AppError) {
        throw error;
      }
      throw new AppError('Failed to change the password', HTTPSTATUS.INTERNAL_SERVER_ERROR);
    }
  }
}
