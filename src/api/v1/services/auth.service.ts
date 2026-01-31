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
  generateSessionToken,
  isTokenExpired,
} from '@core/common/utils/crypto';
import { FIVE_MINUTES, ONE_DAY, ONE_HOUR, sevenDaysFromNow } from '@core/common/utils/date-time';
import type { RefreshTPayload, ResetTPayload } from '@core/common/utils/jwt';
import {
  mfaTokenSignOptions,
  refreshTokenSignOptions,
  resetTokenSignOptions,
  signJwtToken,
  verifyJwtToken,
} from '@core/common/utils/jwt';
import { logger } from '@core/common/utils/logger';
import { checkForNewDevice, checkRateLimit } from '@core/common/utils/metadata';
import { deleteCache, getCache, incrementCache, setCache } from '@core/common/utils/redis-helpers';
import { sanitizeUser } from '@core/common/utils/sanitize';
import { config } from '@core/config/app.config';
import { HTTPSTATUS } from '@core/config/http.config';
import prisma from '@core/database/prisma';
import type { EmailService } from '@core/mailers/resend';

export class AuthService {
  private emailService: EmailService;

  constructor(emailService: EmailService) {
    this.emailService = emailService;
  }

  private readonly MAX_OTP_ATTEMPTS = 3;
  private readonly MAX_OTP_REQUESTS_PER_HOUR = 5;

  public async register(registerData: RegisterData) {
    try {
      const { email, password, name } = registerData;

      const existingUser = await prisma.user.findUnique({
        where: { email },
      });

      if (existingUser) {
        throw new BadRequestException(
          'User already exists with this email',
          ErrorCodeEnum.AUTH_EMAIL_ALREADY_EXISTS
        );
      }

      const newUser = await prisma.$transaction(async tx => {
        const newUser = await tx.user.create({
          data: {
            email,
            name,
            emailVerified: false,
          },
        });

        const hashedPassword = await hashPassword(password);

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

      const verificationUrl = `${config.FRONTEND_ORIGINS[0]}/auth/verify-email?token=${verificationToken}`;

      if (config.NODE_ENV === 'production') {
        await this.emailService.sendEmailVerification(email, verificationUrl, name);
      } else {
        logger.info(`Verification Token: ${verificationToken}`);
      }

      if (config.NODE_ENV === 'production') {
        await this.emailService.sendWelcomeEmail(email, name);
      }

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
      const { email } = resendVerificationData;

      const user = await prisma.user.findUnique({
        where: { email },
      });

      if (!user) {
        throw new NotFoundException('User not found');
      }

      if (user.emailVerified) {
        throw new BadRequestException('Email is already verified');
      }

      const verificationToken = generateRandomToken();

      // Store in Redis (overwrites if collision, but tokens are random so unlikely)
      await setCache(`verify_email:${verificationToken}`, email, ONE_DAY);

      const verificationUrl = `${config.FRONTEND_ORIGINS[0]}/auth/verify-email?token=${verificationToken}`;

      if (config.NODE_ENV === 'production') {
        await this.emailService.sendEmailVerification(email, verificationUrl, user.name);
      } else {
        logger.info(`Verification Token: ${verificationToken}`);
      }

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

      const user = await prisma.user.findUnique({
        where: { email },
        include: {
          accounts: {
            where: { providerId: 'credential' },
          },
        },
      });

      if (!user) {
        throw new BadRequestException(
          'Invalid email or password provided',
          ErrorCodeEnum.AUTH_USER_NOT_FOUND
        );
      }

      const credentialAccount = user.accounts[0];
      if (!credentialAccount?.password) {
        throw new BadRequestException(
          'Invalid email or password provided',
          ErrorCodeEnum.AUTH_USER_NOT_FOUND
        );
      }

      const isValidPassword = await comparePassword(password, credentialAccount.password);
      if (!isValidPassword) {
        throw new BadRequestException(
          'Invalid email or password provided',
          ErrorCodeEnum.AUTH_USER_NOT_FOUND
        );
      }

      if (user.enable2FA) {
        const { ...userInfo } = user;
        const mfaLoginToken = signJwtToken(
          { userId: user.id, purpose: 'MFA_LOGIN' },
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

      const sessionToken = generateSessionToken();
      const expiresAt = sevenDaysFromNow();

      const session = await prisma.session.create({
        data: {
          token: sessionToken,
          userId: user.id,
          expiresAt: expiresAt,
          ipAddress: ipAddress,
          userAgent: userAgent,
          deviceFingerprint,
          isNewDevice,
        },
      });

      if (isNewDevice && config.NODE_ENV === 'production') {
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

      const newAccessToken = signJwtToken({
        userId: session.userId,
        sessionId: session.id,
      });

      const newRefreshToken = signJwtToken({ sessionId: session.id }, refreshTokenSignOptions);

      await prisma.session.update({
        where: { id: session.id },
        data: { expiresAt: sevenDaysFromNow() },
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

      const user = await prisma.user.findUnique({
        where: { email },
      });

      if (!user) {
        throw new NotFoundException('User not found');
      }

      await checkRateLimit(email, ipAddress, this.MAX_OTP_REQUESTS_PER_HOUR);

      const otp = generateOTP();

      // Store OTP in Redis with 5 min expiry: key="password_reset:<email>"
      await setCache(`password_reset:${email}`, otp, FIVE_MINUTES);

      if (config.NODE_ENV === 'production') {
        await this.emailService.sendPasswordResetOTP(email, otp, user.name);
      } else {
        logger.info(`Password Reset OTP: ${otp}`);
      }

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
      const previousAttempts = await incrementCache(attemptsKey, ONE_HOUR);

      if (previousAttempts > this.MAX_OTP_ATTEMPTS) {
        await deleteCache(key); // Invalidate OTP
        await deleteCache(attemptsKey);
        throw new BadRequestException('Too many failed attempts. Please request a new OTP.');
      }

      if (storedOtp !== otp) {
        const remainingAttempts = this.MAX_OTP_ATTEMPTS - previousAttempts;
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
      const { email, password, resetToken } = resetPasswordData;

      const user = await prisma.user.findUnique({
        where: { email },
      });

      if (!user) {
        throw new NotFoundException('User not found');
      }

      const { payload } = verifyJwtToken<ResetTPayload>(resetToken, {
        secret: resetTokenSignOptions.secret,
      });

      if (!payload) {
        throw new UnauthorizedException('Invalid reset token');
      }

      const hashedPassword = await hashPassword(password);

      // Fetch active sessions to invalidate cache
      const activeSessions = await prisma.session.findMany({
        where: { userId: user.id, isRevoked: false },
        select: { id: true },
      });

      await prisma.$transaction(async tx => {
        await tx.account.updateMany({
          where: {
            user: { email },
            providerId: 'credential',
          },
          data: {
            password: hashedPassword,
          },
        });

        await tx.session.updateMany({
          where: { userId: user.id },
          data: {
            isRevoked: true,
            revokedAt: new Date(),
          },
        });
      });

      // Invalidate Redis keys
      for (const session of activeSessions) {
        await deleteCache(`session:${session.id}`);
      }

      if (config.NODE_ENV === 'production') {
        await this.emailService.sendPasswordChangeConfirmation(email, user.name);
      }

      return null;
    } catch (error) {
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

      if (config.NODE_ENV === 'production') {
        await this.emailService.sendPasswordChangeConfirmation(user.email, user.name);
      }

      return null;
    } catch (error) {
      if (error instanceof AppError) {
        throw error;
      }
      throw new AppError('Failed to change the password', HTTPSTATUS.INTERNAL_SERVER_ERROR);
    }
  }
}
