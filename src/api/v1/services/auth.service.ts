import { ErrorCodeEnum } from '@core/common/enums/error-code.enum';
import type {
  ChangePasswordData,
  ForgotPasswordData,
  LoginData,
  LoginWithGoogleData,
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
import { fiveMinutesFromNow, oneDayFromNow, sevenDaysFromNow } from '@core/common/utils/date-time';
import type { RefreshTPayload, ResetTPayload } from '@core/common/utils/jwt';
import {
  refreshTokenSignOptions,
  resetTokenSignOptions,
  signJwtToken,
  verifyJwtToken,
} from '@core/common/utils/jwt';
import { config } from '@core/config/app.config';
import { HTTPSTATUS } from '@core/config/http.config';
import prisma from '@core/database/prisma';
import type { EmailService } from '@core/mailers/resend';
import type { Account, User } from '@prisma/client';

export class AuthService {
  private emailService: EmailService;

  constructor(emailService: EmailService) {
    this.emailService = emailService;
  }

  private readonly MAX_OTP_ATTEMPTS = 3;
  private readonly MAX_OTP_REQUESTS_PER_HOUR = 5;

  private async checkForNewDevice(userId: string, deviceFingerprint: string): Promise<boolean> {
    const existingSession = await prisma.session.findFirst({
      where: {
        userId,
        deviceFingerprint,
        isRevoked: false,
      },
    });

    return !existingSession;
  }

  private async checkRateLimit(email: string, ipAddress: string) {
    const recentAttempts = await prisma.verification.count({
      where: {
        OR: [{ identifier: email }, { ipAddress: ipAddress }],
        type: 'PASSWORD_RESET',
        createdAt: {
          gte: new Date(Date.now() - 1 * 60 * 60 * 1000), // Last 1 hour
        },
      },
    });

    if (recentAttempts >= this.MAX_OTP_REQUESTS_PER_HOUR) {
      throw new BadRequestException('Too many attempts. Please try again later.');
    }
  }

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

      const result = await prisma.$transaction(async tx => {
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

        const verificationToken = generateRandomToken();
        const expiresAt = oneDayFromNow();

        const verification = await tx.verification.create({
          data: {
            identifier: email,
            value: verificationToken,
            expiresAt: expiresAt,
          },
        });

        return {
          user: newUser,
          verification,
        };
      });

      const verificationUrl = `${config.FRONTEND_ORIGINS[0]}/auth/verify-email?token=${result.verification.value}`;
      await this.emailService.sendEmailVerification(email, verificationUrl, name);

      if (config.NODE_ENV === 'production') {
        await this.emailService.sendWelcomeEmail(email, name);
      }

      return {
        user: result.user,
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

      const verification = await prisma.verification.findFirst({
        where: {
          value: token,
          isUsed: false,
          expiresAt: { gt: new Date() },
          type: 'EMAIL_VERIFICATION',
        },
      });

      if (!verification) {
        throw new BadRequestException('Invalid verification token');
      }

      await prisma.$transaction(async tx => {
        await tx.user.update({
          where: { email: verification.identifier },
          data: { emailVerified: true },
        });

        await tx.verification.update({
          where: { id: verification.id },
          data: { isUsed: true, usedAt: new Date() },
        });
      });

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

      const result = await prisma.$transaction(async tx => {
        await tx.verification.updateMany({
          where: { identifier: email, isUsed: false, type: 'EMAIL_VERIFICATION' },
          data: { isUsed: true, usedAt: new Date() },
        });

        const verificationToken = generateRandomToken();
        const expiresAt = oneDayFromNow();

        const verification = await tx.verification.create({
          data: {
            identifier: email,
            value: verificationToken,
            expiresAt: expiresAt,
          },
        });

        return { verification };
      });

      const verificationUrl = `${config.FRONTEND_ORIGINS[0]}/auth/verify-email?token=${result.verification.value}`;
      await this.emailService.sendEmailVerification(email, verificationUrl, user.name);

      return null;
    } catch (error) {
      if (error instanceof AppError) {
        throw error;
      }
      throw new AppError('Failed to send verification email', HTTPSTATUS.INTERNAL_SERVER_ERROR);
    }
  }

  public async loginWithGoogle(loginData: LoginWithGoogleData) {
    try {
      const { profile, ipAddress, userAgent } = loginData;
      const email = profile.emails?.[0]?.value;
      const googleId = profile.id;

      if (!email) {
        throw new BadRequestException('Google account does not have an email address');
      }

      const user = await prisma.user.findUnique({
        where: { email },
        include: {
          accounts: true,
        },
      });

      let result: {
        user: User & { accounts: Account[] };
      };

      if (user) {
        // Check if google account is linked
        const googleAccount = user.accounts.find(
          acc => acc.providerId === 'google' && acc.accountId === googleId
        );

        if (!googleAccount) {
          // Link google account
          await prisma.account.create({
            data: {
              userId: user.id,
              providerId: 'google',
              accountId: googleId,
            },
          });
        }

        result = { user };
      } else {
        // Create a new user
        result = await prisma.$transaction(async tx => {
          const newUser = await tx.user.create({
            data: {
              email,
              name: profile.displayName ?? profile.name?.givenName ?? 'User',
              emailVerified: true,
              image: profile.photos?.[0]?.value,
              accounts: {
                create: {
                  providerId: 'google',
                  accountId: googleId,
                },
              },
            },
            include: {
              accounts: true,
            },
          });

          return {
            user: newUser,
          };
        });
      }

      const deviceFingerprint = generateDeviceFingerprint(userAgent, ipAddress);
      const isNewDevice = await this.checkForNewDevice(result.user.id, deviceFingerprint);

      const sessionToken = generateSessionToken();
      const expiresAt = sevenDaysFromNow();

      const session = await prisma.session.create({
        data: {
          token: sessionToken,
          userId: result.user.id,
          expiresAt: expiresAt,
          ipAddress: ipAddress,
          userAgent: userAgent,
          deviceFingerprint,
          isNewDevice,
        },
      });

      if (isNewDevice && config.NODE_ENV === 'production') {
        await this.emailService.sendNewDeviceNotification(
          result.user.email,
          {
            deviceInfo: userAgent,
            ipAddress,
            loginTime: new Date(),
          },
          result.user.name
        );
      }

      const accessToken = signJwtToken({ userId: result.user.id, sessionId: session.id });
      const refreshToken = signJwtToken({ sessionId: session.id }, refreshTokenSignOptions);

      // eslint-disable-next-line @typescript-eslint/no-unused-vars
      const { accounts, ...userInfo } = result.user;

      return {
        user: userInfo,
        accessToken,
        refreshToken,
      };
    } catch (error) {
      if (error instanceof AppError) {
        throw error;
      }
      throw new AppError('Failed to sign in with Google', HTTPSTATUS.INTERNAL_SERVER_ERROR);
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

      const deviceFingerprint = generateDeviceFingerprint(userAgent, ipAddress);
      const isNewDevice = await this.checkForNewDevice(user.id, deviceFingerprint);

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

      // eslint-disable-next-line @typescript-eslint/no-unused-vars
      const { accounts, ...userInfo } = user;

      return {
        user: userInfo,
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

      await this.checkRateLimit(email, ipAddress);

      const result = await prisma.$transaction(async tx => {
        await tx.verification.updateMany({
          where: {
            identifier: email,
            type: 'PASSWORD_RESET',
            isUsed: false,
            expiresAt: { gt: new Date() },
          },
          data: {
            isUsed: true,
            usedAt: new Date(),
          },
        });

        const otp = generateOTP();
        const expiresAt = fiveMinutesFromNow();

        await tx.verification.create({
          data: {
            identifier: email,
            value: otp,
            expiresAt: expiresAt,
            type: 'PASSWORD_RESET',
            ipAddress: ipAddress,
          },
        });

        return { otp };
      });

      await this.emailService.sendPasswordResetOTP(email, result.otp, user.name);

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

      const verification = await prisma.verification.findFirst({
        where: {
          identifier: email,
          type: 'PASSWORD_RESET',
          isUsed: false,
          expiresAt: { gt: new Date() },
        },
        orderBy: { createdAt: 'desc' },
      });

      if (!verification) {
        throw new BadRequestException('No active OTP found. Please request a new one.');
      }

      if (verification.attempts >= this.MAX_OTP_ATTEMPTS) {
        throw new BadRequestException('Too many failed attempts. Please request a new OTP.');
      }

      if (verification.value !== otp) {
        await prisma.verification.update({
          where: { id: verification.id },
          data: {
            attempts: { increment: 1 },
          },
        });

        const remainingAttempts = this.MAX_OTP_ATTEMPTS - (verification.attempts + 1);
        throw new BadRequestException(`Invalid OTP. ${remainingAttempts} attempt(s) remaining.`);
      }

      await prisma.verification.update({
        where: { id: verification.id },
        data: {
          isUsed: true,
          usedAt: new Date(),
        },
      });

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

      await prisma.account.updateMany({
        where: {
          userId: userId,
          providerId: 'credential',
        },
        data: {
          password: hashedPassword,
        },
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
