import { JWT_CONFIG } from '@core/common/constants/jwt.constant';
import { ErrorCodeEnum } from '@core/common/enums/error-code.enum';
import type { LoginWithGoogleData } from '@core/common/interface/oauth.interface';
import { AppError, BadRequestException } from '@core/common/utils/app-error';
import { generateDeviceFingerprint, hashToken } from '@core/common/utils/crypto';
import { calculateExpirationDate } from '@core/common/utils/date-time';
import { refreshTokenSignOptions, signJwtToken } from '@core/common/utils/jwt';
import { checkForNewDevice } from '@core/common/utils/metadata';
import { setCache } from '@core/common/utils/redis-helpers';
import { sanitizeUser } from '@core/common/utils/sanitize';
import { HTTPSTATUS } from '@core/config/http.config';
import prisma from '@core/database/prisma';
import { EmailService } from '@core/mailers/resend';
import type { Account, User } from '@prisma/client';
import { AuditAction, AuditStatus } from '@prisma/client';

import { AuditService } from './audit.service';

export class OAuthService {
  private emailService: EmailService;
  private auditService: AuditService;

  constructor(
    emailService: EmailService = new EmailService(),
    auditService: AuditService = new AuditService()
  ) {
    this.emailService = emailService;
    this.auditService = auditService;
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
          // Prevent pre-account-takeovers: do not auto-link if the existing local account is not verified
          if (!user.emailVerified) {
            throw new BadRequestException(
              'An account with this email address already exists. Please verify that account first or link it from your account settings.',
              ErrorCodeEnum.AUTH_ACCOUNT_PENDING_VERIFICATION
            );
          }

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
      const isNewDevice = await checkForNewDevice(result.user.id, deviceFingerprint);

      const expiresAt = calculateExpirationDate(JWT_CONFIG.REFRESH_EXPIRES_IN);

      const session = await prisma.session.create({
        data: {
          userId: result.user.id,
          expiresAt: expiresAt,
          ipAddress: ipAddress,
          userAgent: userAgent,
          deviceFingerprint,
          isNewDevice,
        },
      });

      if (isNewDevice) {
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

      // Store refresh token hash in Redis for RTR
      const refreshTokenHash = hashToken(refreshToken);
      await setCache(
        `active_refresh_token:${session.id}`,
        refreshTokenHash,
        JWT_CONFIG.REFRESH_EXPIRES_IN
      );

      const { ...userInfo } = result.user;

      await this.auditService.log({
        userId: result.user.id,
        action: AuditAction.LOGIN,
        entityType: 'User',
        entityId: result.user.id,
        description: 'User logged in via Google OAuth',
        status: AuditStatus.SUCCESS,
        ipAddress,
        userAgent,
        metadata: { providerId: 'google' },
      });

      return {
        user: sanitizeUser(userInfo),
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
}
