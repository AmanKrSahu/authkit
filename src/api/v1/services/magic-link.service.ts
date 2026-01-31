import type {
  MagicLinkLoginData,
  MagicLinkVerifyData,
} from '@core/common/interface/magic-link.interface';
import { AppError, BadRequestException, NotFoundException } from '@core/common/utils/app-error';
import {
  generateDeviceFingerprint,
  generateRandomToken,
  generateSessionToken,
} from '@core/common/utils/crypto';
import { FIFTEEN_MINUTES, sevenDaysFromNow } from '@core/common/utils/date-time';
import { mfaTokenSignOptions, refreshTokenSignOptions, signJwtToken } from '@core/common/utils/jwt';
import { logger } from '@core/common/utils/logger';
import { checkForNewDevice } from '@core/common/utils/metadata';
import { deleteCache, getCache, setCache } from '@core/common/utils/redis-helpers';
import { sanitizeUser } from '@core/common/utils/sanitize';
import { config } from '@core/config/app.config';
import { HTTPSTATUS } from '@core/config/http.config';
import prisma from '@core/database/prisma';
import type { EmailService } from '@core/mailers/resend';

export class MagicLinkService {
  private emailService: EmailService;

  constructor(emailService: EmailService) {
    this.emailService = emailService;
  }

  public async login(magicLinkLoginData: MagicLinkLoginData) {
    try {
      const { email } = magicLinkLoginData;

      const user = await prisma.user.findUnique({
        where: { email },
      });

      if (!user) {
        throw new NotFoundException('User not found');
      }

      const token = generateRandomToken();

      await setCache(`magic_link:${token}`, email, FIFTEEN_MINUTES);

      const magicLinkUrl = `${config.FRONTEND_ORIGINS[0]}/auth/magic-link/verify?token=${token}`;

      if (config.NODE_ENV === 'production') {
        await this.emailService.sendMagicLink(email, magicLinkUrl, user.name);
      } else {
        logger.info(`Magic Link Token: ${token}`);
        logger.info(`Magic Link URL: ${magicLinkUrl}`);
      }

      return null;
    } catch (error) {
      if (error instanceof AppError) {
        throw error;
      }
      throw new AppError('Failed to process magic link login', HTTPSTATUS.INTERNAL_SERVER_ERROR);
    }
  }

  public async verify(magicLinkVerifyData: MagicLinkVerifyData) {
    try {
      const { token, ipAddress, userAgent } = magicLinkVerifyData;

      const email = await getCache(`magic_link:${token}`);

      if (!email) {
        throw new BadRequestException('Invalid or expired magic link token');
      }

      const user = await prisma.user.findUnique({
        where: { email },
      });

      if (!user) {
        throw new NotFoundException('User not found');
      }

      if (user.enable2FA) {
        const { ...userInfo } = user;
        const mfaLoginToken = signJwtToken(
          { userId: user.id, purpose: 'MFA_LOGIN' },
          mfaTokenSignOptions
        );

        await deleteCache(`magic_link:${token}`);

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

      await deleteCache(`magic_link:${token}`);

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
      throw new AppError('Failed to verify magic link', HTTPSTATUS.INTERNAL_SERVER_ERROR);
    }
  }
}
