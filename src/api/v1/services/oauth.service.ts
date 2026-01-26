import type { LoginWithGoogleData } from '@core/common/interface/oauth.interface';
import { AppError, BadRequestException } from '@core/common/utils/app-error';
import { generateDeviceFingerprint, generateSessionToken } from '@core/common/utils/crypto';
import { sevenDaysFromNow } from '@core/common/utils/date-time';
import { refreshTokenSignOptions, signJwtToken } from '@core/common/utils/jwt';
import { checkForNewDevice } from '@core/common/utils/metadata';
import { config } from '@core/config/app.config';
import { HTTPSTATUS } from '@core/config/http.config';
import prisma from '@core/database/prisma';
import type { EmailService } from '@core/mailers/resend';
import type { Account, User } from '@prisma/client';

export class OAuthService {
  private emailService: EmailService;

  constructor(emailService: EmailService) {
    this.emailService = emailService;
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
      const isNewDevice = await checkForNewDevice(result.user.id, deviceFingerprint);

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

      const { ...userInfo } = result.user;

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
}
