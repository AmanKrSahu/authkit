import crypto from 'node:crypto';

import type {
  GenerateMFASetupData,
  RevokeMFAData,
  VerifyMFAForLoginData,
  VerifyMFASetupData,
} from '@core/common/interface/mfa.interface';
import {
  AppError,
  BadRequestException,
  NotFoundException,
  UnauthorizedException,
} from '@core/common/utils/app-error';
import { comparePassword, hashPassword } from '@core/common/utils/bcrypt';
import {
  decrypt,
  encrypt,
  generateDeviceFingerprint,
  generateSessionToken,
} from '@core/common/utils/crypto';
import { oneHourFromNow, sevenDaysFromNow } from '@core/common/utils/date-time';
import type { MFATPayload } from '@core/common/utils/jwt';
import { refreshTokenSignOptions, signJwtToken, verifyJwtToken } from '@core/common/utils/jwt';
import {
  checkForNewDevice,
  checkMfaRateLimit,
  incrementMfaRateLimit,
} from '@core/common/utils/metadata';
import { config } from '@core/config/app.config';
import { HTTPSTATUS } from '@core/config/http.config';
import prisma from '@core/database/prisma';
import { EmailService } from '@core/mailers/resend';
import qrcode from 'qrcode';
import speakeasy from 'speakeasy';

export class MfaService {
  private emailService: EmailService;

  constructor() {
    this.emailService = new EmailService();
  }

  private readonly MAX_MFA_LOGIN_ATTEMPTS = 5;

  public async generateMFASetup(generateMFASetupData: GenerateMFASetupData) {
    try {
      const { userId } = generateMFASetupData;

      const user = await prisma.user.findUnique({ where: { id: userId } });

      if (!user) {
        throw new UnauthorizedException('User not authorized');
      }

      if (user.enable2FA) {
        throw new BadRequestException('MFA is already enabled');
      }

      // Generate a new secret but DO NOT store it in the user table yet
      const secret = speakeasy.generateSecret({ name: 'AuthBackend' });
      const secretKey = secret.base32;

      const url = speakeasy.otpauthURL({
        secret: secretKey,
        label: user.email,
        issuer: 'AuthBackend',
        encoding: 'base32',
      });

      const qrImageUrl = await qrcode.toDataURL(url);

      // Store in Verification table with short expiry (e.g. 1 hour)
      // First, clear any existing pending MFA setups for this user
      await prisma.verification.deleteMany({
        where: {
          identifier: userId,
          type: 'MFA_SETUP',
        },
      });

      await prisma.verification.create({
        data: {
          identifier: userId,
          value: secretKey,
          type: 'MFA_SETUP',
          expiresAt: oneHourFromNow(),
        },
      });

      return {
        qrImageUrl,
      };
    } catch (error) {
      if (error instanceof AppError) {
        throw error;
      }
      throw new AppError('Failed to generate MFA setup', HTTPSTATUS.INTERNAL_SERVER_ERROR);
    }
  }

  public async verifyMFASetup(verifyMFASetupData: VerifyMFASetupData) {
    try {
      const { userId, code } = verifyMFASetupData;

      const user = await prisma.user.findUnique({ where: { id: userId } });

      if (!user) {
        throw new UnauthorizedException('User not authorized');
      }

      if (user.enable2FA) {
        throw new BadRequestException('MFA is already enabled');
      }

      const verificationStr = await prisma.verification.findFirst({
        where: {
          identifier: userId,
          type: 'MFA_SETUP',
          expiresAt: { gt: new Date() },
        },
        orderBy: { createdAt: 'desc' },
      });

      if (!verificationStr) {
        throw new BadRequestException(
          'MFA setup not initiated or expired. Please generate setup first.'
        );
      }

      const secretKey = verificationStr.value;

      const isValid = speakeasy.totp.verify({
        secret: secretKey,
        encoding: 'base32',
        token: code,
        window: 1, // Allow 1 step margin
      });

      if (!isValid) {
        throw new BadRequestException('Invalid MFA code. Please try again.');
      }

      const backupCodes = Array.from({ length: 5 }, () => crypto.randomBytes(4).toString('hex'));
      const hashedBackupCodes = await Promise.all(backupCodes.map(code => hashPassword(code)));

      await prisma.user.update({
        where: { id: userId },
        data: {
          enable2FA: true,
          twoFactorSecret: encrypt(secretKey),
          backupCodes: hashedBackupCodes,
        },
      });

      await prisma.verification.delete({
        where: { id: verificationStr.id },
      });

      return {
        message: 'MFA setup completed successfully',
        backupCodes, // Return plaintext codes ONCE
      };
    } catch (error) {
      if (error instanceof AppError) {
        throw error;
      }
      throw new AppError('Failed to verify MFA setup', HTTPSTATUS.INTERNAL_SERVER_ERROR);
    }
  }

  public async revokeMFA(revokeMFAData: RevokeMFAData) {
    try {
      const { userId } = revokeMFAData;

      const user = await prisma.user.findUnique({ where: { id: userId } });

      if (!user) {
        throw new UnauthorizedException('User not authorized');
      }

      if (!user.enable2FA) {
        throw new BadRequestException('MFA is not enabled');
      }

      await prisma.user.update({
        where: { id: userId },
        data: {
          twoFactorSecret: null,
          enable2FA: false,
          backupCodes: [], // Clear backup codes
        },
      });

      return null;
    } catch (error) {
      if (error instanceof AppError) {
        throw error;
      }
      throw new AppError('Failed to revoke MFA', HTTPSTATUS.INTERNAL_SERVER_ERROR);
    }
  }

  public async verifyMFAForLogin(verifyMFAForLoginData: VerifyMFAForLoginData) {
    try {
      const { code, userAgent, ipAddress, mfaLoginToken } = verifyMFAForLoginData;

      const { payload } = verifyJwtToken<MFATPayload>(mfaLoginToken);

      if (!payload) {
        throw new UnauthorizedException('Invalid or expired login token');
      }

      const user = await prisma.user.findUnique({ where: { id: payload.userId } });

      if (!user) {
        throw new NotFoundException('User not found');
      }

      if (!user.enable2FA) {
        throw new UnauthorizedException('MFA not enabled for this user');
      }

      const mfaAttempts = await checkMfaRateLimit(
        user.email,
        ipAddress,
        this.MAX_MFA_LOGIN_ATTEMPTS
      );

      let isValid = false;

      // Check TOTP first (cheaper than iterating backup codes)
      if (user.twoFactorSecret) {
        isValid = speakeasy.totp.verify({
          secret: decrypt(user.twoFactorSecret),
          encoding: 'base32',
          token: code,
          window: 1,
        });
      }

      if (isValid == false) {
        // Check backup codes (hashed)
        // We need to compare specific code against all hashed backup codes.
        // Since bcrypt comparison is slow, this is acceptable for 5 codes.
        for (const hashedCode of user.backupCodes) {
          const isMatch = await comparePassword(code, hashedCode);
          if (isMatch) {
            isValid = true;
            // Remove used backup code
            const newBackupCodes = user.backupCodes.filter(c => c !== hashedCode);
            await prisma.user.update({
              where: { id: user.id },
              data: {
                backupCodes: newBackupCodes,
              },
            });
            break;
          }
        }
      }

      if (!isValid) {
        const remainingAttempts = this.MAX_MFA_LOGIN_ATTEMPTS - (mfaAttempts + 1);

        await incrementMfaRateLimit(user.email, ipAddress);

        throw new BadRequestException(
          `Invalid MFA code. ${remainingAttempts} attempt(s) remaining.`
        );
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
          user.email,
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
        user: userInfo,
        accessToken,
        refreshToken,
      };
    } catch (error) {
      if (error instanceof AppError) {
        throw error;
      }
      throw new AppError('Failed to verify MFA for login', HTTPSTATUS.INTERNAL_SERVER_ERROR);
    }
  }
}
