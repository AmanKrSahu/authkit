/**
 * Factory for creating Session records in the database with custom overrides.
 */
import { generateDeviceFingerprint } from '@core/common/utils/crypto';
import { calculateExpirationDate, ONE_DAY } from '@core/common/utils/date-time';
import prisma from '@core/database/prisma';

export const createSessionFactory = async (userId: string, overrides: any = {}) => {
  const ipAddress = overrides.ipAddress ?? '127.0.0.1';
  const userAgent = overrides.userAgent ?? 'Mozilla/5.0';
  const deviceFingerprint =
    overrides.deviceFingerprint ?? generateDeviceFingerprint(userAgent, ipAddress);

  const session = await prisma.session.create({
    data: {
      userId,
      expiresAt: overrides.expiresAt ?? calculateExpirationDate(ONE_DAY * 7),
      ipAddress,
      userAgent,
      deviceFingerprint,
      isRevoked: overrides.isRevoked ?? false,
      isNewDevice: overrides.isNewDevice ?? false,
    },
  });

  return session;
};
