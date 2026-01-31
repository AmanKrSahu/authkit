import type { User } from '@prisma/client';

export const sanitizeUser = (
  user: User & { accounts?: unknown[]; sessions?: unknown[]; password?: string }
) => {
  // eslint-disable-next-line @typescript-eslint/no-unused-vars
  const { password, twoFactorSecret, backupCodes, accounts, sessions, ...sanitizedUser } = user;
  return sanitizedUser;
};
