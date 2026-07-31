import type { User } from '@prisma/client';

export const sanitizeUser = (
  user: User & { accounts?: unknown[]; sessions?: unknown[]; password?: string }
) => {
  // eslint-disable-next-line @typescript-eslint/no-unused-vars
  const { password, twoFactorSecret, backupCodes, accounts, sessions, ...sanitizedUser } = user;
  return sanitizedUser;
};

export const escapeHtml = (unsafe: string): string => {
  if (typeof unsafe !== 'string') return '';
  return unsafe
    .replaceAll('&', '&amp;')
    .replaceAll('<', '&lt;')
    .replaceAll('>', '&gt;')
    .replaceAll('"', '&quot;')
    .replaceAll("'", '&#039;');
};
