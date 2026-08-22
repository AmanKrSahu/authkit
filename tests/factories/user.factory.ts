/**
 * Factory for creating User records in the database with custom overrides.
 */
import { Role } from '@prisma/client';
import bcrypt from 'bcrypt';

import prisma from '@core/database/prisma';

export const createUserFactory = async (overrides: any = {}) => {
  const email =
    overrides.email ?? `user_${Math.random().toString(36).substring(2, 11)}@example.com`;
  const password = overrides.password ?? 'Password123!';
  const passwordHash = await bcrypt.hash(password, 10);

  const user = await prisma.user.create({
    data: {
      name: overrides.name ?? 'Mock User',
      email,
      emailVerified: overrides.emailVerified ?? false,
      image: overrides.image ?? null,
      role: overrides.role ?? Role.USER,
      twoFactorSecret: overrides.twoFactorSecret ?? null,
      enable2FA: overrides.enable2FA ?? false,
      backupCodes: overrides.backupCodes ?? [],
      accounts: overrides.accounts ?? {
        create: {
          providerId: 'credential',
          accountId: email,
          password: passwordHash,
        },
      },
    },
  });

  return user;
};
