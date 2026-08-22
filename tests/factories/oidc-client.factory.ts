/**
 * Factory for creating OidcClient records in the database with custom overrides.
 */
import bcrypt from 'bcrypt';

import prisma from '@core/database/prisma';

export const createOidcClientFactory = async (overrides: any = {}) => {
  const secret = overrides.clientSecret ?? 'test-secret-value-must-be-long-and-secure';
  const hashedSecret = await bcrypt.hash(secret, 12);
  const clientId = overrides.clientId ?? `client_${Math.random().toString(36).substring(2, 11)}`;

  const client = await prisma.oidcClient.create({
    data: {
      clientName: overrides.clientName ?? 'Mock OIDC Client',
      clientId,
      clientSecret: hashedSecret,
      redirectUrls: overrides.redirectUrls ?? ['http://localhost:3000/callback'],
      grantTypes: overrides.grantTypes ?? ['authorization_code', 'refresh_token'],
      scope: overrides.scope ?? 'openid email profile',
    },
  });

  return { ...client, clientSecretRaw: secret };
};
