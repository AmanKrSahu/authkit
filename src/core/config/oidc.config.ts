import RedisAdapter from '@core/adapter/oidc.adapter';
import { config } from '@core/config/app.config';
import prisma from '@core/database/prisma';
import type { Configuration } from 'oidc-provider';

export const oidcConfig: Configuration = {
  adapter: RedisAdapter,
  clients: [],

  async findAccount(_ctx, id) {
    const user = await prisma.user.findUnique({
      where: { id },
      select: {
        id: true,
        email: true,
        name: true,
        emailVerified: true,
        role: true,
      },
    });

    if (!user) return;

    return {
      accountId: id,
      async claims(_use, _scope) {
        return {
          sub: id,
          email: user.email,
          email_verified: !!user.emailVerified,
          name: user.name,
          preferred_username: user.email.split('@')[0],
          role: user.role,
        };
      },
    };
  },

  interactions: {
    url(_ctx: unknown, interaction: { uid: string }) {
      return `${config.BASE_PATH}/oidc/interaction/${interaction.uid}`;
    },
  },

  cookies: {
    keys: config.OIDC.COOKIE_KEYS,
    long: {
      signed: true,
      secure: config.NODE_ENV === 'production',
      httpOnly: true,
      sameSite: 'lax', // Use 'none' for cross-domain if needed
    },
    short: {
      signed: true,
      secure: config.NODE_ENV === 'production',
      httpOnly: true,
      sameSite: 'lax', // Use 'none' for cross-domain if needed
    },
  },

  pkce: {
    required: () => true,
  },

  claims: {
    openid: ['sub'],
    profile: ['name', 'preferred_username', 'nickname'],
    email: ['email', 'email_verified'],
    role: ['role'],
  },

  features: {
    devInteractions: { enabled: false },
    deviceFlow: { enabled: false },
    revocation: { enabled: true },
    introspection: { enabled: true },
    userinfo: { enabled: true },
    rpInitiatedLogout: { enabled: true },
  },

  rotateRefreshToken: true,

  jwks: config.OIDC.JWKS,
};
