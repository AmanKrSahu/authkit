import { getEnv as getEnvironment } from '../common/utils/get-env';

const appConfig = () => ({
  PORT: getEnvironment('PORT', '8000'),
  NODE_ENV: getEnvironment('NODE_ENV', 'development'),
  BASE_PATH: getEnvironment('BASE_PATH', '/api/v1'),
  DOMAIN_URL: getEnvironment('DOMAIN_URL', 'localhost'),
  TRUST_PROXY: getEnvironment('TRUST_PROXY', 'false'),
  BCRYPT_SALT_ROUNDS: Number(getEnvironment('BCRYPT_SALT_ROUNDS', '12')),

  FRONTEND_ORIGINS: getEnvironment('FRONTEND_ORIGINS', 'http://localhost:3000').split(','),

  DATABASE_URL: getEnvironment('DATABASE_URL', ''),

  REDIS: {
    HOST: getEnvironment('REDIS_HOST', 'localhost'),
    PORT: getEnvironment('REDIS_PORT', '6379'),
    PASSWORD: getEnvironment('REDIS_PASSWORD', ''),
    TLS: getEnvironment('REDIS_TLS', 'false'),
  },

  GOOGLE_CLIENT_ID: getEnvironment('GOOGLE_CLIENT_ID', ''),
  GOOGLE_CLIENT_SECRET: getEnvironment('GOOGLE_CLIENT_SECRET', ''),
  GOOGLE_CALLBACK_URL: getEnvironment('GOOGLE_CALLBACK_URL', ''),

  JWT: {
    SECRET: getEnvironment('JWT_SECRET'),
    REFRESH_SECRET: getEnvironment('JWT_REFRESH_SECRET'),
    RESET_SECRET: getEnvironment('JWT_RESET_SECRET'),
    MFA_LOGIN_SECRET: getEnvironment('JWT_MFA_LOGIN_SECRET'),
  },

  RESEND_API_KEY: getEnvironment('RESEND_API_KEY', ''),
  RESEND_SENDER_EMAIL: getEnvironment('RESEND_EMAIL', 'noreply@yourdomain.com'),

  AUTHENTICATOR_APP_SECRET: (() => {
    const val = getEnvironment('AUTHENTICATOR_APP_SECRET');
    if (Buffer.byteLength(val, 'utf8') < 32) {
      throw new Error(
        'AUTHENTICATOR_APP_SECRET is too short. It must be at least 32 bytes of secure entropy.'
      );
    }
    return val;
  })(),

  OIDC: {
    COOKIE_KEYS: getEnvironment('OIDC_COOKIE_KEYS').split(','),
    JWKS: (() => {
      const jwksEnv = getEnvironment('OIDC_JWKS');
      try {
        return JSON.parse(jwksEnv);
      } catch {
        throw new Error('Failed to parse OIDC_JWKS environment variable.');
      }
    })(),
  },

  WEBAUTHN: {
    RP_NAME: getEnvironment('WEBAUTHN_RP_NAME', 'AuthKit'),
    RP_ID: getEnvironment('WEBAUTHN_RP_ID', 'localhost'),
    ORIGIN: getEnvironment('WEBAUTHN_ORIGIN', 'http://localhost:3000'),
  },
});

export const config = appConfig();
