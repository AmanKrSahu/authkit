import { getEnv as getEnvironment } from '../common/utils/get-env';

const appConfig = () => ({
  PORT: getEnvironment('PORT', '8000'),
  NODE_ENV: getEnvironment('NODE_ENV', 'development'),
  BASE_PATH: getEnvironment('BASE_PATH', '/api/v1'),
  DOMAIN_URL: getEnvironment('DOMAIN_URL', 'localhost'),

  FRONTEND_ORIGINS: getEnvironment('FRONTEND_ORIGINS', 'http://localhost:3000').split(','),

  DATABASE_URL: getEnvironment('DATABASE_URL', ''),

  REDIS: {
    HOST: getEnvironment('REDIS_HOST', 'localhost'),
    PORT: getEnvironment('REDIS_PORT', '6379'),
  },

  GOOGLE_CLIENT_ID: getEnvironment('GOOGLE_CLIENT_ID', ''),
  GOOGLE_CLIENT_SECRET: getEnvironment('GOOGLE_CLIENT_SECRET', ''),
  GOOGLE_CALLBACK_URL: getEnvironment('GOOGLE_CALLBACK_URL', ''),

  JWT: {
    SECRET: getEnvironment('JWT_SECRET'),
    EXPIRES_IN: getEnvironment('JWT_EXPIRES_IN', '15m'),

    REFRESH_SECRET: getEnvironment('JWT_REFRESH_SECRET'),
    REFRESH_EXPIRES_IN: getEnvironment('JWT_REFRESH_EXPIRES_IN', '7d'),

    RESET_SECRET: getEnvironment('JWT_RESET_SECRET'),
    RESET_EXPIRES_IN: getEnvironment('JWT_RESET_EXPIRES_IN', '10m'),

    MFA_LOGIN_SECRET: getEnvironment('JWT_MFA_LOGIN_SECRET'),
    MFA_LOGIN_EXPIRES_IN: getEnvironment('JWT_MFA_LOGIN_EXPIRES_IN', '5m'),
  },

  RESEND_API_KEY: getEnvironment('RESEND_API_KEY', ''),
  RESEND_SENDER_EMAIL: getEnvironment('RESEND_EMAIL', 'noreply@yourdomain.com'),

  AUTHENTICATOR_APP_SECRET: getEnvironment(
    'AUTHENTICATOR_APP_SECRET',
    'dev_secret_key_which_should_be_32_chars_long'
  ),
});

export const config = appConfig();
