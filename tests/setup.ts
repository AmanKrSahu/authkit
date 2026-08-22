/**
 * Global Vitest Test Environment Setup.
 * Dynamically constructs a 100% isolated, self-contained test environment in process.env
 * before any test file runs, ensuring complete independence from external .env files or host machine variables.
 */
import crypto from 'node:crypto';
import { generateKeyPair, exportJWK } from 'jose';

const generateSecret = () => crypto.randomBytes(32).toString('hex');

// Unconditionally set all test environment variables for complete test isolation
process.env.NODE_ENV = 'test';
process.env.PORT = '8000';
process.env.BASE_PATH = '/api/v1';
process.env.DOMAIN_URL = 'localhost';
process.env.TRUST_PROXY = 'false';
process.env.BCRYPT_SALT_ROUNDS = '4'; // Fast rounds for test execution
process.env.FRONTEND_ORIGINS = 'http://localhost:3000';

process.env.DATABASE_URL =
  'postgresql://postgres:postgres@localhost:5432/authkit_test?schema=public';
process.env.TEST_DATABASE_URL =
  'postgresql://postgres:postgres@localhost:5432/authkit_test?schema=public';

process.env.REDIS_HOST = 'localhost';
process.env.REDIS_PORT = '6379';
process.env.REDIS_PASSWORD = 'test_redis_pass';

// OAuth Integration Defaults for Passport Strategies
process.env.GOOGLE_CLIENT_ID = 'test_google_client_id';
process.env.GOOGLE_CLIENT_SECRET = 'test_google_client_secret';
process.env.GOOGLE_CALLBACK_URL = 'http://localhost:8000/api/v1/oauth/google/callback';

// Email Service Defaults
process.env.RESEND_API_KEY = 'test_resend_api_key';
process.env.RESEND_EMAIL = 'noreply@yourdomain.com';

// Cryptographic Secrets & JWT Keys (Dynamically Generated per Test Run)
process.env.JWT_SECRET = generateSecret();
process.env.JWT_REFRESH_SECRET = generateSecret();
process.env.JWT_RESET_SECRET = generateSecret();
process.env.JWT_MFA_LOGIN_SECRET = generateSecret();
process.env.AUTHENTICATOR_APP_SECRET = generateSecret();
process.env.OIDC_COOKIE_KEYS = `${generateSecret()},${generateSecret()}`;

// Dynamically generate a fresh RS256 RSA key pair for OIDC JWKS
const { privateKey } = await generateKeyPair('RS256', { extractable: true });
const jwk = await exportJWK(privateKey);
jwk.kid = 'test-key-1';
jwk.use = 'sig';
process.env.OIDC_JWKS = JSON.stringify({ keys: [jwk] });
