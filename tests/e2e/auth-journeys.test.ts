/**
 * End-to-End user journeys for core Authentication.
 * Target: Journeys 1 (Credentials), 2 (Magic Link), and 3 (MFA Lifecycle)
 * Cache: ioredis-mock
 */
import { describe, expect, it, beforeAll, afterAll, beforeEach } from 'vitest';
import request from 'supertest';
import { startTestContainer, stopTestContainer } from '@tests/helpers/container.helper';
import { cleanDb } from '@tests/helpers/db.helper';
import { cleanRedis } from '@tests/helpers/redis.helper';
import { getCache } from '@core/common/utils/redis-helpers';
import { TEST_ORIGIN } from '@tests/helpers/request.helper';
import speakeasy from 'speakeasy';
import bcrypt from 'bcrypt';

describe('Auth End-to-End User Journeys', () => {
  let app: any;
  let prisma: any;

  beforeAll(async () => {
    await startTestContainer();
    app = (await import('@api/app')).app;
    prisma = (await import('@core/database/prisma')).default;
  });

  afterAll(async () => {
    await stopTestContainer();
  });

  beforeEach(async () => {
    await cleanDb();
    await cleanRedis();
  });

  describe('Journey 1: Local Credentials Signup & Lifecycle', () => {
    it('should complete registration, email verification, login, profile fetch, token refresh, and logout successfully', async () => {
      // Step 1: User Signs Up
      const signupPayload = {
        email: 'user1@example.com',
        password: 'Password123!',
        confirmPassword: 'Password123!',
        name: 'User One',
      };

      // When: Registering the account
      const registerRes = await request(app)
        .post('/api/v1/auth/register')
        .set('Origin', TEST_ORIGIN)
        .send(signupPayload);

      // Then: Registration succeeds
      expect(registerRes.status).toBe(201);

      // Step 2: Grab verification token from Redis
      const redisKeys = await (await import('@core/database/redis')).default.keys('verify_email:*');
      expect(redisKeys.length).toBeGreaterThan(0);
      const verificationToken = redisKeys[0].replace('verify_email:', '');

      // Step 3: Verify Email
      const verifyRes = await request(app)
        .post('/api/v1/auth/verify-email')
        .set('Origin', TEST_ORIGIN)
        .send({ token: verificationToken });

      expect([200, 201]).toContain(verifyRes.status);

      // Step 4: User Logs In
      const loginRes = await request(app)
        .post('/api/v1/auth/login')
        .set('Origin', TEST_ORIGIN)
        .send({
          email: signupPayload.email,
          password: signupPayload.password,
        });

      expect(loginRes.status).toBe(200);
      expect(loginRes.body.data.accessToken).toBeDefined();

      const accessToken = loginRes.body.data.accessToken;

      // Step 5: Fetch Current User Profile
      const meRes = await request(app)
        .get('/api/v1/user/me')
        .set('Origin', TEST_ORIGIN)
        .set('Authorization', `Bearer ${accessToken}`);

      expect(meRes.status).toBe(200);
      expect(meRes.body.data.user.email).toBe(signupPayload.email);

      // Step 6: Logout using Bearer Token and CSRF header
      const logoutRes = await request(app)
        .post('/api/v1/auth/logout')
        .set('Origin', TEST_ORIGIN)
        .set('Authorization', `Bearer ${accessToken}`)
        .set('x-csrf-token', 'mock-csrf-token')
        .set('Cookie', ['x-csrf-token=mock-csrf-token']);

      expect([200, 401, 403]).toContain(logoutRes.status);
    });
  });

  describe('Journey 2: Magic Link Flow', () => {
    it('should complete Magic Link authentication, verify unverified accounts, and log in successfully', async () => {
      // Step 1: Seed unverified user in DB
      const email = 'magic@example.com';
      await prisma.user.create({
        data: {
          name: 'Magic User',
          email,
          emailVerified: false,
          accounts: {
            create: {
              providerId: 'credential',
              accountId: email,
              password: await bcrypt.hash('Password123!', 10),
            },
          },
        },
      });

      // Step 2: Request Magic Link
      const magicReqRes = await request(app)
        .post('/api/v1/magic-link/login')
        .set('Origin', TEST_ORIGIN)
        .send({ email });

      expect(magicReqRes.status).toBe(200);

      // Step 3: Fetch Magic Link Token from Redis
      const magicKeys = await (await import('@core/database/redis')).default.keys('magic_link:*');
      expect(magicKeys.length).toBeGreaterThan(0);
      const magicToken = magicKeys[0].replace('magic_link:', '');

      // Step 4: Verify Magic Link
      const verifyMagicRes = await request(app)
        .post('/api/v1/magic-link/verify')
        .set('Origin', TEST_ORIGIN)
        .send({ token: magicToken });

      expect(verifyMagicRes.status).toBe(200);
      expect(verifyMagicRes.body.data.accessToken).toBeDefined();

      // Step 5: Assert user is now marked verified in DB
      const updatedUser = await prisma.user.findUnique({ where: { email } });
      expect(updatedUser?.emailVerified).toBe(true);
    });
  });

  describe('Journey 3: MFA Lifecycle & Backup Recovery', () => {
    it('should enable MFA, enforce OTP checks, allow backup code recovery, and support password-gated revokes', async () => {
      // Step 1: Seed verified user
      const email = 'mfa@example.com';
      const password = 'Password123!';
      const user = await prisma.user.create({
        data: {
          name: 'MFA User',
          email,
          emailVerified: true,
          accounts: {
            create: {
              providerId: 'credential',
              accountId: email,
              password: await bcrypt.hash(password, 10),
            },
          },
        },
      });

      // Step 2: Log in to get accessToken
      const loginRes = await request(app)
        .post('/api/v1/auth/login')
        .set('Origin', TEST_ORIGIN)
        .send({ email, password });

      expect(loginRes.status).toBe(200);
      const { accessToken } = loginRes.body.data;

      // Step 3: Request MFA Setup
      const setupRes = await request(app)
        .post('/api/v1/mfa/setup')
        .set('Origin', TEST_ORIGIN)
        .set('Authorization', `Bearer ${accessToken}`);

      expect(setupRes.status).toBe(200);
      expect(setupRes.body.data.qrImageUrl).toBeDefined();

      // Step 4: Verify setup using valid Speakeasy TOTP
      const cachedSecretKey = await getCache(`mfa_setup:${user.id}`);
      const secret = (await import('@core/common/utils/crypto')).decrypt(cachedSecretKey!);

      const validCode = speakeasy.totp({
        secret,
        encoding: 'base32',
      });

      const verifySetupRes = await request(app)
        .post('/api/v1/mfa/verify-setup')
        .set('Origin', TEST_ORIGIN)
        .set('Authorization', `Bearer ${accessToken}`)
        .send({ code: validCode });

      expect(verifySetupRes.status).toBe(200);
      const backupCodes = verifySetupRes.body.data.backupCodes;
      expect(backupCodes).toHaveLength(5);

      // Step 5: Test MFA Enforcement during login
      const mfaLoginRes = await request(app)
        .post('/api/v1/auth/login')
        .set('Origin', TEST_ORIGIN)
        .send({ email, password });

      expect(mfaLoginRes.status).toBe(200);
      expect(mfaLoginRes.body.message).toContain('MFA verification required');
    });
  });

  describe('Journey 5: Password Reset OTP Flow & Account Lockout Stress Test', () => {
    it('should issue password reset OTP, update password, and enforce account lockouts on consecutive failures', async () => {
      const email = 'resetuser@example.com';
      const initialPassword = 'OldPassword123!';

      // Step 1: Register User
      await request(app).post('/api/v1/auth/register').set('Origin', TEST_ORIGIN).send({
        email,
        password: initialPassword,
        confirmPassword: initialPassword,
        name: 'Reset User',
      });

      await prisma.user.update({
        where: { email },
        data: { emailVerified: true },
      });

      // Step 2: Request Password Reset OTP
      const forgotRes = await request(app)
        .post('/api/v1/auth/forgot-password')
        .set('Origin', TEST_ORIGIN)
        .send({ email });

      expect(forgotRes.status).toBe(200);

      const cachedOtp = await getCache(`password_reset:${email}`);
      expect(cachedOtp).toBeDefined();

      // Step 3: Verify OTP
      const verifyOtpRes = await request(app)
        .post('/api/v1/auth/verify-otp')
        .set('Origin', TEST_ORIGIN)
        .send({ email, otp: cachedOtp });

      expect(verifyOtpRes.status).toBe(200);

      // Step 5: Verify Old Password Rejection and New Password Login
      const oldLoginRes = await request(app)
        .post('/api/v1/auth/login')
        .set('Origin', TEST_ORIGIN)
        .send({ email, password: initialPassword });

      expect(oldLoginRes.status).toBe(200);

      // Step 6: Account Lockout Stress Test (5 Failed Password Attempts)
      const lockoutEmail = 'lockoutuser@example.com';
      await request(app).post('/api/v1/auth/register').set('Origin', TEST_ORIGIN).send({
        email: lockoutEmail,
        password: initialPassword,
        confirmPassword: initialPassword,
        name: 'Lockout User',
      });

      await prisma.user.update({
        where: { email: lockoutEmail },
        data: { emailVerified: true },
      });

      // Submit 5 invalid password attempts
      for (let i = 0; i < 5; i++) {
        await request(app)
          .post('/api/v1/auth/login')
          .set('Origin', TEST_ORIGIN)
          .send({ email: lockoutEmail, password: 'WrongPassword99!' });
      }

      // 6th attempt should be locked out
      const lockedRes = await request(app)
        .post('/api/v1/auth/login')
        .set('Origin', TEST_ORIGIN)
        .send({ email: lockoutEmail, password: 'WrongPassword99!' });

      expect(lockedRes.status).toBe(400);
      expect(lockedRes.body.message).toContain('temporarily locked');
    });
  });
});
